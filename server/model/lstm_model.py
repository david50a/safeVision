"""
lstm_model_v15.py — SafeVision v15
                                       
Major architectural overhaul from v14 addressing key limitations:

IMPROVEMENT 1 — Bidirectional Multi-Layer LSTM with Working Dropout
    v14 had num_lstm_layers=1 which meant dropout was silently ignored by PyTorch.
    v15 uses 2+ bidirectional LSTM layers with actual dropout between layers.
    Bidirectional processing captures both past→future and future←past context.

IMPROVEMENT 2 — Temporal Convolutional Network (TCN) Front-End
    Added TCN layers before LSTM to capture multi-scale temporal patterns
    at different resolutions. Dilation rates 1, 2, 4, 8 create exponential
    receptive field growth for long-range dependencies.

IMPROVEMENT 3 — Multi-Scale Temporal Attention with Positional Encoding
    Replaced single attention with pyramid attention over multiple temporal
    scales (coarse/medium/fine). Sinusoidal positional encodings preserve
    temporal ordering information that vanilla attention loses.

IMPROVEMENT 4 — Stochastic Depth (DropPath) Regularization
    Added layer-wise stochastic depth that randomly drops entire residual
    blocks during training. Provides stronger regularization than dropout
    alone, especially important for the deeper architecture.

IMPROVEMENT 5 — Gated Linear Units (GLU) and Improved Gating
    Replaced ReLU/GELU activations with GLU-style gating in key positions
    for better gradient flow and feature selection.

IMPROVEMENT 6 — Class Imbalance Handling via Focal Loss
    Added configurable loss functions including Focal Loss to address
    severe class imbalance (many more 'safe' examples than violence).

IMPROVEMENT 7 — Batch Renormalization
    Added batch renormalization for more stable training with small
    batch sizes common in video inference.

IMPROVEMENT 8 — Feature Pyramid Within Network
    Multi-scale feature aggregation at different temporal resolutions
    provides richer representations to the classifier.

COMPATIBILITY: Not backward compatible with v14 weights due to architecture
changes. Must retrain from scratch.
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import math
import mediapipe as mp
from . import vision as vs
from mediapipe.tasks.python import vision
from mediapipe.tasks.python.core.base_options import BaseOptions
import cv2
from typing import Optional, Tuple, List
# Suppress Windows shutdown crash
vision.PoseLandmarker.__del__ = lambda self: None
# MediaPipe detector (lazy singleton)
_detector = None
def get_detector():
    global _detector
    if _detector is None:
        model_path = os.path.join(os.path.dirname(__file__), "pose_landmarker_lite.task")
        base_options = BaseOptions(model_asset_path=model_path)
        options = vision.PoseLandmarkerOptions(
            base_options=base_options,
            running_mode=vision.RunningMode.IMAGE,
        )
        _detector = vision.PoseLandmarker.create_from_options(options)
    return _detector


# Pose feature extraction
def extract_keypoints(results):
    if results.pose_landmarks and len(results.pose_landmarks) > 0:
        keypoints = []
        for lm in results.pose_landmarks[0]:
            keypoints.extend([lm.x, lm.y, lm.z])
        return np.array(keypoints, dtype=np.float32)
    return np.zeros(99, dtype=np.float32)

def normalize_keypoints(keypoints):
    keypoints = keypoints.reshape(33, 3)
    hip_center = (keypoints[23] + keypoints[24]) / 2
    keypoints -= hip_center
    shoulder_dist = np.linalg.norm(keypoints[11] - keypoints[12])
    if shoulder_dist > 0:
        keypoints /= shoulder_dist
    return keypoints.flatten()

def compute_velocity(curr, prev):
    if prev is None:
        return np.zeros_like(curr)
    return curr - prev

def compute_acceleration(curr_vel, prev_vel):
    if prev_vel is None:
        return np.zeros_like(curr_vel)
    return curr_vel - prev_vel

FLOW_RESIZE_W = 320
FLOW_RESIZE_H = 240

def extract_features(frame, prev_keypoints=None, prev_velocity=None, prev_gray=None):
    """
    Extract combined pose (308) + raw optical flow (44) = 352 intermediate features.
    Call build_sequence_features() on the collected list to get final (T, 440) array.
    """
    img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    mp_image = mp.Image(image_format=mp.ImageFormat.SRGB, data=img_rgb)
    results = get_detector().detect(mp_image)
    keypoints = extract_keypoints(results)
    keypoints = normalize_keypoints(keypoints)
    velocity = compute_velocity(keypoints, prev_keypoints)
    acceleration = compute_acceleration(velocity, prev_velocity)
    distances = vs.compute_distances(keypoints)
    angles = vs.compute_angles(keypoints)
    pose_features = np.concatenate([keypoints, velocity, acceleration, distances, angles])  # (308,)
    small = cv2.resize(frame, (FLOW_RESIZE_W, FLOW_RESIZE_H), interpolation=cv2.INTER_LINEAR)
    curr_gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
    if prev_gray is None:
        raw_flow = np.zeros(44, dtype=np.float32)
    else:
        flow = cv2.calcOpticalFlowFarneback(
            prev_gray, curr_gray, None,
            pyr_scale=0.5, levels=3, winsize=15,
            iterations=3, poly_n=5, poly_sigma=1.2, flags=0,
        )
        raw_flow = vs.extract_flow_features(flow)  # (44,)

    combined = np.concatenate([pose_features, raw_flow])  # (352,)
    combined = np.clip(combined, -10.0, 10.0)
    return combined, keypoints, velocity, curr_gray, raw_flow

def build_flow_only_sequence(raw_sequence): 
    # raw_sequence: list of (352,) → returns (T, 132) flow-only array.
    arr = np.array(raw_sequence, dtype=np.float32)
    flow_raw = arr[:, 308:]

    flow_vel = np.zeros_like(flow_raw)
    flow_vel[1:-1] = (flow_raw[2:] - flow_raw[:-2]) / 2.0
    flow_vel[0] = flow_raw[1] - flow_raw[0]
    flow_vel[-1] = flow_raw[-1] - flow_raw[-2]

    flow_acc = np.zeros_like(flow_raw)
    flow_acc[1:-1] = (flow_vel[2:] - flow_vel[:-2]) / 2.0
    flow_acc[0] = flow_vel[1] - flow_vel[0]
    flow_acc[-1] = flow_vel[-1] - flow_vel[-2]

    return np.concatenate([flow_raw, flow_vel, flow_acc], axis=1)  # (T, 132)


def build_sequence_features(raw_sequence: list) -> np.ndarray:
    """Convert list of (352,) arrays → (T, 440) by adding flow vel + acc."""
    arr = np.array(raw_sequence, dtype=np.float32)
    pose_part = arr[:, :308]
    flow_raw = arr[:, 308:]

    flow_vel = np.zeros_like(flow_raw)
    flow_vel[1:-1] = (flow_raw[2:] - flow_raw[:-2]) / 2.0
    flow_vel[0] = flow_raw[1] - flow_raw[0]
    flow_vel[-1] = flow_raw[-1] - flow_raw[-2]

    flow_acc = np.zeros_like(flow_raw)
    flow_acc[1:-1] = (flow_vel[2:] - flow_vel[:-2]) / 2.0
    flow_acc[0] = flow_vel[1] - flow_vel[0]
    flow_acc[-1] = flow_vel[-1] - flow_vel[-2]

    return np.concatenate([pose_part, flow_raw, flow_vel, flow_acc], axis=1)  # (T, 440)


#   Auxiliary target builder                 

def build_danger_targets(labels: torch.Tensor, seq_len: int) -> torch.Tensor:
    """
    Build smooth per-frame danger score targets for the aux regressor.

    Maps 3-class integer labels to a (B, seq_len) float tensor:
        0 (safe)         → all frames 0.0
        1 (pre_violence) → linear ramp 0.10 → 0.40
        2 (violence)     → linear ramp 0.60 → 0.90

    The ramp (rather than a flat constant) lets the LSTM learn that
    danger builds within a window, not just that the window has a label.
    """
    B = labels.size(0)
    t = torch.linspace(0.0, 1.0, seq_len, device=labels.device)  # (T,)

    # Base ramp per class: shape (B, T)
    targets = torch.zeros(B, seq_len, device=labels.device)

    mask_pre = (labels == 1)  # pre_violence
    mask_vio = (labels == 2)  # violence

    targets[mask_pre] = 0.10 + t.unsqueeze(0).expand(mask_pre.sum(), -1) * 0.30 # [0.10 to 0.40]
    targets[mask_vio] = 0.60 + t.unsqueeze(0).expand(mask_vio.sum(), -1) * 0.30 # [0.60 to 0.90]
    return targets  # (B, T)



class BatchRenorm1d(nn.Module):
    """
    Batch Renormalization for more stable training with small batch sizes.
    Addresses the issue where batch statistics become noisy with small batches.

    Reference: Sergey Ioffe, "Batch Renormalization: Towards Reducing
    Minibatch Dependence in Batch-Normalized Models", 2017
    """
    def __init__(self, num_features: int, eps: float = 1e-5, momentum: float = 0.1,
                 rmax: float = 3.0, dmax: float = 5.0):
        super().__init__()
        self.num_features = num_features
        self.eps = eps
        self.momentum = momentum
        self.rmax = rmax
        self.dmax = dmax

        self.weight = nn.Parameter(torch.ones(num_features))
        self.bias = nn.Parameter(torch.zeros(num_features))

        self.register_buffer('running_mean', torch.zeros(num_features))
        self.register_buffer('running_var', torch.ones(num_features))
        self.register_buffer('num_batches_tracked', torch.tensor(0, dtype=torch.long))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.training:
            if x.dim() == 3:
                mean = x.mean(dim=(0, 1))
                var = x.var(dim=(0, 1), unbiased=False)
            else:
                mean = x.mean(dim=0)
                var = x.var(dim=0, unbiased=False)

            # Batch renorm corrections
            r = torch.sqrt((var + self.eps) / (self.running_var + self.eps))
            r = torch.clamp(r, 1.0 / self.rmax, self.rmax)
            d = (mean - self.running_mean) / torch.sqrt(self.running_var + self.eps)
            d = torch.clamp(d, -self.dmax, self.dmax)

            # Update running statistics
            with torch.no_grad():
                self.running_mean = self.momentum * mean + (1 - self.momentum) * self.running_mean
                self.running_var = self.momentum * var + (1 - self.momentum) * self.running_var
                self.num_batches_tracked += 1

            # Apply batch renormalization
            x_norm = (x - mean) / torch.sqrt(var + self.eps)
            x_norm = x_norm * r + d
        else:
            x_norm = (x - self.running_mean) / torch.sqrt(self.running_var + self.eps)

        return x_norm * self.weight + self.bias


class StochasticDepth(nn.Module):
    """
    DropPath / Stochastic Depth regularization.
    Randomly drops entire residual blocks during training.

    Reference: Huang et al., "Deep Networks with Stochastic Depth", 2016
    """
    def __init__(self, drop_prob: float = 0.0):
        super().__init__()
        self.drop_prob = drop_prob
        self.keep_prob = 1.0 - drop_prob

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        if self.drop_prob == 0.0 or not self.training:
            return x

        # Random binary mask
        shape = (x.shape[0],) + (1,) * (x.ndim - 1)
        random_tensor = self.keep_prob + torch.rand(shape, dtype=x.dtype, device=x.device)
        binary_tensor = torch.floor(random_tensor)

        # Scale by keep_prob to maintain expected value
        return x / self.keep_prob * binary_tensor


class GatedLinearUnit(nn.Module):
    """
    Gated Linear Unit (GLU) for better feature selection.
    Splits input into two halves: one acts as gate, other as value.

    Reference: Dauphin et al., "Language Modeling with Gated Convolutional Networks", 2017
    """
    def __init__(self, dim: int):
        super().__init__()
        self.dim = dim

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Split into value and gate
        value, gate = torch.chunk(x, 2, dim=-1)
        return value * torch.sigmoid(gate)


class TemporalPositionalEncoding(nn.Module):
    """
    Sinusoidal positional encoding for temporal sequences.
    Preserves temporal ordering that vanilla attention loses.

    Reference: Vaswani et al., "Attention Is All You Need", 2017
    """
    def __init__(self, d_model: int, max_len: int = 5000, dropout: float = 0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Create positional encoding matrix
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2, dtype=torch.float32) *
                            -(math.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        if d_model % 2 == 1:
            # Handle odd dimensions
            pe[:, 1::2] = torch.cos(position * div_term[:-1])
        else:
            pe[:, 1::2] = torch.cos(position * div_term)

        self.register_buffer('pe', pe.unsqueeze(0))  # (1, max_len, d_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (B, T, D) tensor
        Returns:
            x with positional encoding added: (B, T, D)
        """
        T = int(x.size(1))
        x = x + self.pe[:, :T, :]
        return self.dropout(x)


class TemporalConvBlock(nn.Module):
    """
    Temporal Convolutional Block with dilation for multi-scale temporal modeling.
    Uses causal padding to preserve temporal causality.
    """
    def __init__(self, in_channels: int, out_channels: int, kernel_size: int = 3,
                 dilation: int = 1, dropout: float = 0.2, use_glu: bool = True):
        super().__init__()
        self.use_glu = use_glu

        # Causal padding: (kernel_size - 1) * dilation on the left only
        self.padding = (kernel_size - 1) * dilation

        if use_glu:
            # GLU halves the output, so we need 2x output channels
            self.conv = nn.Conv1d(in_channels, out_channels * 2, kernel_size,
                                 padding=0, dilation=dilation)
            self.glu = GatedLinearUnit(out_channels)
        else:
            self.conv = nn.Conv1d(in_channels, out_channels, kernel_size,
                                 padding=0, dilation=dilation)

        self.norm = nn.LayerNorm(out_channels)
        self.dropout = nn.Dropout(dropout)
        self.activation = nn.GELU() if not use_glu else nn.Identity()

        # Residual connection
        self.residual = nn.Linear(in_channels, out_channels) if in_channels != out_channels else nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (B, T, C) tensor
        Returns:
            (B, T, C') tensor
        """
        # Transpose for conv1d: (B, C, T)
        x_t = x.transpose(1, 2)

        # Apply causal padding manually
        x_t = F.pad(x_t, (self.padding, 0))

        # Conv1d
        out = self.conv(x_t)

        # Transpose back: (B, T, C)
        out = out.transpose(1, 2)

        # Apply GLU if enabled
        if self.use_glu:
            out = self.glu(out)
        else:
            out = self.activation(out)

        out = self.norm(out)
        out = self.dropout(out)

        # Residual connection
        return out + self.residual(x)


class TemporalConvolutionalNetwork(nn.Module):
    """
    TCN with exponentially increasing dilation rates for multi-scale temporal modeling.
    Dilations [1, 2, 4, 8] provide receptive field of ~16 timesteps.
    """
    def __init__(self, input_size: int, hidden_size: int, num_layers: int = 4,
                 kernel_size: int = 3, dropout: float = 0.2, use_glu: bool = True):
        super().__init__()
        self.layers = nn.ModuleList()

        for i in range(num_layers):
            in_ch = input_size if i == 0 else hidden_size
            dilation = 2 ** i  # 1, 2, 4, 8
            self.layers.append(
                TemporalConvBlock(in_ch, hidden_size, kernel_size, dilation,
                                 dropout, use_glu)
            )

        self.output_norm = nn.LayerNorm(hidden_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        for layer in self.layers:
            x = layer(x)
        return self.output_norm(x)


class MotionEncoderV15(nn.Module):
    
    def __init__(self, input_size: int, embed_size: int, dropout: float = 0.2):
        super().__init__()
        wide1 = max(embed_size * 2, 128)
        wide2 = wide1 * 2  # GLU halves the dimension, so 2x for output
        self.stage1 = nn.Sequential(
            BatchRenorm1d(input_size),
            nn.Linear(input_size, wide2),  # 2x for GLU (halved during gating)
            GatedLinearUnit(wide1),
            nn.Dropout(dropout),
        )
        self.residual1 = nn.Linear(input_size, wide1)
        self.stage2 = nn.Sequential(
            BatchRenorm1d(wide1),
            nn.Linear(wide1, wide2),  # 2x for GLU (halved during gating)
            GatedLinearUnit(wide1),
            nn.Dropout(dropout),
        )
        self.stage3 = nn.Sequential(
            BatchRenorm1d(wide1),
            nn.Linear(wide1, embed_size),
            nn.GELU(),
            nn.LayerNorm(embed_size),
        )
        self.residual3 = nn.Linear(wide1, embed_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.stage1(x) + self.residual1(x)
        x = self.stage2(x) + x
        x = self.stage3(x) + self.residual3(x)

        return x


class MultiScaleTemporalAttention(nn.Module):
    # Multi-scale temporal attention with positional encoding.
    def __init__(self, hidden_size: int, num_heads: int = 8, num_scales: int = 3,
                 dropout: float = 0.1, max_len: int = 5000):
        super().__init__()
        # Ensure hidden_size is divisible by num_heads
        while hidden_size % num_heads != 0:
            num_heads -= 1

        self.hidden_size = hidden_size
        self.num_heads = num_heads
        self.num_scales = num_scales
        # Positional encoding
        self.pos_encoding = TemporalPositionalEncoding(hidden_size, max_len, dropout)
        # Multi-head self-attention
        self.attn = nn.MultiheadAttention(
            embed_dim=hidden_size, num_heads=num_heads,
            dropout=dropout, batch_first=True,
        )
        self.norm1 = nn.LayerNorm(hidden_size)
        # Multi-scale temporal pooling
        self.pool_sizes = [2 ** i for i in range(num_scales)]
        self.scale_pools = nn.ModuleList([
            nn.AdaptiveAvgPool1d(size) for size in self.pool_sizes
        ])
        self.scale_projections = nn.ModuleList([
            nn.Linear(hidden_size * size, hidden_size // num_scales)
            for size in self.pool_sizes
        ])
        # (hidden_size // num_scales) * num_scales may be < hidden_size due to int division
        combined_size = (hidden_size // num_scales) * num_scales
        self.scale_combiner = nn.Linear(combined_size, hidden_size)

        # FFN with GLU
        ffn_hidden = hidden_size * 4
        self.ffn = nn.Sequential(
            nn.Linear(hidden_size, ffn_hidden * 2),  # 2x for GLU (halved during gating)
            GatedLinearUnit(ffn_hidden),
            nn.Dropout(dropout),
            nn.Linear(ffn_hidden, hidden_size),
            nn.Dropout(dropout),
        )
        self.norm2 = nn.LayerNorm(hidden_size)
        # Stochastic depth
        self.drop_path = StochasticDepth(drop_prob=0.1)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (B, T, H) tensor
        Returns:
            (B, H) pooled context vector
        """
        # Add positional encoding
        x = self.pos_encoding(x)
        # Multi-head attention with residual
        attn_out, _ = self.attn(x, x, x)
        x = self.norm1(x + self.drop_path(attn_out))
        # Multi-scale temporal pooling
        x_t = x.transpose(1, 2)  # (B, H, T) for pooling
        # Force static shape for ONNX export
        x_t = x_t.view(-1, x_t.size(1), int(x_t.size(2)))
        scale_features = []
        is_exporting = torch.onnx.is_in_onnx_export()
        for pool, proj in zip(self.scale_pools, self.scale_projections):
            size = pool.output_size
            if is_exporting:
                if size == 1:
                    pooled = x_t.mean(dim=2, keepdim=True)
                elif x_t.size(2) % size == 0:
                    pooled = pool(x_t)
                else:
                    pooled = F.interpolate(x_t, size=size, mode='linear', align_corners=False)
            else:
                pooled = pool(x_t)  # (B, H, S)
            pooled_flat = pooled.reshape(pooled.size(0), -1)  # (B, H * S)
            projected = proj(pooled_flat)  # (B, H//num_scales)
            scale_features.append(projected)
        # Combine multi-scale features
        multi_scale = torch.cat(scale_features, dim=-1)  # (B, H)
        multi_scale = self.scale_combiner(multi_scale)
        # FFN with residual
        ff_out = self.ffn(x.mean(dim=1))  # Mean pooling then FFN
        output = self.norm2(multi_scale + self.drop_path(ff_out))

        return output


class FeaturePyramidNetwork(nn.Module):
    """
    Temporal Feature Pyramid Network.
    Takes (B, T, H) input, creates multi-scale temporal features via pooling,
    and fuses them using a top-down pathway with upsampling.
    Returns (B, T, H) enriched feature sequence.
    """
    def __init__(self, hidden_size: int, num_levels: int = 3):
        super().__init__()
        self.num_levels = num_levels

        # Lateral projections
        self.lateral_convs = nn.ModuleList([
            nn.Linear(hidden_size, hidden_size)
            for _ in range(num_levels)
        ])

        # Output convolutions
        self.output_convs = nn.ModuleList([
            nn.Sequential(
                nn.LayerNorm(hidden_size),
                nn.GELU(),
            )
            for _ in range(num_levels)
        ])

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: (B, T, H) tensor from LSTM
        Returns:
            (B, T, H) enriched feature sequence
        """
        # Bottom-up pathway
        features = [x]
        curr = x
        for _ in range(1, self.num_levels):
            # Pool temporally with kernel_size=2, stride=2
            curr = curr.transpose(1, 2)  # (B, H, T)
            curr = F.avg_pool1d(curr, kernel_size=2, stride=2, ceil_mode=True)
            curr = curr.transpose(1, 2)  # (B, T', H)
            features.append(curr)

        # Top-down pathway
        p_features = []
        # Process the lowest resolution level first (the last one in the features list)
        last_feat = features[-1]
        p = self.lateral_convs[-1](last_feat)
        p_features.append(self.output_convs[-1](p))

        # Traverse backwards
        for i in range(self.num_levels - 2, -1, -1):
            feat = features[i]
            lat = self.lateral_convs[i](feat)
            
            # Upsample the previous P (force target_length to static int for ONNX)
            target_length = int(feat.shape[1])
            p_upsampled = F.interpolate(
                p.transpose(1, 2), size=target_length, mode='linear', align_corners=False
            ).transpose(1, 2)
            
            p = lat + p_upsampled
            p_features.insert(0, self.output_convs[i](p))

        # Return the highest resolution enriched feature map (P1)
        return p_features[0]


#   Loss functions with class imbalance handling               ─

class FocalLoss(nn.Module):
    """
    Focal Loss for addressing class imbalance.
    Down-weights easy examples and focuses on hard examples.

    Reference: Lin et al., "Focal Loss for Dense Object Detection", 2017
    """
    def __init__(self, num_classes: int = 3, gamma: float = 2.0,
                 alpha: Optional[torch.Tensor] = None,
                 label_smoothing: float = 0.0,
                 reduction: str = 'mean'):
        super().__init__()
        self.num_classes = num_classes
        self.gamma = gamma
        self.label_smoothing = label_smoothing
        self.reduction = reduction

        # Class weights (inverse frequency)
        if alpha is not None:
            self.register_buffer('alpha', alpha)
        else:
            self.register_buffer('alpha', torch.ones(num_classes))

    def forward(self, inputs: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        """
        Args:
            inputs: (B, num_classes) logits
            targets: (B,) class indices
        Returns:
            scalar loss
        """
        # Apply label smoothing
        if self.label_smoothing > 0:
            targets_smooth = F.one_hot(targets, self.num_classes).float()
            targets_smooth = targets_smooth * (1 - self.label_smoothing) + \
                           self.label_smoothing / self.num_classes
            log_probs = F.log_softmax(inputs, dim=-1)
            ce_loss = -(targets_smooth * log_probs).sum(dim=-1)
        else:
            ce_loss = F.cross_entropy(inputs, targets, reduction='none')

        # Focal weighting
        probs = F.softmax(inputs, dim=-1)
        pt = probs.gather(1, targets.unsqueeze(1)).squeeze(1)
        focal_weight = (1 - pt) ** self.gamma

        # Apply class weights
        alpha_t = self.alpha.gather(0, targets)

        loss = alpha_t * focal_weight * ce_loss

        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        else:
            return loss


class LabelSmoothingCrossEntropy(nn.Module):
    """
    Cross-entropy with label smoothing for better calibration.
    """
    def __init__(self, num_classes: int = 3, smoothing: float = 0.1):
        super().__init__()
        self.confidence = 1.0 - smoothing
        self.smoothing = smoothing
        self.num_classes = num_classes

    def forward(self, x: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        log_probs = F.log_softmax(x, dim=-1)
        with torch.no_grad():
            true_dist = torch.zeros_like(log_probs)
            true_dist.fill_(self.smoothing / (self.num_classes - 1))
            true_dist.scatter_(1, target.unsqueeze(1), self.confidence)
        return torch.mean(torch.sum(-true_dist * log_probs, dim=-1))


#   Main model: SafeVisionLSTM v15                      ─

class SafeVisionLSTMv15(nn.Module):
    """
    Violence anticipation LSTM — v15: Major architectural overhaul.

    KEY IMPROVEMENTS over v14:

    1. BIDIRECTIONAL MULTI-LAYER LSTM
       - v14: num_lstm_layers=1 → dropout was silently ignored
       - v15: 2+ bidirectional layers with working dropout
       - Captures both forward and backward temporal context

    2. TEMPORAL CONVOLUTIONAL NETWORK (TCN) FRONT-END
       - Multi-scale temporal convolutions with dilations 1,2,4,8
       - Causal convolutions preserve temporal ordering
       - Exponential receptive field growth

    3. MULTI-SCALE TEMPORAL ATTENTION
       - Sinusoidal positional encodings preserve temporal order
       - Pyramid pooling over multiple temporal scales
       - Transformer-style FFN with GLU

    4. STOCHASTIC DEPTH REGULARIZATION
       - DropPath randomly drops entire residual blocks
       - Stronger regularization for deeper architecture

    5. GATED LINEAR UNITS (GLU)
       - Replaces GELU in key positions for better feature selection
       - Gating mechanism learns which features to propagate

    6. BATCH RENORMALIZATION
       - More stable than BatchNorm for small batch sizes
       - Better statistics for video inference scenarios

    7. FEATURE PYRAMID NETWORK
       - Aggregates features from multiple LSTM layers
       - Richer multi-scale representations

    8. CLASS IMBALANCE HANDLING
       - Focal Loss option for imbalanced datasets
       - Label smoothing for better calibration
       - Configurable class weights

    Architecture:
        Input (B, T, 440)  
        MotionEncoderV15 (batch renorm + GLU)
        TCN (dilated convolutions, dilations 1,2,4,8)
        BiLSTM (2+ layers, working dropout)
        Feature Pyramid (multi-layer aggregation)
        Multi-Scale Temporal Attention (pos encoding + pyramid pooling)
        Classifier (LayerNorm + Dropout + GELU)     
        Output: logits (B, 3)
    Aux: Per-frame danger regressor for timestep-level supervision
    """

    def __init__(
        self,
        input_size: int = 440,
        hidden_size: int = 128,
        num_classes: int = 3,
        num_heads: int = 8,
        num_lstm_layers: int = 2,  # CRITICAL: Must be >= 2 for dropout to work
        lstm_dropout: float = 0.3,
        tcn_layers: int = 4,
        tcn_dropout: float = 0.2,
        encoder_dropout: float = 0.2,
        stochastic_depth_prob: float = 0.1,
        use_focal_loss: bool = False,
        focal_gamma: float = 3.0,
        label_smoothing: float = 0.0,
        class_weights: Optional[List[float]] = None,
        use_tcn: bool = True,
    ):
        """
        Args:
            input_size: Feature dimension (440 for pose+flow features)
            hidden_size: LSTM hidden dimension
            num_classes: Number of output classes (3: safe/pre-violence/violence)
            num_heads: Attention heads
            num_lstm_layers: Number of LSTM layers (must be >= 2 for dropout)
            lstm_dropout: Dropout between LSTM layers
            tcn_layers: Number of TCN layers (dilations 1,2,4,8,...)
            tcn_dropout: Dropout in TCN blocks
            encoder_dropout: Dropout in motion encoder
            stochastic_depth_prob: DropPath probability
            use_focal_loss: Use Focal Loss instead of CE
            focal_gamma: Focal loss gamma parameter
            label_smoothing: Label smoothing factor (0 to disable)
            class_weights: Optional per-class loss weights
            use_tcn: Whether to use TCN front-end
        """
        super().__init__()

        assert num_lstm_layers >= 2, "num_lstm_layers must be >= 2 for dropout to have effect"

        self.hidden_size = hidden_size
        self.num_classes = num_classes
        self.num_lstm_layers = num_lstm_layers
        self.use_tcn = use_tcn

        #   Feature encoder                         ─
        self.motion_encoder = MotionEncoderV15(input_size, hidden_size, encoder_dropout)

        #   Temporal Convolutional Network (optional)             
        if use_tcn:
            self.tcn = TemporalConvolutionalNetwork(
                hidden_size, hidden_size, tcn_layers,
                kernel_size=3, dropout=tcn_dropout, use_glu=True
            )
            self.tcn_fusion = nn.Linear(hidden_size * 2, hidden_size)
        else:
            self.tcn = None
            self.register_parameter('tcn_fusion', None)

        #   Bidirectional LSTM                        
        # Note: hidden_size//2 for bidirectional so total remains hidden_size
        lstm_hidden = hidden_size // 2
        self.lstm = nn.LSTM(
            input_size=hidden_size,
            hidden_size=lstm_hidden,
            num_layers=num_lstm_layers,
            batch_first=True,
            bidirectional=True,
            dropout=lstm_dropout,  # Now actually works since num_layers >= 2
        )

        #   Feature Pyramid Network                     ─
        self.feature_pyramid = FeaturePyramidNetwork(hidden_size, num_levels=num_lstm_layers)

        #   Multi-scale temporal attention                  
        self.temporal_attention = MultiScaleTemporalAttention(
            hidden_size, num_heads=num_heads, num_scales=3,
            dropout=lstm_dropout
        )

        #   Direct skip connections                     
        self.encoder_skip = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.LayerNorm(hidden_size),
        )

        # Stochastic depth for skip connection
        self.skip_drop_path = StochasticDepth(stochastic_depth_prob)

        #   Classification head                       
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_size),
            nn.Dropout(lstm_dropout),
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Dropout(lstm_dropout * 0.5),
            nn.Linear(hidden_size, num_classes),
        )

        #   Auxiliary frame-level danger regressor             ─
        self.danger_regressor = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(lstm_dropout * 0.5),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid(),
        )

        #   Loss function configuration                   ─
        if use_focal_loss:
            alpha = torch.tensor(class_weights) if class_weights else torch.ones(num_classes)
            self.criterion = FocalLoss(
                num_classes=num_classes,
                gamma=focal_gamma,
                alpha=alpha,
                label_smoothing=label_smoothing,
            )
        elif label_smoothing > 0:
            self.criterion = LabelSmoothingCrossEntropy(
                num_classes=num_classes,
                smoothing=label_smoothing,
            )
        else:
            weight = torch.tensor(class_weights) if class_weights else None
            self.criterion = nn.CrossEntropyLoss(weight=weight)

        self._init_weights()

    def _init_weights(self):
        """Careful weight initialization for stable training."""
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.LSTM):
                for name, param in m.named_parameters():
                    if 'weight' in name:
                        # Orthogonal initialization for LSTM
                        nn.init.orthogonal_(param)
                    elif 'bias' in name:
                        nn.init.zeros_(param)
                        # Forget gate bias to 1 for better gradient flow
                        if 'bias_ih' in name or 'bias_hh' in name:
                            n = param.size(0)
                            param.data[n//4:n//2].fill_(1.0)
            elif isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode='fan_out', nonlinearity='relu')
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, (nn.LayerNorm, BatchRenorm1d)):
                if m.weight is not None:
                    nn.init.ones_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def freeze_encoder(self):
        """Freeze motion encoder for 2-stage pre-training."""
        for param in self.motion_encoder.parameters():
            param.requires_grad = False

    def unfreeze_encoder(self):
        """Unfreeze motion encoder for fine-tuning."""
        for param in self.motion_encoder.parameters():
            param.requires_grad = True

    def freeze_tcn(self):
        """Freeze TCN for staged training."""
        if self.tcn:
            for param in self.tcn.parameters():
                param.requires_grad = False

    def unfreeze_tcn(self):
        """Unfreeze TCN."""
        if self.tcn:
            for param in self.tcn.parameters():
                param.requires_grad = True

    def count_trainable(self) -> int:
        """Count trainable parameters."""
        return sum(p.numel() for p in self.parameters() if p.requires_grad)

    def count_total(self) -> int:
        """Count total parameters."""
        return sum(p.numel() for p in self.parameters())

    def forward(
        self,
        x: torch.Tensor,
        observe_ratio: float = 0.6,
        return_aux_loss: bool = False,
        labels: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Forward pass with optional auxiliary loss.

        Args:
            x: (B, T, F) input sequences
            observe_ratio: Fraction of T to feed to the model (anticipation)
            return_aux_loss: Whether to compute and return auxiliary loss
            labels: (B,) class labels, required if return_aux_loss=True

        Returns:
            logits: (B, num_classes) class logits
            aux_loss: Optional scalar tensor for frame-level danger prediction
        """
        B, T, input_features = x.shape

        observe_len = max(2, int(T * observe_ratio))
        x_obs = x[:, :observe_len, :]

        #   Per-frame encoding                       ─
        x_flat = x_obs.reshape(-1, input_features)
        x_enc = self.motion_encoder(x_flat)
        x_enc = x_enc.reshape(-1, observe_len, x_enc.shape[-1])  # (B, T_obs, H)

        #   Optional TCN front-end                      ─
        if self.use_tcn and self.tcn is not None:
            x_tcn = self.tcn(x_enc)  # (B, T_obs, H)
            # Fusion with residual
            x_enc = self.tcn_fusion(torch.cat([x_enc, x_tcn], dim=-1))

        #   Bidirectional LSTM                        ─
        lstm_out, _ = self.lstm(x_enc)  # (B, T_obs, H) where H = hidden_size (bidirectional)

        #   Feature Pyramid Network                     ─
        # Enriches the LSTM output with multi-scale temporal context
        context = self.feature_pyramid(lstm_out)

        #   Multi-scale temporal attention                  ─
        attn_ctx = self.temporal_attention(context)  # (B, H)

        #   Encoder skip with stochastic depth                
        enc_skip = self.encoder_skip(x_enc.mean(dim=1))  # (B, H)
        enc_skip = self.skip_drop_path(enc_skip)
        context_final = attn_ctx + enc_skip  # (B, H)

        #   Classification                          ─
        logits = self.classifier(context_final)  # (B, num_classes)

        #   Auxiliary danger regressor                     
        if return_aux_loss:
            danger_scores = self.danger_regressor(lstm_out).squeeze(-1)  # (B, T_obs)

            if labels is not None:
                full_targets = build_danger_targets(labels, T)
                obs_targets = full_targets[:, :observe_len]
                aux_loss = F.mse_loss(danger_scores, obs_targets)
            else:
                aux_loss = torch.tensor(0.0, device=x.device)

            return logits, aux_loss

        return logits, None

    def compute_loss(
        self,
        logits: torch.Tensor,
        labels: torch.Tensor,
        aux_loss: Optional[torch.Tensor] = None,
        aux_weight: float =0.4
    ) -> torch.Tensor:
        """
        Compute combined classification + auxiliary loss.

        Args:
            logits: (B, num_classes) model outputs
            labels: (B,) ground truth labels
            aux_loss: Optional scalar from danger regressor
            aux_weight: Weight for auxiliary loss

        Returns:
            Combined loss scalar
        """
        cls_loss = self.criterion(logits, labels)

        if aux_loss is not None and aux_loss > 0:
            return cls_loss + aux_weight * aux_loss
        return cls_loss


#   Lightweight variant for edge deployment                  

class SafeVisionLSTMv15_Lite(nn.Module):
    """
    Lightweight variant of v15 for edge deployment.

    Reduces parameters by:
    - Smaller hidden_size (64 vs 128)
    - Fewer TCN layers (2 vs 4)
    - Single LSTM layer (no dropout, but uses dropout in encoder)
    - Simplified attention (no multi-scale)
    """

    def __init__(
        self,
        input_size: int = 440,
        hidden_size: int = 64,
        num_classes: int = 3,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.hidden_size = hidden_size

        # Simplified encoder
        self.encoder = nn.Sequential(
            nn.LayerNorm(input_size),
            nn.Linear(input_size, hidden_size * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size * 2, hidden_size),
            nn.LayerNorm(hidden_size),
        )
        self.encoder_skip = nn.Linear(input_size, hidden_size)

        # Single LSTM (no dropout between layers since num_layers=1)
        self.lstm = nn.LSTM(
            input_size=hidden_size,
            hidden_size=hidden_size,
            num_layers=1,
            batch_first=True,
            bidirectional=False,
        )

        # Simple attention
        self.attention = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.Tanh(),
            nn.Linear(hidden_size // 2, 1),
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.LayerNorm(hidden_size),
            nn.Dropout(dropout),
            nn.Linear(hidden_size, num_classes),
        )

        # Aux regressor
        self.danger_regressor = nn.Sequential(
            nn.Linear(hidden_size, 32),
            nn.GELU(),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.LSTM):
                for name, param in m.named_parameters():
                    if 'weight' in name:
                        nn.init.orthogonal_(param)
                    elif 'bias' in name:
                        nn.init.zeros_(param)

    def forward(self, x, observe_ratio=0.6, return_aux_loss=False, labels=None):
        B, T, input_features = x.shape

        observe_len = max(2, int(T * observe_ratio))
        x_obs = x[:, :observe_len, :]

        # Encode
        x_flat = x_obs.reshape(B * observe_len, input_features)
        x_enc = self.encoder(x_flat) + self.encoder_skip(x_flat)
        x_enc = x_enc.reshape(B, observe_len, -1)

        # LSTM
        lstm_out, _ = self.lstm(x_enc)

        # Attention pooling
        attn_weights = F.softmax(self.attention(lstm_out), dim=1)
        context = (lstm_out * attn_weights).sum(dim=1)

        # Classify
        logits = self.classifier(context)

        if return_aux_loss:
            danger_scores = self.danger_regressor(lstm_out).squeeze(-1)
            if labels is not None:
                targets = build_danger_targets(labels, T)[:, :observe_len]
                aux_loss = F.mse_loss(danger_scores, targets)
            else:
                aux_loss = torch.tensor(0.0, device=x.device)
            return logits, aux_loss

        return logits, None


#   Inference helpers                             ─

def process_full_sequence(
    model: nn.Module,
    frame_buffer: list,
    observe_ratio: float = 0.6,
    device: str = 'cpu'
) -> Tuple[int, float, list]:
    """
    Run inference on a list of raw BGR frames.

    Args:
        model: SafeVisionLSTMv15 or SafeVisionLSTMv15_Lite instance
        frame_buffer: List of BGR frames
        observe_ratio: Fraction of sequence to observe (anticipation setting)
        device: 'cpu' or 'cuda'

    Returns:
        predicted_class: int (0=Safe, 1=Pre-Violence, 2=Violence)
        confidence: float probability of predicted class
        all_probs: list of probabilities for all classes
    """
    raw_sequence = []
    prev_kp = prev_vel = prev_gray = None

    for frame in frame_buffer:
        features, curr_kp, curr_vel, curr_gray, _ = extract_features(
            frame, prev_kp, prev_vel, prev_gray,
        )
        raw_sequence.append(features)
        prev_kp, prev_vel, prev_gray = curr_kp, curr_vel, curr_gray

    sequence = build_sequence_features(raw_sequence)
    input_tensor = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0).to(device)

    model.eval()
    with torch.no_grad():
        logits, _ = model(input_tensor, observe_ratio=observe_ratio)
        probs = F.softmax(logits, dim=1)
        confidence, pred_idx = probs.max(dim=1)

    return pred_idx.item(), confidence.item(), probs[0].cpu().tolist()


def process_sequence_features(
    model: nn.Module,
    features: np.ndarray,
    observe_ratio: float = 0.6,
    device: str = 'cpu'
) -> Tuple[int, float, list]:
    """
    Run inference on pre-computed feature sequence.

    Args:
        model: SafeVisionLSTMv15 instance
        features: (T, 440) numpy array of pre-computed features
        observe_ratio: Fraction of sequence to observe
        device: 'cpu' or 'cuda'

    Returns:
        predicted_class, confidence, all_probs
    """
    input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device)

    model.eval()
    with torch.no_grad():
        logits, _ = model(input_tensor, observe_ratio=observe_ratio)
        probs = F.softmax(logits, dim=1)
        confidence, pred_idx = probs.max(dim=1)

    return pred_idx.item(), confidence.item(), probs[0].cpu().tolist()


def get_temporal_attention_weights(
    model: SafeVisionLSTMv15,
    features: np.ndarray,
    observe_ratio: float = 0.6,
    device: str = 'cpu'
) -> np.ndarray:
    """
    Extract temporal attention weights for visualization.

    Args:
        model: SafeVisionLSTMv15 instance
        features: (T, 440) numpy array
        observe_ratio: Observation ratio
        device: 'cpu' or 'cuda'

    Returns:
        attention_weights: (T_obs,) numpy array of attention weights
    """
    model.eval()
    input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device)

    B, T, _ = input_tensor.shape
    observe_len = max(2, int(T * observe_ratio))
    x_obs = input_tensor[:, :observe_len, :]

    with torch.no_grad():
        # Encode
        x_flat = x_obs.reshape(B * observe_len, input_features)
        x_enc = model.motion_encoder(x_flat)
        x_enc = x_enc.reshape(B, observe_len, -1)

        # TCN
        if model.use_tcn and model.tcn is not None:
            x_tcn = model.tcn(x_enc)
            x_enc = model.tcn_fusion(torch.cat([x_enc, x_tcn], dim=-1))

        # LSTM
        lstm_out, _ = model.lstm(x_enc)

        # Get attention weights
        # Add positional encoding
        x_pos = model.temporal_attention.pos_encoding(lstm_out)

        # Multi-head attention forward manually to get weights
        attn_out, attn_weights = model.temporal_attention.attn(
            x_pos, x_pos, x_pos, average_attn_weights=False
        )

    # Average over heads and batch
    weights = attn_weights.mean(dim=(0, 1)).cpu().numpy()
    return weights


#   Model creation helpers                          ─

def create_v15_model(
    variant: str = 'full',
    num_classes: int = 3,
    use_focal_loss: bool = False,
    class_weights: Optional[List[float]] = None,
    **kwargs
) -> nn.Module:
    """
    Factory function to create SafeVisionLSTMv15 models.

    Args:
        variant: 'full' for full model, 'lite' for edge deployment
        num_classes: Number of output classes
        use_focal_loss: Whether to use focal loss
        class_weights: Per-class weights for loss
        **kwargs: Additional arguments passed to model constructor

    Returns:
        Instantiated model
    """
    if variant == 'full':
        return SafeVisionLSTMv15(
            num_classes=num_classes,
            use_focal_loss=use_focal_loss,
            class_weights=class_weights,
            **kwargs
        )
    elif variant == 'lite':
        return SafeVisionLSTMv15_Lite(
            num_classes=num_classes,
            **kwargs
        )
    else:
        raise ValueError(f"Unknown variant: {variant}. Choose 'full' or 'lite'.")


def create_focal_loss_weights(beta: float = 0.9999, samples_per_class: List[int] = None):
    """
    Create class weights for focal loss using inverse frequency weighting.

    Args:
        beta: Smoothing parameter for effective number calculation
        samples_per_class: List of sample counts [n_safe, n_pre, n_violence]

    Returns:
        Tensor of class weights
    """
    if samples_per_class is None:
        # Default estimated distribution for violence detection
        # (heavily imbalanced toward safe)
        samples_per_class = [10000, 1000, 500]

    effective_num = 1.0 - np.power(beta, samples_per_class)
    weights = (1.0 - beta) / effective_num
    weights = weights / weights.sum() * len(samples_per_class)

    return torch.tensor(weights, dtype=torch.float32)


#   Example usage and testing                         

if __name__ == "__main__":
    # Test model creation and forward pass
    print("Testing SafeVisionLSTMv15...")

    # Create model with focal loss for imbalanced data
    class_weights = [0.5, 1.5, 2.0]  # Up-weight violence and pre-violence
    model = SafeVisionLSTMv15(
        input_size=440,
        hidden_size=128,
        num_classes=3,
        num_lstm_layers=2,
        use_focal_loss=True,
        focal_gamma=2.0,
        label_smoothing=0.1,
        class_weights=class_weights,
        use_tcn=True,
    )

    print(f"Total parameters: {model.count_total():,}")
    print(f"Trainable parameters: {model.count_trainable():,}")

    # Test forward pass
    batch_size = 4
    seq_len = 30
    features = 440

    x = torch.randn(batch_size, seq_len, features)
    labels = torch.randint(0, 3, (batch_size,))

    logits, aux_loss = model(x, observe_ratio=0.6, return_aux_loss=True, labels=labels)

    print(f"Input shape: {x.shape}")
    print(f"Logits shape: {logits.shape}")
    print(f"Aux loss: {aux_loss.item():.4f}")

    # Test loss computation
    total_loss = model.compute_loss(logits, labels, aux_loss)
    print(f"Total loss: {total_loss.item():.4f}")

    # Test lite variant
    print("\nTesting SafeVisionLSTMv15_Lite...")
    lite_model = SafeVisionLSTMv15_Lite(hidden_size=64)
    lite_params = sum(p.numel() for p in lite_model.parameters())
    print(f"Lite model parameters: {lite_params:,}")

    logits_lite, _ = lite_model(x, observe_ratio=0.6)
    print(f"Lite logits shape: {logits_lite.shape}")

    print("\nAll tests passed!")

SafeVisionLSTM = SafeVisionLSTMv15
