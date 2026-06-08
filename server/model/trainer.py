"""
trainer.py — Complete Training Pipeline for SafeVision LSTM Models

Supports both SafeVisionLSTMv15 (full) and SafeVisionLSTMv15_Lite variants
with comprehensive training features:
    - Learning rate scheduling (warmup + cosine decay)
    - Early stopping based on validation metrics
    - Checkpoint management (best, last, periodic)
    - TensorBoard and CSV logging
    - Gradient clipping and mixed precision training
    - Stratified k-fold cross-validation
    - Staged training (freeze/unfreeze encoder)

Usage:
    # Train full model from scratch
    python trainer.py --train_data ./datasets/train.npz \
                      --val_data ./datasets/val.npz \
                      --output_dir ./runs/exp001

    # Train with cross-validation
    python trainer.py --data_path ./datasets/train.npz \
                      --cross_validation --num_folds 5

    # Train lite model
    python trainer.py --train_data ./datasets/train.npz \
                      --val_data ./datasets/val.npz \
                      --model_variant lite

    # Resume from checkpoint
    python trainer.py --resume ./runs/exp001/checkpoints/last.pt
"""

import os
import sys
import json
import time
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict
import warnings

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torch.utils.tensorboard import SummaryWriter
from torch.cuda.amp import autocast, GradScaler
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR, LinearLR, SequentialLR
from sklearn.metrics import (accuracy_score, precision_recall_fscore_support,
                             confusion_matrix, classification_report)
from tqdm import tqdm

# Import local modules
from lstm_model_v15 import (SafeVisionLSTMv15, SafeVisionLSTMv15_Lite,
                            FocalLoss, LabelSmoothingCrossEntropy,
                            build_danger_targets)
from dataset_builder import SafeVisionDataset, WeightedSequenceSampler, load_dataset

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)

# Class names
CLASS_NAMES = ['safe', 'pre_violence', 'violence']


@dataclass
class TrainingConfig:
    """Configuration for training."""
    # Model configuration
    model_variant: str = 'full'  # 'full' or 'lite'
    input_size: int = 440
    hidden_size: int = 128
    num_classes: int = 3
    num_lstm_layers: int = 2
    num_heads: int = 8

    # Training configuration
    batch_size: int = 32
    num_epochs: int = 100
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    max_grad_norm: float = 1.0

    # Loss configuration
    loss_type: str = 'focal'  # 'ce', 'focal', 'label_smoothing'
    focal_gamma: float = 2.0
    label_smoothing: float = 0.1
    # Adjusted for dataset imbalance: safe(16%), pre_violence(19%), violence(64%)
    class_weights: Optional[List[float]] = None
    aux_loss_weight: float = 0.25

    # LR scheduling
    warmup_epochs: int = 5
    warmup_factor: float = 0.1
    lr_scheduler: str = 'cosine'  # 'cosine', 'step', 'plateau'

    # Early stopping
    early_stopping: bool = True
    patience: int = 15
    monitor_metric: str = 'f1_macro'  # 'loss', 'accuracy', 'f1_macro' (or prefixed: 'val_f1_macro')
    mode: str = 'max'  # 'max' or 'min'

    # Checkpointing
    save_best: bool = True
    save_last: bool = True
    save_period: int = 10  # Save every N epochs
    checkpoint_dir: str = './checkpoints'

    # Training features
    mixed_precision: bool = True
    gradient_clipping: bool = True
    observe_ratio: float = 0.6

    # Staged training
    staged_training: bool = False
    freeze_epochs: int = 10  # Freeze encoder for first N epochs

    # Cross-validation
    cross_validation: bool = False
    num_folds: int = 5
    fold_idx: int = 0

    # Data configuration
    sequence_length: int = 30
    num_workers: int = 4
    use_weighted_sampling: bool = True

    # Logging
    log_dir: str = './logs'
    log_interval: int = 10  # Log every N batches
    tensorboard: bool = True

    # Device
    device: str = 'auto'  # 'auto', 'cuda', 'cpu'

    def to_dict(self) -> Dict:
        return asdict(self)

    def save(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> 'TrainingConfig':
        with open(path, 'r') as f:
            return cls(**json.load(f))


class MetricsTracker:
    """Track and compute training metrics."""

    def __init__(self, num_classes: int = 3):
        self.num_classes = num_classes
        self.reset()

    def reset(self):
        self.predictions = []
        self.targets = []
        self.losses = []
        self.probs = []

    def update(self, logits: torch.Tensor, labels: torch.Tensor, loss: float):
        """Update metrics with a batch of predictions."""
        preds = logits.argmax(dim=1).cpu().numpy()
        probs = F.softmax(logits, dim=1).cpu().numpy()

        self.predictions.extend(preds)
        self.targets.extend(labels.cpu().numpy())
        self.probs.extend(probs)
        self.losses.append(loss)

    def compute(self) -> Dict[str, float]:
        """Compute all metrics."""
        predictions = np.array(self.predictions)
        targets = np.array(self.targets)

        # Accuracy
        accuracy = accuracy_score(targets, predictions)

        # Per-class precision, recall, F1
        precision, recall, f1, support = precision_recall_fscore_support(
            targets, predictions,
            labels=list(range(self.num_classes)),
            zero_division=0
        )

        # Macro averages
        precision_macro = precision.mean()
        recall_macro = recall.mean()
        f1_macro = f1.mean()

        # Weighted averages
        if support.sum() > 0:
            precision_weighted = np.average(precision, weights=support)
            recall_weighted = np.average(recall, weights=support)
            f1_weighted = np.average(f1, weights=support)
        else:
            precision_weighted = recall_weighted = f1_weighted = 0.0

        # Confusion matrix
        conf_mat = confusion_matrix(targets, predictions, labels=list(range(self.num_classes)))

        metrics = {
            'loss': np.mean(self.losses),
            'accuracy': accuracy,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'f1_macro': f1_macro,
            'precision_weighted': precision_weighted,
            'recall_weighted': recall_weighted,
            'f1_weighted': f1_weighted,
            'confusion_matrix': conf_mat.tolist(),
        }

        # Per-class metrics
        for i, name in enumerate(CLASS_NAMES):
            metrics[f'{name}_precision'] = precision[i]
            metrics[f'{name}_recall'] = recall[i]
            metrics[f'{name}_f1'] = f1[i]
            metrics[f'{name}_support'] = int(support[i])

        return metrics


class EarlyStopping:
    """Early stopping with patience and optional metric monitoring."""

    def __init__(
        self,
        patience: int = 10,
        min_delta: float = 1e-4,
        mode: str = 'max',
        verbose: bool = True
    ):
        self.patience = patience
        self.min_delta = min_delta
        self.mode = mode
        self.verbose = verbose
        self.counter = 0
        self.best_score = None
        self.early_stop = False

        if mode == 'max':
            self.is_better = lambda score, best: score > best + min_delta
        else:
            self.is_better = lambda score, best: score < best - min_delta

    def __call__(self, score: float) -> bool:
        if self.best_score is None:
            self.best_score = score
            return False

        if self.is_better(score, self.best_score):
            self.best_score = score
            self.counter = 0
            if self.verbose:
                logger.info(f"EarlyStopping: New best score: {score:.4f}")
        else:
            self.counter += 1
            if self.verbose:
                logger.info(f"EarlyStopping: No improvement ({self.counter}/{self.patience})")

        if self.counter >= self.patience:
            self.early_stop = True
            if self.verbose:
                logger.info(f"EarlyStopping: Triggered after {self.patience} epochs")

        return self.early_stop


class CheckpointManager:
    """Manage model checkpoints."""

    def __init__(
        self,
        checkpoint_dir: str,
        save_best: bool = True,
        save_last: bool = True,
        save_period: int = 10,
        monitor: str = 'val_f1_macro',
        mode: str = 'max'
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self.save_best = save_best
        self.save_last = save_last
        self.save_period = save_period
        self.monitor = monitor
        self.mode = mode

        self.best_score = float('-inf') if mode == 'max' else float('inf')
        self.best_path = None

    def save_checkpoint(
        self,
        epoch: int,
        model: nn.Module,
        optimizer: torch.optim.Optimizer,
        scheduler: Optional[Any],
        metrics: Dict[str, float],
        is_best: bool = False
    ):
        """Save a checkpoint."""
        checkpoint = {
            'epoch': epoch,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'metrics': metrics,
        }

        if scheduler is not None:
            checkpoint['scheduler_state_dict'] = scheduler.state_dict()

        # Save last checkpoint
        if self.save_last:
            last_path = self.checkpoint_dir / 'last.pt'
            torch.save(checkpoint, last_path)

        # Save periodic checkpoint
        if self.save_period > 0 and (epoch + 1) % self.save_period == 0:
            periodic_path = self.checkpoint_dir / f'epoch_{epoch + 1}.pt'
            torch.save(checkpoint, periodic_path)
            logger.info(f"Saved periodic checkpoint: {periodic_path}")

        # Save best checkpoint
        if is_best and self.save_best:
            best_path = self.checkpoint_dir / 'best.pt'
            torch.save(checkpoint, best_path)
            self.best_path = str(best_path)
            # Try to get metric value (handle optional val_/train_ prefix)
            metric_val = metrics.get(self.monitor)
            if metric_val is None:
                bare_key = self.monitor.removeprefix('val_').removeprefix('train_')
                metric_val = metrics.get(bare_key, 'N/A')
            
            # Format value for display
            val_str = f"{metric_val:.4f}" if isinstance(metric_val, (int, float)) else str(metric_val)
            logger.info(f"Saved best checkpoint: {best_path} ({self.monitor}: {val_str})")

    def load_checkpoint(
        self,
        checkpoint_path: str,
        model: nn.Module,
        optimizer: Optional[torch.optim.Optimizer] = None,
        scheduler: Optional[Any] = None,
        strict: bool = True
    ) -> Dict:
        """Load a checkpoint."""
        checkpoint = torch.load(checkpoint_path, map_location='cpu')

        model.load_state_dict(checkpoint['model_state_dict'], strict=strict)

        if optimizer is not None and 'optimizer_state_dict' in checkpoint:
            optimizer.load_state_dict(checkpoint['optimizer_state_dict'])

        if scheduler is not None and 'scheduler_state_dict' in checkpoint:
            scheduler.load_state_dict(checkpoint['scheduler_state_dict'])

        logger.info(f"Loaded checkpoint from {checkpoint_path} (epoch {checkpoint.get('epoch', 'unknown')})")

        return checkpoint


class CSVLogger:
    """Log training metrics to CSV file."""

    def __init__(self, log_dir: str, filename: str = 'training_log.csv'):
        self.log_path = Path(log_dir) / filename
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.headers = None
        self.file = None

    def setup(self, headers: List[str]):
        self.headers = headers
        self.file = open(self.log_path, 'w', newline='')
        self.file.write(','.join(headers) + '\n')
        self.file.flush()

    def log(self, values: Dict[str, float]):
        if self.file is None:
            raise RuntimeError("CSVLogger not setup. Call setup() first.")

        row = [str(values.get(h, '')) for h in self.headers]
        self.file.write(','.join(row) + '\n')
        self.file.flush()

    def close(self):
        if self.file is not None:
            self.file.close()

    def __del__(self):
        self.close()


class Trainer:
    """Complete training pipeline for SafeVision LSTM models."""

    def __init__(self, config: TrainingConfig):
        self.config = config
        self.device = self._get_device()

        # Create output directories
        self.output_dir = Path(config.checkpoint_dir).parent if config.checkpoint_dir else Path('./output')
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self._setup_logging()

        # Build model
        self.model = self._build_model()
        logger.info(f"Model: {self.config.model_variant}")
        logger.info(f"Total parameters: {sum(p.numel() for p in self.model.parameters()):,}")
        logger.info(f"Trainable parameters: {sum(p.numel() for p in self.model.parameters() if p.requires_grad):,}")

        # Setup optimizer and scheduler
        self.optimizer = self._build_optimizer()
        self.scheduler = self._build_scheduler()

        # Mixed precision
        self.use_amp = config.mixed_precision and torch.cuda.is_available()
        self.scaler = GradScaler() if self.use_amp else None

        # Checkpoint manager
        self.checkpoint_manager = CheckpointManager(
            checkpoint_dir=config.checkpoint_dir,
            save_best=config.save_best,
            save_last=config.save_last,
            save_period=config.save_period,
            monitor=config.monitor_metric,
            mode=config.mode
        )

        # Early stopping
        self.early_stopping = EarlyStopping(
            patience=config.patience,
            mode=config.mode
        ) if config.early_stopping else None

        # Metrics tracking
        self.metrics_tracker = {'train': MetricsTracker(), 'val': MetricsTracker()}

        # TensorBoard
        self.writer = SummaryWriter(config.log_dir) if config.tensorboard else None

        # CSV logger
        self.csv_logger = CSVLogger(config.log_dir)

        # Training state
        self.current_epoch = 0
        self.best_metric = float('-inf') if config.mode == 'max' else float('inf')

    def _get_device(self) -> torch.device:
        if self.config.device == 'auto':
            return torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        return torch.device(self.config.device)

    def _setup_logging(self):
        """Setup file logging."""
        log_file = self.output_dir / 'training.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
        logger.addHandler(file_handler)

        # Save config
        config_path = self.output_dir / 'config.json'
        self.config.save(str(config_path))

    def _build_model(self) -> nn.Module:
        """Build the model."""
        if self.config.model_variant == 'full':
            model = SafeVisionLSTMv15(
                input_size=self.config.input_size,
                hidden_size=self.config.hidden_size,
                num_classes=self.config.num_classes,
                num_lstm_layers=self.config.num_lstm_layers,
                num_heads=self.config.num_heads,
                use_focal_loss=(self.config.loss_type == 'focal'),
                focal_gamma=self.config.focal_gamma,
                label_smoothing=self.config.label_smoothing,
                class_weights=self.config.class_weights,
            )
        else:
            model = SafeVisionLSTMv15_Lite(
                input_size=self.config.input_size,
                hidden_size=self.config.hidden_size // 2,  # Smaller for lite
                num_classes=self.config.num_classes,
            )

        return model.to(self.device)

    def _build_optimizer(self) -> torch.optim.Optimizer:
        """Build the optimizer."""
        # Separate parameters with/without weight decay
        decay_params = []
        no_decay_params = []

        for name, param in self.model.named_parameters():
            if not param.requires_grad:
                continue
            if 'bias' in name or 'norm' in name.lower() or 'ln' in name:
                no_decay_params.append(param)
            else:
                decay_params.append(param)

        param_groups = [
            {'params': decay_params, 'weight_decay': self.config.weight_decay},
            {'params': no_decay_params, 'weight_decay': 0.0}
        ]

        optimizer = AdamW(param_groups, lr=self.config.learning_rate)
        return optimizer

    def _build_scheduler(self):
        """Build learning rate scheduler with warmup."""
        total_steps = self.config.num_epochs
        warmup_steps = self.config.warmup_epochs

        if warmup_steps > 0:
            warmup_scheduler = LinearLR(
                self.optimizer,
                start_factor=self.config.warmup_factor,
                end_factor=1.0,
                total_iters=warmup_steps
            )

            if self.config.lr_scheduler == 'cosine':
                main_scheduler = CosineAnnealingLR(
                    self.optimizer,
                    T_max=total_steps - warmup_steps,
                    eta_min=self.config.learning_rate * 0.01
                )
            else:
                main_scheduler = None

            if main_scheduler:
                scheduler = SequentialLR(
                    self.optimizer,
                    schedulers=[warmup_scheduler, main_scheduler],
                    milestones=[warmup_steps]
                )
            else:
                scheduler = warmup_scheduler
        else:
            if self.config.lr_scheduler == 'cosine':
                scheduler = CosineAnnealingLR(
                    self.optimizer,
                    T_max=total_steps,
                    eta_min=self.config.learning_rate * 0.01
                )
            else:
                scheduler = None

        return scheduler

    def _compute_loss(
        self,
        logits: torch.Tensor,
        labels: torch.Tensor,
        aux_loss: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """Compute loss with optional auxiliary loss."""
        # Main classification loss
        if self.config.loss_type == 'focal':
            loss = self.model.criterion(logits, labels)
        elif self.config.loss_type == 'label_smoothing':
            loss = self.model.criterion(logits, labels)
        else:
            loss = F.cross_entropy(logits, labels)

        # Add auxiliary loss if provided
        if aux_loss is not None and self.config.aux_loss_weight > 0:
            loss = loss + self.config.aux_loss_weight * aux_loss

        return loss

    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """Train for one epoch."""
        self.model.train()
        self.metrics_tracker['train'].reset()

        # Handle staged training
        if self.config.staged_training:
            if self.current_epoch == 0:
                logger.info("Freezing encoder for staged training...")
                if hasattr(self.model, 'freeze_encoder'):
                    self.model.freeze_encoder()
            elif self.current_epoch == self.config.freeze_epochs:
                logger.info("Unfreezing encoder...")
                if hasattr(self.model, 'unfreeze_encoder'):
                    self.model.unfreeze_encoder()

        pbar = tqdm(train_loader, desc=f"Epoch {self.current_epoch + 1} [Train]")

        for batch_idx, (features, labels, _) in enumerate(pbar):
            features = features.to(self.device)
            labels = labels.to(self.device)

            self.optimizer.zero_grad()

            # Forward pass with mixed precision
            if self.use_amp:
                with autocast():
                    logits, aux_loss = self.model(
                        features,
                        observe_ratio=self.config.observe_ratio,
                        return_aux_loss=True,
                        labels=labels
                    )
                    loss = self._compute_loss(logits, labels, aux_loss)
            else:
                logits, aux_loss = self.model(
                    features,
                    observe_ratio=self.config.observe_ratio,
                    return_aux_loss=True,
                    labels=labels
                )
                loss = self._compute_loss(logits, labels, aux_loss)

            # Backward pass
            if self.use_amp:
                self.scaler.scale(loss).backward()

                # Gradient clipping
                if self.config.gradient_clipping:
                    self.scaler.unscale_(self.optimizer)
                    torch.nn.utils.clip_grad_norm_(
                        self.model.parameters(),
                        self.config.max_grad_norm
                    )

                self.scaler.step(self.optimizer)
                self.scaler.update()
            else:
                loss.backward()

                if self.config.gradient_clipping:
                    torch.nn.utils.clip_grad_norm_(
                        self.model.parameters(),
                        self.config.max_grad_norm
                    )

                self.optimizer.step()

            # Update metrics
            self.metrics_tracker['train'].update(logits.detach(), labels, loss.item())

            # Update progress bar
            pbar.set_postfix({'loss': f"{loss.item():.4f}"})

        return self.metrics_tracker['train'].compute()

    @torch.no_grad()
    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """Validate the model."""
        self.model.eval()
        self.metrics_tracker['val'].reset()

        pbar = tqdm(val_loader, desc=f"Epoch {self.current_epoch + 1} [Val]")

        for features, labels, _ in pbar:
            features = features.to(self.device)
            labels = labels.to(self.device)

            logits, aux_loss = self.model(
                features,
                observe_ratio=self.config.observe_ratio,
                return_aux_loss=True,
                labels=labels
            )
            loss = self._compute_loss(logits, labels, aux_loss)

            self.metrics_tracker['val'].update(logits, labels, loss.item())

        return self.metrics_tracker['val'].compute()

    def log_metrics(self, metrics: Dict[str, Dict[str, float]]):
        """Log metrics to TensorBoard and CSV."""
        epoch = self.current_epoch

        # TensorBoard logging
        if self.writer is not None:
            for split, split_metrics in metrics.items():
                for key, value in split_metrics.items():
                    if isinstance(value, (int, float)):
                        self.writer.add_scalar(f'{split}/{key}', value, epoch)

            # Log learning rate
            lr = self.optimizer.param_groups[0]['lr']
            self.writer.add_scalar('train/lr', lr, epoch)

        # Console logging
        train_metrics = metrics['train']
        val_metrics = metrics['val']

        logger.info(f"\nEpoch {epoch + 1} Results:")
        logger.info(f"  Train - Loss: {train_metrics['loss']:.4f}, "
                   f"Acc: {train_metrics['accuracy']:.4f}, "
                   f"F1: {train_metrics['f1_macro']:.4f}")
        logger.info(f"  Val   - Loss: {val_metrics['loss']:.4f}, "
                   f"Acc: {val_metrics['accuracy']:.4f}, "
                   f"F1: {val_metrics['f1_macro']:.4f}")

        # Per-class metrics
        logger.info("  Per-class F1:")
        for name in CLASS_NAMES:
            logger.info(f"    {name}: {val_metrics.get(f'{name}_f1', 0):.4f}")

    def train(self, train_loader: DataLoader, val_loader: DataLoader):
        """Complete training loop."""
        logger.info("=" * 60)
        logger.info("Starting Training")
        logger.info("=" * 60)
        logger.info(f"Device: {self.device}")
        logger.info(f"Mixed Precision: {self.use_amp}")
        logger.info(f"Epochs: {self.config.num_epochs}")
        logger.info(f"Batch Size: {self.config.batch_size}")
        logger.info(f"Learning Rate: {self.config.learning_rate}")

        # Setup CSV logger
        self.csv_logger.setup([
            'epoch', 'train_loss', 'train_acc', 'train_f1_macro',
            'val_loss', 'val_acc', 'val_f1_macro',
            'safe_f1', 'pre_violence_f1', 'violence_f1',
            'lr'
        ])

        for epoch in range(self.config.num_epochs):
            self.current_epoch = epoch

            # Train
            train_metrics = self.train_epoch(train_loader)

            # Validate
            val_metrics = self.validate(val_loader)

            # Combine metrics
            metrics = {'train': train_metrics, 'val': val_metrics}

            # Log
            self.log_metrics(metrics)

            # Update scheduler
            if self.scheduler is not None:
                self.scheduler.step()

            # CSV logging
            self.csv_logger.log({
                'epoch': epoch + 1,
                'train_loss': train_metrics['loss'],
                'train_acc': train_metrics['accuracy'],
                'train_f1_macro': train_metrics['f1_macro'],
                'val_loss': val_metrics['loss'],
                'val_acc': val_metrics['accuracy'],
                'val_f1_macro': val_metrics['f1_macro'],
                'safe_f1': val_metrics.get('safe_f1', 0),
                'pre_violence_f1': val_metrics.get('pre_violence_f1', 0),
                'violence_f1': val_metrics.get('violence_f1', 0),
                'lr': self.optimizer.param_groups[0]['lr']
            })

            # Check for best model
            # monitor_metric may have a 'val_' prefix (e.g. 'val_f1_macro') but
            # MetricsTracker.compute() returns bare keys (e.g. 'f1_macro').
            # Strip the prefix so the lookup always works regardless of convention.
            _metric_key = self.config.monitor_metric
            _metric_key_bare = _metric_key.removeprefix('val_').removeprefix('train_')
            if _metric_key in val_metrics:
                current_metric = val_metrics[_metric_key]
            elif _metric_key_bare in val_metrics:
                current_metric = val_metrics[_metric_key_bare]
            else:
                logger.warning(
                    f"monitor_metric '{_metric_key}' not found in val_metrics "
                    f"(available: {list(val_metrics.keys())}). Falling back to 'loss'."
                )
                current_metric = val_metrics['loss']

            is_best = (self.config.mode == 'max' and current_metric > self.best_metric) or \
                      (self.config.mode == 'min' and current_metric < self.best_metric)

            if is_best:
                self.best_metric = current_metric

            # Save checkpoint
            self.checkpoint_manager.save_checkpoint(
                epoch=epoch,
                model=self.model,
                optimizer=self.optimizer,
                scheduler=self.scheduler,
                metrics=val_metrics,
                is_best=is_best
            )

            # Early stopping
            if self.early_stopping is not None:
                if self.early_stopping(current_metric):
                    logger.info(f"Early stopping triggered at epoch {epoch + 1}")
                    break

        logger.info("=" * 60)
        logger.info("Training Complete!")
        logger.info(f"Best {self.config.monitor_metric}: {self.best_metric:.4f}")
        logger.info("=" * 60)

        self.csv_logger.close()
        if self.writer is not None:
            self.writer.close()

    def evaluate(self, test_loader: DataLoader) -> Dict[str, float]:
        """Evaluate on test set."""
        logger.info("Evaluating on test set...")
        metrics = self.validate(test_loader)

        logger.info("\nTest Set Results:")
        logger.info(f"  Loss: {metrics['loss']:.4f}")
        logger.info(f"  Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"  F1 (macro): {metrics['f1_macro']:.4f}")
        logger.info(f"  F1 (weighted): {metrics['f1_weighted']:.4f}")

        logger.info("\nPer-class Results:")
        for name in CLASS_NAMES:
            p = metrics.get(f'{name}_precision', 0)
            r = metrics.get(f'{name}_recall', 0)
            f1 = metrics.get(f'{name}_f1', 0)
            s = metrics.get(f'{name}_support', 0)
            logger.info(f"  {name}: P={p:.4f}, R={r:.4f}, F1={f1:.4f}, Support={s}")

        logger.info(f"\nConfusion Matrix:\n{np.array(metrics['confusion_matrix'])}")

        return metrics


def create_dataloaders_from_config(
    config: TrainingConfig,
    train_path: str,
    val_path: str,
    test_path: Optional[str] = None
) -> Tuple[DataLoader, DataLoader, Optional[DataLoader]]:
    """Create DataLoaders from saved datasets."""

    # Load data
    train_features, train_labels, train_ids = load_dataset(train_path)
    val_features, val_labels, val_ids = load_dataset(val_path)

    # Create datasets
    train_dataset = SafeVisionDataset(train_features, train_labels, train_ids)
    val_dataset = SafeVisionDataset(val_features, val_labels, val_ids)

    # Create samplers
    if config.use_weighted_sampling:
        train_sampler = WeightedSequenceSampler(train_labels)
    else:
        train_sampler = None

    # Create dataloaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=config.batch_size,
        sampler=train_sampler,
        shuffle=(train_sampler is None),
        num_workers=config.num_workers,
        pin_memory=True,
        drop_last=True
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=config.batch_size,
        shuffle=False,
        num_workers=config.num_workers,
        pin_memory=True
    )

    test_loader = None
    if test_path:
        test_features, test_labels, test_ids = load_dataset(test_path)
        test_dataset = SafeVisionDataset(test_features, test_labels, test_ids)
        test_loader = DataLoader(
            test_dataset,
            batch_size=config.batch_size,
            shuffle=False,
            num_workers=config.num_workers,
            pin_memory=True
        )

    return train_loader, val_loader, test_loader


def main():
    parser = argparse.ArgumentParser(description='Train SafeVision LSTM Model')

    # Data arguments
    parser.add_argument('--train_data', type=str, help='Path to train.npz')
    parser.add_argument('--val_data', type=str, help='Path to val.npz')
    parser.add_argument('--test_data', type=str, help='Path to test.npz (optional)')

    # Model arguments
    parser.add_argument('--model_variant', type=str, default='full', choices=['full', 'lite'])
    parser.add_argument('--hidden_size', type=int, default=128)
    parser.add_argument('--num_lstm_layers', type=int, default=2)
    parser.add_argument('--num_heads', type=int, default=8)

    # Training arguments
    parser.add_argument('--batch_size', type=int, default=32)
    parser.add_argument('--num_epochs', type=int, default=100)
    parser.add_argument('--learning_rate', type=float, default=1e-3)
    parser.add_argument('--weight_decay', type=float, default=1e-4)
    parser.add_argument('--max_grad_norm', type=float, default=1.0)

    # Loss arguments
    parser.add_argument('--loss_type', type=str, default='focal',
                       choices=['ce', 'focal', 'label_smoothing'])
    parser.add_argument('--focal_gamma', type=float, default=2.0)
    parser.add_argument('--label_smoothing', type=float, default=0.1)
    parser.add_argument('--aux_loss_weight', type=float, default=0.25)
    parser.add_argument('--class_weights', type=float, nargs=3, default=[3.96, 3.29, 1.0],
                       help='Class weights for loss (safe pre_violence violence). Default tuned for dataset balance.')

    # LR scheduling
    parser.add_argument('--warmup_epochs', type=int, default=5)
    parser.add_argument('--lr_scheduler', type=str, default='cosine')

    # Early stopping
    parser.add_argument('--early_stopping', action='store_true', default=True)
    parser.add_argument('--no_early_stopping', dest='early_stopping', action='store_false')
    parser.add_argument('--patience', type=int, default=15)
    parser.add_argument('--monitor_metric', type=str, default='val_f1_macro')

    # Checkpointing
    parser.add_argument('--output_dir', type=str, default='./runs/exp001')
    parser.add_argument('--save_period', type=int, default=10)
    parser.add_argument('--resume', type=str, default=None,
                       help='Resume from checkpoint')

    # Training features
    parser.add_argument('--no_mixed_precision', action='store_true')
    parser.add_argument('--staged_training', action='store_true',
                       help='Freeze encoder for first N epochs')
    parser.add_argument('--freeze_epochs', type=int, default=10)

    # Data loading
    parser.add_argument('--num_workers', type=int, default=4)
    parser.add_argument('--no_weighted_sampling', action='store_true')

    # Misc
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--device', type=str, default='auto')

    args = parser.parse_args()

    # Set random seed
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    # Create config
    config = TrainingConfig(
        model_variant=args.model_variant,
        hidden_size=args.hidden_size,
        num_lstm_layers=args.num_lstm_layers,
        num_heads=args.num_heads,
        batch_size=args.batch_size,
        num_epochs=args.num_epochs,
        learning_rate=args.learning_rate,
        weight_decay=args.weight_decay,
        max_grad_norm=args.max_grad_norm,
        loss_type=args.loss_type,
        focal_gamma=args.focal_gamma,
        label_smoothing=args.label_smoothing,
        class_weights=args.class_weights,
        aux_loss_weight=args.aux_loss_weight,
        warmup_epochs=args.warmup_epochs,
        lr_scheduler=args.lr_scheduler,
        early_stopping=args.early_stopping,
        patience=args.patience,
        monitor_metric=args.monitor_metric,
        save_period=args.save_period,
        checkpoint_dir=os.path.join(args.output_dir, 'checkpoints'),
        log_dir=os.path.join(args.output_dir, 'logs'),
        mixed_precision=not args.no_mixed_precision,
        staged_training=args.staged_training,
        freeze_epochs=args.freeze_epochs,
        num_workers=args.num_workers,
        use_weighted_sampling=not args.no_weighted_sampling,
        device=args.device
    )

    # Check data paths
    if not args.train_data or not args.val_data:
        parser.error("--train_data and --val_data are required")

    # Create dataloaders
    train_loader, val_loader, test_loader = create_dataloaders_from_config(
        config, args.train_data, args.val_data, args.test_data
    )

    # Create trainer
    trainer = Trainer(config)

    # Resume from checkpoint if specified
    start_epoch = 0
    if args.resume:
        checkpoint = trainer.checkpoint_manager.load_checkpoint(
            args.resume,
            trainer.model,
            trainer.optimizer,
            trainer.scheduler
        )
        start_epoch = checkpoint.get('epoch', 0) + 1
        trainer.current_epoch = start_epoch

    # Train
    trainer.train(train_loader, val_loader)

    # Evaluate on test set if provided
    if test_loader is not None:
        # Load best model
        best_path = os.path.join(config.checkpoint_dir, 'best.pt')
        if os.path.exists(best_path):
            trainer.checkpoint_manager.load_checkpoint(best_path, trainer.model)
        trainer.evaluate(test_loader)


if __name__ == '__main__':
    main()
