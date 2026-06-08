"""
Pre-Violence Dataset Builder
Extracts pre-violence segments from violent videos to build training dataset.
"""

import os
import sys
import json
from pathlib import Path
from typing import List, Dict, Tuple
from tqdm import tqdm

import numpy as np
import cv2
import torch
import torch.nn.functional as F

from lstm_model_v15 import (
    SafeVisionLSTMv15,
    build_sequence_features,
    extract_features,
)
import vision as vs


class Config:
    window_size = 30
    stride = 5
    observe_ratio = 0.6
    
    pre_violence_threshold = 0.50
    min_segment_length = 15
    
    margin_before = 30
    margin_after = 10
    
    min_clip_duration = 0.5
    max_clip_duration = 5.0


def load_model(checkpoint_path: str, device: str = 'auto') -> SafeVisionLSTMv15:
    if device == 'auto':
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    checkpoint = torch.load(checkpoint_path, map_location=device)
    
    if isinstance(checkpoint, dict):
        state_dict = checkpoint.get('model_state_dict') or checkpoint.get('state_dict') or checkpoint.get('model') or checkpoint
    else:
        state_dict = checkpoint
    
    model = SafeVisionLSTMv15(
        input_size=440,
        hidden_size=128,
        num_classes=3,
        num_lstm_layers=2,
        use_tcn=True,
    )
    model.load_state_dict(state_dict, strict=False)
    model.to(device)
    model.eval()
    
    print(f"[+] Model loaded: {checkpoint_path}")
    return model, device


def extract_features_from_video(video_path: str, target_fps: int = 10) -> List[np.ndarray]:
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise ValueError(f"Cannot open: {video_path}")
    
    video_fps = cap.get(cv2.CAP_PROP_FPS)
    frame_interval = max(1, int(video_fps / target_fps))
    
    processor = vs.VideoProcessor()
    features = []
    frame_idx = 0
    
    while True:
        for _ in range(frame_interval):
            if not cap.grab():
                break
        ret, frame = cap.read()
        if not ret:
            break
        
        if frame_idx % frame_interval == 0:
            timestamp_ms = int(frame_idx * 1000 / video_fps)
            keypoints = processor.process(frame, timestamp_ms)
            features.append(keypoints)
        frame_idx += 1
    
    cap.release()
    return features


def predict_sliding_window(model, features: List[np.ndarray], config: Config, device: str):
    window_size = config.window_size
    stride = config.stride
    observe_ratio = config.observe_ratio
    
    predictions = []
    
    n_frames = len(features)
    if n_frames < window_size:
        return predictions
    
    for start_idx in range(0, n_frames - window_size + 1, stride):
        window = features[start_idx:start_idx + window_size]
        
        sequence = build_sequence_features(window, observe_ratio=observe_ratio)
        sequence = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0).to(device)
        
        with torch.no_grad():
            output = model(sequence)
            probs = F.softmax(output, dim=1)
            predictions.append({
                'start_idx': start_idx,
                'prob_pre_violence': probs[0, 1].item(),
                'prob_violence': probs[0, 2].item(),
                'probs': probs[0].cpu().numpy(),
            })
    
    return predictions


def find_pre_violence_segments(
    predictions: List[Dict],
    threshold: float,
    min_length: int,
) -> List[Dict]:
    if not predictions:
        return []
    
    scores = [p['prob_pre_violence'] for p in predictions]
    
    window = 5
    smoothed = []
    for i in range(len(scores)):
        start = max(0, i - window // 2)
        end = min(len(scores), i + window // 2 + 1)
        smoothed.append(np.mean(scores[start:end]))
    
    segments = []
    in_segment = False
    start_idx = 0
    
    for i, score in enumerate(smoothed):
        if score >= threshold:
            if not in_segment:
                in_segment = True
                start_idx = i
        else:
            if in_segment:
                length = i - start_idx
                if length >= min_length:
                    peak = start_idx + np.argmax(smoothed[start_idx:i])
                    segments.append({
                        'start_idx': start_idx * Config.stride,
                        'end_idx': (i - 1) * Config.stride + Config.window_size,
                        'peak_idx': peak * Config.stride,
                        'confidence': max(smoothed[start_idx:i]),
                        'avg_score': np.mean(smoothed[start_idx:i]),
                    })
                in_segment = False
    
    if in_segment:
        length = len(smoothed) - start_idx
        if length >= min_length:
            peak = start_idx + np.argmax(smoothed[start_idx:])
            segments.append({
                'start_idx': start_idx * Config.stride,
                'end_idx': (len(smoothed) - 1) * Config.stride + Config.window_size,
                'peak_idx': peak * Config.stride,
                'confidence': max(smoothed[start_idx:]),
                'avg_score': np.mean(smoothed[start_idx:]),
            })
    
    return segments


def extract_clip(
    video_path: str,
    start_frame: int,
    end_frame: int,
    output_path: str,
    margin_before: int = 30,
    margin_after: int = 10,
) -> bool:
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return False
    
    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    
    start_frame = max(0, start_frame - margin_before)
    end_frame = min(total_frames - 1, end_frame + margin_after)
    
    if (end_frame - start_frame) / fps > Config.max_clip_duration:
        end_frame = start_frame + int(fps * Config.max_clip_duration)
    
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    writer = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
    
    cap.set(cv2.CAP_PROP_POS_FRAMES, start_frame)
    for _ in range(start_frame, end_frame + 1):
        ret, frame = cap.read()
        if not ret:
            break
        writer.write(frame)
    
    cap.release()
    writer.release()
    
    return True


def process_dataset(
    dataset_path: str,
    model: SafeVisionLSTMv15,
    config: Config,
    device: str,
    output_dir: str,
    split: str = 'violence',
    extensions: tuple = ('.mp4', '.avi', '.mov', '.mkv'),
) -> Dict:
    violence_dir = Path(dataset_path) / split
    if not violence_dir.exists():
        violence_dir = Path(dataset_path) / 'videos' / split
    
    video_files = []
    for ext in extensions:
        video_files.extend(list(violence_dir.glob(f'*{ext}')))
        video_files.extend(list(violence_dir.glob(f'*{ext.upper()}')))
    
    if not video_files:
        print(f"[!] No videos found in {violence_dir}")
        return {'clips': [], 'videos_processed': 0}
    
    print(f"[+] Processing {len(video_files)} videos from {violence_dir}")
    
    clips_dir = Path(output_dir) / split
    clips_dir.mkdir(parents=True, exist_ok=True)
    
    manifest = []
    videos_processed = 0
    
    for video_path in tqdm(video_files, desc=f"Extracting {split}"):
        try:
            features = extract_features_from_video(str(video_path))
            if len(features) < config.window_size:
                continue
            
            predictions = predict_sliding_window(model, features, config, device)
            segments = find_pre_violence_segments(
                predictions,
                config.pre_violence_threshold,
                config.min_segment_length,
            )
            
            if not segments:
                continue
            
            video_name = video_path.stem
            
            for i, seg in enumerate(segments):
                clip_path = clips_dir / f"{video_name}_previolence_{i:03d}.mp4"
                
                success = extract_clip(
                    str(video_path),
                    seg['start_idx'],
                    seg['end_idx'],
                    str(clip_path),
                    config.margin_before,
                    config.margin_after,
                )
                
                if success:
                    manifest.append({
                        'source_video': str(video_path),
                        'clip_path': str(clip_path),
                        'start_frame': seg['start_idx'],
                        'end_frame': seg['end_idx'],
                        'confidence': seg['confidence'],
                        'label': 'pre_violence',
                    })
                    print(f"    [+] {clip_path.name}")
            
            videos_processed += 1
            
        except Exception as e:
            print(f"[!] Error: {video_path.name}: {e}")
    
    manifest_path = Path(output_dir) / f"{split}_manifest.json"
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    return {
        'clips': manifest,
        'videos_processed': videos_processed,
        'output_dir': str(clips_dir),
    }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Extract pre-violence clips for training dataset'
    )
    parser.add_argument('--dataset', '-d', required=True,
                        help='Path to dataset (RLVS or RWF-200)')
    parser.add_argument('--model', '-m', required=True,
                        help='Path to model checkpoint')
    parser.add_argument('--output', '-o', required=True,
                        help='Output directory')
    parser.add_argument('--threshold', '-t', type=float, default=0.50,
                        help='Pre-violence threshold')
    parser.add_argument('--split', choices=['violence', 'fight', 'all'],
                        default='violence', help='Dataset split')
    
    args = parser.parse_args()
    
    config = Config()
    config.pre_violence_threshold = args.threshold
    
    model, device = load_model(args.model)
    
    split = args.split if args.split != 'all' else 'violence'
    
    result = process_dataset(
        args.dataset,
        model,
        config,
        device,
        args.output,
        split=split,
    )
    
    print(f"\n[+] Done: {result['videos_processed']} videos, "
          f"{len(result['clips'])} clips extracted")
    print(f"[+] Output: {result['output_dir']}")


if __name__ == "__main__":
    main()