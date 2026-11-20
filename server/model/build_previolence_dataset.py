"""
Pre-Violence Dataset Builder
Extracts pre-violence segments from violent videos to build training dataset.

NEW: Added mining step that uses a trained model to find pre-violence segments
in unlabeled/weakly-labeled violence videos, creating 3-class datasets
(safe / pre_violence / violence) for SafeVisionLSTMv15 training.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from tqdm import tqdm

import numpy as np
import cv2
import torch
import torch.nn.functional as F
import pandas as pd

# Import from local lstm_model (not lstm_model_v15 which doesn't exist)
import lstm_model as lm
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


def load_model(checkpoint_path: str, device: str = 'auto'):
    if device == 'auto':
        device = 'cuda' if torch.cuda.is_available() else 'cpu'

    checkpoint = torch.load(checkpoint_path, map_location=device)

    if isinstance(checkpoint, dict):
        state_dict = checkpoint.get('model_state_dict') or checkpoint.get('state_dict') or checkpoint.get('model') or checkpoint
    else:
        state_dict = checkpoint

    # Use SafeVisionLSTMv15 from lstm_model (the actual class name)
    model = lm.SafeVisionLSTMv15(
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

        sequence = lm.build_sequence_features(window, observe_ratio=observe_ratio)
        sequence = torch.tensor(sequence, dtype=torch.float32).unsqueeze(0).to(device)

        with torch.no_grad():
            output = model(sequence)
            probs = F.softmax(output, dim=1)
            predictions.append({
                'start_idx': start_idx,
                'prob_safe': probs[0, 0].item(),
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


def mine_three_class_segments(
    model,
    video_path: str,
    config: Config,
    device: str,
    target_fps: int = 10,
) -> Dict[str, List[Dict]]:
    """
    Mine safe / pre_violence / violence segments from a single video using model predictions.

    Returns dict with keys 'safe', 'pre_violence', 'violence' containing segment dicts.
    """
    features = extract_features_from_video(video_path, target_fps)
    if len(features) < config.window_size:
        return {'safe': [], 'pre_violence': [], 'violence': []}

    predictions = predict_sliding_window(model, features, config, device)
    if not predictions:
        return {'safe': [], 'pre_violence': [], 'violence': []}

    # Smooth all three class probabilities
    window = 5
    smooth = {cls: [] for cls in ['safe', 'pre_violence', 'violence']}
    for cls in smooth:
        scores = [p[f'prob_{cls}'] for p in predictions]
        for i in range(len(scores)):
            start = max(0, i - window // 2)
            end = min(len(scores), i + window // 2 + 1)
            smooth[cls].append(np.mean(scores[start:end]))

    # Find segments for each class using thresholding
    segments = {'safe': [], 'pre_violence': [], 'violence': []}
    min_len = config.min_segment_length

    # Pre-violence: high pre_violence prob
    thresh_pv = config.pre_violence_threshold
    in_seg = False
    seg_start = 0
    for i, score in enumerate(smooth['pre_violence']):
        if score >= thresh_pv:
            if not in_seg:
                in_seg = True
                seg_start = i
        else:
            if in_seg:
                length = i - seg_start
                if length >= min_len:
                    peak = seg_start + np.argmax(smooth['pre_violence'][seg_start:i])
                    segments['pre_violence'].append({
                        'start_idx': seg_start * config.stride,
                        'end_idx': (i - 1) * config.stride + config.window_size,
                        'peak_idx': peak * config.stride,
                        'confidence': max(smooth['pre_violence'][seg_start:i]),
                        'avg_score': np.mean(smooth['pre_violence'][seg_start:i]),
                    })
                in_seg = False
    if in_seg:
        length = len(smooth['pre_violence']) - seg_start
        if length >= min_len:
            peak = seg_start + np.argmax(smooth['pre_violence'][seg_start:])
            segments['pre_violence'].append({
                'start_idx': seg_start * config.stride,
                'end_idx': (len(smooth['pre_violence']) - 1) * config.stride + config.window_size,
                'peak_idx': peak * config.stride,
                'confidence': max(smooth['pre_violence'][seg_start:]),
                'avg_score': np.mean(smooth['pre_violence'][seg_start:]),
            })

    # Violence: high violence prob
    thresh_vio = 0.6
    in_seg = False
    seg_start = 0
    for i, score in enumerate(smooth['violence']):
        if score >= thresh_vio:
            if not in_seg:
                in_seg = True
                seg_start = i
        else:
            if in_seg:
                length = i - seg_start
                if length >= min_len:
                    peak = seg_start + np.argmax(smooth['violence'][seg_start:i])
                    segments['violence'].append({
                        'start_idx': seg_start * config.stride,
                        'end_idx': (i - 1) * config.stride + config.window_size,
                        'peak_idx': peak * config.stride,
                        'confidence': max(smooth['violence'][seg_start:i]),
                        'avg_score': np.mean(smooth['violence'][seg_start:i]),
                    })
                in_seg = False
    if in_seg:
        length = len(smooth['violence']) - seg_start
        if length >= min_len:
            peak = seg_start + np.argmax(smooth['violence'][seg_start:])
            segments['violence'].append({
                'start_idx': seg_start * config.stride,
                'end_idx': (len(smooth['violence']) - 1) * config.stride + config.window_size,
                'peak_idx': peak * config.stride,
                'confidence': max(smooth['violence'][seg_start:]),
                'avg_score': np.mean(smooth['violence'][seg_start:]),
            })

    # Safe: high safe prob, away from violence/pre_violence segments
    # Find frames not covered by pre_violence or violence segments
    n_frames = len(features)
    covered = np.zeros(n_frames, dtype=bool)
    for cls in ['pre_violence', 'violence']:
        for seg in segments[cls]:
            covered[seg['start_idx']:seg['end_idx']] = True

    # Safe segments: continuous regions where safe prob > 0.7 and not covered
    thresh_safe = 0.7
    in_seg = False
    seg_start = 0
    for i in range(n_frames):
        # Check if frame i is in a window center
        pred_idx = i // config.stride
        if pred_idx >= len(smooth['safe']):
            pred_idx = len(smooth['safe']) - 1
        score = smooth['safe'][pred_idx]
        is_covered = covered[i]

        if score >= thresh_safe and not is_covered:
            if not in_seg:
                in_seg = True
                seg_start = i
        else:
            if in_seg:
                length = i - seg_start
                if length >= min_len:
                    segments['safe'].append({
                        'start_idx': seg_start,
                        'end_idx': i - 1,
                        'peak_idx': seg_start + length // 2,
                        'confidence': 1.0,  # Not directly applicable
                        'avg_score': np.mean(smooth['safe'][seg_start//config.stride:pred_idx]),
                    })
                in_seg = False
    if in_seg:
        length = n_frames - seg_start
        if length >= min_len:
            segments['safe'].append({
                'start_idx': seg_start,
                'end_idx': n_frames - 1,
                'peak_idx': seg_start + length // 2,
                'confidence': 1.0,
                'avg_score': np.mean(smooth['safe'][seg_start//config.stride:]),
            })

    return segments


def process_dataset_mining(
    dataset_path: str,
    model,
    config: Config,
    device: str,
    output_dir: str,
    split: str = 'violence',
    extensions: tuple = ('.mp4', '.avi', '.mov', '.mkv'),
    target_fps: int = 10,
    max_samples_per_class: int = 500,
) -> Dict:
    """
    Mine 3-class segments from violence videos and create manifest for training.
    """
    dataset_path = Path(dataset_path)
    violence_dir = dataset_path / split
    if not violence_dir.exists():
        violence_dir = dataset_path / 'videos' / split

    video_files = []
    for ext in extensions:
        video_files.extend(list(violence_dir.glob(f'*{ext}')))
        video_files.extend(list(violence_dir.glob(f'*{ext.upper()}')))

    if not video_files:
        print(f"[!] No videos found in {violence_dir}")
        return {'clips': [], 'videos_processed': 0, 'manifest_csv': None}

    print(f"[+] Mining 3-class segments from {len(video_files)} videos in {violence_dir}")

    clips_dir = Path(output_dir) / 'mined_clips'
    clips_dir.mkdir(parents=True, exist_ok=True)
    features_dir = Path(output_dir) / 'features'
    features_dir.mkdir(parents=True, exist_ok=True)

    manifest_rows = []
    videos_processed = 0
    class_counts = {'safe': 0, 'pre_violence': 0, 'violence': 0}

    for video_path in tqdm(video_files, desc=f"Mining {split}"):
        try:
            segments = mine_three_class_segments(model, str(video_path), config, device, target_fps)

            if not any(segments.values()):
                continue

            video_name = video_path.stem

            for cls_name in ['safe', 'pre_violence', 'violence']:
                for i, seg in enumerate(segments[cls_name]):
                    if class_counts[cls_name] >= max_samples_per_class:
                        continue

                    # Extract features for this segment
                    cap = cv2.VideoCapture(str(video_path))
                    fps = cap.get(cv2.CAP_PROP_FPS) or 30.0
                    start_frame = int(seg['start_idx'] * (fps / target_fps))
                    end_frame = int(seg['end_idx'] * (fps / target_fps))
                    cap.release()

                    # Extract and save features directly (no need to save video clips)
                    cap = cv2.VideoCapture(str(video_path))
                    cap.set(cv2.CAP_PROP_POS_FRAMES, start_frame)

                    raw_sequence = []
                    prev_kp, prev_vel, prev_gray = None, None, None
                    frame_interval = max(1, int(fps / target_fps))
                    frames_needed = config.window_size
                    curr_frame = 0

                    while cap.isOpened() and len(raw_sequence) < frames_needed:
                        ret, frame = cap.read()
                        if not ret:
                            break
                        if curr_frame % frame_interval == 0:
                            feat_352, prev_kp, prev_vel, prev_gray, _ = lm.extract_features(
                                frame, prev_kp, prev_vel, prev_gray
                            )
                            raw_sequence.append(feat_352)
                        curr_frame += 1
                    cap.release()

                    # Pad if needed
                    while len(raw_sequence) < frames_needed:
                        raw_sequence.append(np.zeros(352, dtype=np.float32))

                    features_440 = lm.build_sequence_features(raw_sequence[:frames_needed])

                    # Save features
                    save_name = f"{video_name}_{cls_name}_{i:03d}.npy"
                    save_path = features_dir / save_name
                    np.save(save_path, features_440)

                    manifest_rows.append({
                        'feature_path': str(save_path.relative_to(Path(output_dir))),
                        'label': cls_name,
                        'source_video': str(video_path),
                        'start_frame': seg['start_idx'],
                        'end_frame': seg['end_idx'],
                        'confidence': seg.get('confidence', 1.0),
                    })
                    class_counts[cls_name] += 1

            videos_processed += 1

        except Exception as e:
            print(f"[!] Error: {video_path.name}: {e}")

    # Save manifest
    manifest_df = pd.DataFrame(manifest_rows)
    manifest_path = Path(output_dir) / 'manifest_with_features.csv'
    manifest_df.to_csv(manifest_path, index=False)

    print(f"\n[+] Done: {videos_processed} videos processed")
    print(f"    Class distribution: {class_counts}")
    print(f"    Total samples: {len(manifest_rows)}")
    print(f"[+] Manifest: {manifest_path}")

    return {
        'clips': manifest_rows,
        'videos_processed': videos_processed,
        'class_counts': class_counts,
        'manifest_csv': str(manifest_path),
        'output_dir': str(clips_dir),
    }


def process_dataset(
    dataset_path: str,
    model,
    config: Config,
    device: str,
    output_dir: str,
    split: str = 'violence',
    extensions: tuple = ('.mp4', '.avi', '.mov', '.mkv'),
) -> Dict:
    """Original method: extract pre_violence clips as video files."""
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
    parser = argparse.ArgumentParser(
        description='Extract pre-violence clips OR mine 3-class dataset for training'
    )
    parser.add_argument('--dataset', '-d', required=True,
                        help='Path to dataset (RLVS, RWF-2000, etc.)')
    parser.add_argument('--model', '-m', required=True,
                        help='Path to model checkpoint')
    parser.add_argument('--output', '-o', required=True,
                        help='Output directory')
    parser.add_argument('--threshold', '-t', type=float, default=0.50,
                        help='Pre-violence threshold')
    parser.add_argument('--split', choices=['violence', 'fight', 'all'],
                        default='violence', help='Dataset split')
    parser.add_argument('--mode', choices=['clips', 'mine'], default='mine',
                        help='clips: extract video clips (old); mine: create 3-class feature manifest (new)')
    parser.add_argument('--target-fps', type=int, default=10, help='Target FPS for feature extraction')
    parser.add_argument('--max-samples', type=int, default=500,
                        help='Max samples per class (mine mode)')

    args = parser.parse_args()

    config = Config()
    config.pre_violence_threshold = args.threshold

    model, device = load_model(args.model)

    split = args.split if args.split != 'all' else 'violence'

    if args.mode == 'mine':
        result = process_dataset_mining(
            args.dataset,
            model,
            config,
            device,
            args.output,
            split=split,
            target_fps=args.target_fps,
            max_samples_per_class=args.max_samples,
        )
        print(f"\n[+] Mining complete!")
        print(f"    Manifest: {result['manifest_csv']}")
        print(f"    Ready for training: python train_safevision.py --manifest {result['manifest_csv']}")
    else:
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