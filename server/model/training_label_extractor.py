"""
training_label_extractor.py — Pre-Violence Training Label Extractor

This module extracts pre-violence labels from RLVS and RWF-200 datasets
for training the SafeVision v15 model.

Strategy:
    - RWF-200: Fight videos are split temporally
        * First portion -> pre_violence (label=1)
        * Last portion -> violence (label=2)
    - RLVS: Violence videos can use the same temporal split approach

Usage:
    python training_label_extractor.py \
        --dataset RWF200 \
        --data_dir /path/to/RWF-200 \
        --output ./datasets/rwf200_labeled \
        --pre_violence_ratio 0.4

    # Then train with the extracted labels
    python trainer.py --train_data ./datasets/rwf200_labeled/train.npz \
                      --val_data ./datasets/rwf200_labeled/val.npz
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import List, Tuple, Dict, Optional, Any
from dataclasses import dataclass
from collections import defaultdict
import numpy as np
import cv2
from tqdm import tqdm
from sklearn.model_selection import train_test_split

# Import local modules
import vision as vs
from lstm_model_v15 import build_sequence_features, extract_features

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)


# ── Data Classes ──────────────────────────────────────────────────────────────

@dataclass
class LabeledSegment:
    """A labeled video segment for training."""
    video_path: str
    start_frame: int
    end_frame: int
    label: int  # 0=safe, 1=pre_violence, 2=violence
    label_name: str
    features: Optional[np.ndarray] = None


@dataclass
class ExtractionConfig:
    """Configuration for label extraction."""
    # Temporal splitting
    pre_violence_ratio: float = 0.4  # First 40% of fight = pre-violence
    violence_ratio: float = 0.6      # Last 60% of fight = violence
    min_segment_frames: int = 15     # Minimum frames per segment
    fps_target: int = 10             # Target FPS for processing

    # Feature extraction
    sequence_length: int = 30        # Frames per training sample
    stride: int = 5                  # Stride for sliding window
    window_size: int = 5             # Temporal context window

    # Splits
    val_split: float = 0.15
    test_split: float = 0.15
    seed: int = 42


# ── Label Extraction Logic ────────────────────────────────────────────────────

class TrainingLabelExtractor:
    """
    Extract training labels from violence detection datasets.

    The key insight: In a fight video, the escalation phase (pre-violence)
    happens before the actual violence. We split videos temporally:

    [---- pre-violence ----][---- violence ----]
    |                       |                   |
    start                transition           end
    """

    def __init__(self, config: ExtractionConfig):
        self.config = config

    def _find_dir(self, root: Path, names: List[str]) -> Optional[Path]:
        """Find a directory matching any of the given names."""
        for name in names:
            d = root / name
            if d.exists() and d.is_dir():
                return d
        return None

    def extract_from_rwf200(
        self,
        data_dir: str,
        max_videos: Optional[int] = None
    ) -> List[LabeledSegment]:
        """
        Extract labeled segments from RWF-200 dataset.
        """
        data_dir = Path(data_dir)
        fight_dir = self._find_dir(data_dir, ["fight", "violence"])
        nonfight_dir = self._find_dir(data_dir, ["nonfight", "nonviolence", "safe"])

        if not fight_dir and not nonfight_dir:
            logger.error(f"Could not find fight/violence or nonfight/safe folders in {data_dir}")
            return []

        all_segments = []

        # Process fight videos
        if fight_dir:
            logger.info(f"Processing fight videos from {fight_dir}...")
            fight_videos = list(fight_dir.glob("*.avi")) + list(fight_dir.glob("*.mp4"))
            for video_path in tqdm(fight_videos[:max_videos], desc="Fight videos"):
                segments = self._process_fight_video(str(video_path), split_temporal=True)
                all_segments.extend(segments)

        # Process non-fight videos (safe)
        if nonfight_dir:
            logger.info(f"Processing non-fight videos from {nonfight_dir}...")
            nonfight_videos = list(nonfight_dir.glob("*.avi")) + list(nonfight_dir.glob("*.mp4"))
            for video_path in tqdm(nonfight_videos[:max_videos], desc="Non-fight videos"):
                segments = self._process_safe_video(str(video_path))
                all_segments.extend(segments)

        return all_segments

    def extract_from_rlvs(
        self,
        data_dir: str,
        max_videos: Optional[int] = None
    ) -> List[LabeledSegment]:
        """
        Extract labeled segments from RLVS dataset.
        """
        data_dir = Path(data_dir)
        violence_dir = self._find_dir(data_dir, ["violence", "fight"])
        nonviolence_dir = self._find_dir(data_dir, ["nonviolence", "nonfight", "safe"])

        if not violence_dir and not nonviolence_dir:
            logger.error(f"Could not find violence/fight or nonviolence/safe folders in {data_dir}")
            return []

        all_segments = []

        # Process violence videos
        if violence_dir:
            logger.info(f"Processing violence videos from {violence_dir}...")
            violence_videos = list(violence_dir.glob("*.avi")) + list(violence_dir.glob("*.mp4"))
            for video_path in tqdm(violence_videos[:max_videos], desc="Violence videos"):
                segments = self._process_fight_video(str(video_path), split_temporal=True, dataset="RLVS")
                all_segments.extend(segments)

        # Process non-violence videos (safe)
        if nonviolence_dir:
            logger.info(f"Processing non-violence videos from {nonviolence_dir}...")
            nonviolence_videos = list(nonviolence_dir.glob("*.avi")) + list(nonviolence_dir.glob("*.mp4"))
            for video_path in tqdm(nonviolence_videos[:max_videos], desc="Non-violence videos"):
                segments = self._process_safe_video(str(video_path))
                all_segments.extend(segments)

        return all_segments

    def run_pipeline(self, segments: List[LabeledSegment], output_dir: str):
        """Run the feature extraction and splitting pipeline on a list of segments."""
        if not segments:
            logger.error("No video segments to process.")
            sys.exit(1)
        
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        return self._create_splits(segments, output_dir)

    def _process_fight_video(
        self,
        video_path: str,
        split_temporal: bool = True,
        dataset: str = "RWF200"
    ) -> List[LabeledSegment]:
        """Process a fight/violence video into pre-violence and violence segments."""
        cap = cv2.VideoCapture(video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()

        if total_frames < self.config.min_segment_frames * 2:
            logger.warning(f"Skipping {video_path}: too short ({total_frames} frames)")
            return []

        segments = []
        video_id = Path(video_path).stem

        if split_temporal:
            # Split point
            split_frame = int(total_frames * self.config.pre_violence_ratio)
            split_frame = max(split_frame, self.config.min_segment_frames)
            split_frame = min(split_frame, total_frames - self.config.min_segment_frames)

            # Pre-violence segment
            segments.append(LabeledSegment(
                video_path=video_path,
                start_frame=0,
                end_frame=split_frame,
                label=1,
                label_name="pre_violence"
            ))

            # Violence segment
            segments.append(LabeledSegment(
                video_path=video_path,
                start_frame=split_frame,
                end_frame=total_frames,
                label=2,
                label_name="violence"
            ))

            logger.debug(f"{video_id}: {split_frame} frames pre-violence, "
                        f"{total_frames - split_frame} frames violence")
        else:
            # Entire video is violence
            segments.append(LabeledSegment(
                video_path=video_path,
                start_frame=0,
                end_frame=total_frames,
                label=2,
                label_name="violence"
            ))

        return segments

    def _process_safe_video(self, video_path: str) -> List[LabeledSegment]:
        """Process a safe/non-violence video."""
        cap = cv2.VideoCapture(video_path)
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        cap.release()

        if total_frames < self.config.min_segment_frames:
            logger.warning(f"Skipping {video_path}: too short")
            return []

        return [LabeledSegment(
            video_path=video_path,
            start_frame=0,
            end_frame=total_frames,
            label=0,
            label_name="safe"
        )]

    def _extract_features(self, segment: LabeledSegment) -> List[np.ndarray]:
        """Extract features from a labeled segment using sliding windows."""
        cap = cv2.VideoCapture(segment.video_path)
        if not cap.isOpened():
            return []

        # Extract 352-dim raw features for all frames in segment
        raw_features_list = []
        prev_kp = prev_vel = prev_gray = None

        cap.set(cv2.CAP_PROP_POS_FRAMES, segment.start_frame)
        for _ in range(segment.start_frame, segment.end_frame):
            ret, frame = cap.read()
            if not ret:
                break

            # extract_features returns: combined (352), keypoints, velocity, curr_gray, raw_flow
            feat, kp, vel, gray, _ = extract_features(
                frame, prev_kp, prev_vel, prev_gray
            )
            raw_features_list.append(feat)
            prev_kp, prev_vel, prev_gray = kp, vel, gray

        cap.release()

        if len(raw_features_list) < self.config.sequence_length:
            return []

        # Build 440-dim sequence features with sliding windows
        features = []
        for i in range(0, len(raw_features_list) - self.config.sequence_length + 1, self.config.stride):
            window_raw = raw_features_list[i:i + self.config.sequence_length]
            # build_sequence_features takes list of 352-dim features and returns (T, 440)
            seq_features = build_sequence_features(window_raw)
            features.append(seq_features)

        return features

    def _create_splits(
        self,
        segments: List[LabeledSegment],
        output_dir: Path
    ) -> Dict[str, Dict]:
        """Create train/val/test splits and save datasets."""
        # Group by label
        by_label = defaultdict(list)
        for seg in segments:
            by_label[seg.label].append(seg)

        # Extract features for all segments
        logger.info("Extracting features...")
        all_features = []
        all_labels = []
        all_video_ids = []

        for seg in tqdm(segments, desc="Extracting features"):
            features = self._extract_features(seg)
            for feat in features:
                all_features.append(feat)
                all_labels.append(seg.label)
                all_video_ids.append(Path(seg.video_path).stem)

        if not all_features:
            logger.error("No features were extracted from the video segments.")
            logger.error(f"Possible reasons: segments are shorter than sequence_length ({self.config.sequence_length} frames) or feature extraction failed.")
            sys.exit(1)

        logger.info(f"Total training samples: {len(all_features)}")

        # Create stratified splits
        train_idx, temp_idx, train_labels, temp_labels = train_test_split(
            range(len(all_features)),
            all_labels,
            test_size=(self.config.val_split + self.config.test_split),
            random_state=self.config.seed,
            stratify=all_labels
        )

        val_ratio = self.config.val_split / (self.config.val_split + self.config.test_split)
        val_idx, test_idx = train_test_split(
            temp_idx,
            test_size=(1 - val_ratio),
            random_state=self.config.seed,
            stratify=temp_labels
        )

        # Save splits
        results = {}
        for split_name, indices in [("train", train_idx), ("val", val_idx), ("test", test_idx)]:
            features = np.array([all_features[i] for i in indices])
            labels = np.array([all_labels[i] for i in indices])
            video_ids = np.array([all_video_ids[i] for i in indices])

            output_path = output_dir / f"{split_name}.npz"
            np.savez(output_path,
                    features=features,
                    labels=labels,
                    video_ids=video_ids)

            label_counts = defaultdict(int)
            for l in labels:
                label_counts[int(l)] += 1

            results[split_name] = {
                "num_samples": len(indices),
                "label_distribution": dict(label_counts)
            }

            logger.info(f"{split_name}: {len(indices)} samples - {dict(label_counts)}")

        # Save metadata
        metadata = {
            "config": {
                "pre_violence_ratio": self.config.pre_violence_ratio,
                "violence_ratio": self.config.violence_ratio,
                "sequence_length": self.config.sequence_length,
                "stride": self.config.stride,
            },
            "splits": results
        }

        with open(output_dir / "metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        return results

    def close(self):
        """Release resources."""
        pass


# ── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract training labels from datasets")

    parser.add_argument("--dataset", type=str, required=True,
                       choices=["RWF200", "RLVS", "BOTH"],
                       help="Dataset to process")
    parser.add_argument("--data_dir", type=str, 
                       help="Path to dataset root (if only processing one)")
    parser.add_argument("--rwf_dir", type=str,
                       help="Path to RWF-200 root (for BOTH)")
    parser.add_argument("--rlvs_dir", type=str,
                       help="Path to RLVS root (for BOTH)")
    parser.add_argument("--output", type=str, required=True,
                       help="Output directory for extracted datasets")
    parser.add_argument("--pre_violence_ratio", type=float, default=0.4,
                       help="Ratio of fight video that is pre-violence (default: 0.4)")
    parser.add_argument("--sequence_length", type=int, default=30,
                       help="Frames per training sample")
    parser.add_argument("--stride", type=int, default=5,
                       help="Sliding window stride")
    parser.add_argument("--max_videos", type=int, default=None,
                       help="Max videos per class (for testing)")
    parser.add_argument("--val_split", type=float, default=0.15)
    parser.add_argument("--test_split", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)

    args = parser.parse_args()

    config = ExtractionConfig(
        pre_violence_ratio=args.pre_violence_ratio,
        sequence_length=args.sequence_length,
        stride=args.stride,
        val_split=args.val_split,
        test_split=args.test_split,
        seed=args.seed
    )

    extractor = TrainingLabelExtractor(config)

    try:
        all_segments = []
        
        if args.dataset == "RWF200":
            if not args.data_dir:
                logger.error("--data_dir is required for RWF200 dataset")
                sys.exit(1)
            all_segments = extractor.extract_from_rwf200(args.data_dir, args.max_videos)
            
        elif args.dataset == "RLVS":
            if not args.data_dir:
                logger.error("--data_dir is required for RLVS dataset")
                sys.exit(1)
            all_segments = extractor.extract_from_rlvs(args.data_dir, args.max_videos)
            
        elif args.dataset == "BOTH":
            if not args.rwf_dir or not args.rlvs_dir:
                logger.error("--rwf_dir and --rlvs_dir are required for BOTH option")
                sys.exit(1)
            
            logger.info("Collecting segments from RWF-200...")
            all_segments.extend(extractor.extract_from_rwf200(args.rwf_dir, args.max_videos))
            
            logger.info("Collecting segments from RLVS...")
            all_segments.extend(extractor.extract_from_rlvs(args.rlvs_dir, args.max_videos))
            
        # Run the unified pipeline
        extractor.run_pipeline(all_segments, args.output)
        
    finally:
        extractor.close()

    logger.info("\n" + "=" * 60)
    logger.info("Extraction complete!")
    logger.info(f"Datasets saved to: {args.output}")
    logger.info("\nTo train the model:")
    logger.info(f"  python trainer.py --train_data {args.output}/train.npz \\")
    logger.info(f"                    --val_data {args.output}/val.npz \\")
    logger.info(f"                    --output_dir ./runs/previolence_exp")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
