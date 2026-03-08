import os
import numpy as np
import cv2
import vision
from tqdm import tqdm

# --- Configuration ---
SEQUENCE_LENGTH = 30
STEP = 5
OUTPUT_DIR = "../processed_data_rwf_2000"
DATASET_DIR = r"C:\Users\meir\Documents\datasets\RWF-2000"
CHUNK_SIZE = 2000

# RWF-2000 pre-split folder structure:
#   DATASET_DIR/
#     train/
#       Fight/
#       NonFight/
#     val/
#       Fight/
#       NonFight/
SPLITS = {
    "train": ("train/Fight", "train/NonFight"),
    "val":   ("val/Fight",   "val/NonFight"),
}

# Pose / confidence settings
CONFIDENCE_THRESHOLD = 0.3
MAX_MISSING_GAP = 10

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_keypoints(keypoints: np.ndarray) -> np.ndarray:
    """
    Normalize keypoints to be translation- and scale-invariant.

    Handles both [x, y] (stride=2) and [x, y, confidence] (stride=3) formats.
    - Translates bounding-box centre to (0, 0)
    - Scales bounding-box diagonal to 1.0
    - Zeros out joints below CONFIDENCE_THRESHOLD
    """
    kp = keypoints.copy().astype(np.float32)

    stride = 3 if (len(kp) % 3 == 0 and len(kp) % 2 != 0) else 2
    n_joints = len(kp) // stride
    xy = kp.reshape(n_joints, stride)[:, :2]

    if stride == 3:
        conf = kp.reshape(n_joints, stride)[:, 2]
        visible = conf > CONFIDENCE_THRESHOLD
    else:
        visible = np.ones(n_joints, dtype=bool)

    if visible.sum() < 2:
        return np.zeros_like(kp)

    visible_xy = xy[visible]
    min_xy = visible_xy.min(axis=0)
    max_xy = visible_xy.max(axis=0)
    centre = (min_xy + max_xy) / 2.0
    diag = np.linalg.norm(max_xy - min_xy)
    if diag < 1e-6:
        diag = 1.0

    xy_norm = (xy - centre) / diag
    if stride == 3:
        xy_norm[~visible] = 0.0

    kp_out = kp.reshape(n_joints, stride).copy()
    kp_out[:, :2] = xy_norm
    return kp_out.flatten()


def process_video(video_path: str):
    """
    Extract pose features from a video.

    Returns np.ndarray of shape (T, D*3) — pose + velocity + acceleration.
    Returns None if the video is too short or pose extraction fails.
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return None

    poses = []
    prev_pose = None
    missing_gap = 0

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        keypoints = vision.imgpose(frame)

        if keypoints is None:
            missing_gap += 1
            if missing_gap > MAX_MISSING_GAP:
                cap.release()
                return None
            keypoints = prev_pose
        else:
            missing_gap = 0
            keypoints = normalize_keypoints(np.array(keypoints, dtype=np.float32))

        if keypoints is not None:
            poses.append(keypoints)
            prev_pose = keypoints

    cap.release()

    if len(poses) < 2:
        return None

    poses = np.array(poses, dtype=np.float32)  # (T, D)

    velocity = np.vstack([
        np.zeros((1, poses.shape[1]), dtype=np.float32),
        poses[1:] - poses[:-1]
    ])
    acceleration = np.vstack([
        np.zeros((1, velocity.shape[1]), dtype=np.float32),
        velocity[1:] - velocity[:-1]
    ])

    return np.concatenate([poses, velocity, acceleration], axis=1)  # (T, D*3)


def create_sequences(features: np.ndarray, label: int):
    """Sliding-window segmentation."""
    X, y = [], []
    for i in range(0, len(features) - SEQUENCE_LENGTH + 1, STEP):
        seq = features[i: i + SEQUENCE_LENGTH]
        if len(seq) == SEQUENCE_LENGTH:
            X.append(seq)
            y.append(label)
    return X, y


def save_chunk(X: list, y: list, split: str, chunk_id: int):
    X_arr = np.array(X, dtype=np.float32)
    y_arr = np.array(y, dtype=np.int8)
    np.save(os.path.join(OUTPUT_DIR, f"{split}_X_{chunk_id}.npy"), X_arr)
    np.save(os.path.join(OUTPUT_DIR, f"{split}_y_{chunk_id}.npy"), y_arr)
    print(f"  Saved {split} chunk {chunk_id} | shape {X_arr.shape}")


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_split(split: str, fight_rel: str, nonfight_rel: str):
    """Process all videos for one split (train or val) and save chunks."""
    categories = [
        (os.path.join(DATASET_DIR, fight_rel),    1),
        (os.path.join(DATASET_DIR, nonfight_rel), 0),
    ]

    # Collect all video paths for this split
    all_videos = []
    for folder_path, label in categories:
        if not os.path.exists(folder_path):
            print(f"[WARNING] Folder not found: {folder_path}")
            continue
        for filename in os.listdir(folder_path):
            if filename.lower().endswith((".avi", ".mp4")):
                all_videos.append((os.path.join(folder_path, filename), label))

    print(f"\n--- {split.upper()} | {len(all_videos)} videos ---")

    X_buf, y_buf = [], []
    chunk_id = 0
    skipped = 0

    for video_path, label in tqdm(all_videos, desc=split, unit="vid"):
        features = process_video(video_path)

        if features is None or len(features) < SEQUENCE_LENGTH:
            tqdm.write(f"  [SKIP] {os.path.basename(video_path)}")
            skipped += 1
            continue

        X, y = create_sequences(features, label)
        X_buf.extend(X)
        y_buf.extend(y)

        if len(X_buf) >= CHUNK_SIZE:
            save_chunk(X_buf[:CHUNK_SIZE], y_buf[:CHUNK_SIZE], split, chunk_id)
            chunk_id += 1
            X_buf = X_buf[CHUNK_SIZE:]
            y_buf = y_buf[CHUNK_SIZE:]

    # Flush remainder
    if X_buf:
        save_chunk(X_buf, y_buf, split, chunk_id)
        chunk_id += 1

    total_seqs = sum(
        np.load(os.path.join(OUTPUT_DIR, f)).shape[0]
        for f in os.listdir(OUTPUT_DIR)
        if f.startswith(f"{split}_X_")
    )
    print(f"  {split}: {chunk_id} chunk(s) | {total_seqs} sequences | {skipped} skipped")


def build_dataset():
    print("===== RWF-2000 Dataset Builder =====")
    print(f"Output : {OUTPUT_DIR}")
    print(f"Source : {DATASET_DIR}\n")

    for split, (fight_rel, nonfight_rel) in SPLITS.items():
        build_split(split, fight_rel, nonfight_rel)

    print("\n===== Done =====")


if __name__ == "__main__":
    build_dataset()