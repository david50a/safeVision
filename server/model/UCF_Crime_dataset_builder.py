"""
ucf_crime_dataset_builder_flow.py
UCF-Crime dataset builder using OPTICAL FLOW features.

Why optical flow instead of pose:
  - UCF-Crime is surveillance footage — people are small/distant
  - MediaPipe fails to detect poses reliably at distance
  - Optical flow measures pixel motion directly — works at any distance/scale
  - Captures exactly what matters: HOW FAST and IN WHAT DIRECTION things move

Feature vector per frame (204 features):
  - Flow magnitude stats  : mean, std, max, 75th percentile        (4)
  - Flow direction hist   : 8 bins (N,NE,E,SE,S,SW,W,NW)          (8)
  - Grid cells 4×4        : mean magnitude per cell                (16)
  - Grid cells 4×4        : mean angle per cell                    (16)
  - Velocity of above     : frame-to-frame difference of all above (44)
  - Acceleration          : frame-to-frame difference of velocity  (44)
  Total: 88 + 88 + 88 = ... actually: 44 raw + 44 velocity + 44 accel = 132
  Wait — exact: 4+8+16+16 = 44 raw features per frame
  44 raw + 44 velocity + 44 acceleration = 132 features total

Classes:
  0 = SAFE          (normal video)
  1 = PRE_VIOLENCE  (fight video, first 50% of clip)
  2 = VIOLENCE      (fight video, second 50% of clip)
"""

import os
import cv2
import numpy as np
import random
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import vision

# ── Configuration ─────────────────────────────────────────────────────────────
SEQUENCE_LENGTH    = 30
STEP               = 5
CHUNK_SIZE         = 2000
SEED               = 42

OUTPUT_DIR  = r"../processed_data_ucf_flow"
DATASET_DIR = r"C:\Users\meir\Documents\datasets\UCF_CRIME"

PRE_VIOLENCE_RATIO = 0.5
TRANSITION_MARGIN  = 0.08

MAX_SAFE_WINDOWS  = 200
MAX_FIGHT_WINDOWS = 400

# Optical flow settings
RESIZE_H     = 240   # resize frame to this height before flow computation
RESIZE_W     = 320   # keeps aspect ratio manageable
GRID_ROWS    = 4     # divide frame into 4×4 grid
GRID_COLS    = 4
FLOW_BINS    = 8     # direction histogram bins

# Frame sampling
FRAME_SAMPLE = 2     # process every 2nd frame

CLASS_MAP = {'SAFE': 0, 'DANGER': 1}  # binary: Safe vs Danger (pre-violence + violence combined)

# UCF-Crime folder structure
FIGHT_FOLDERS = [
    r"FightingA_Part1",
    r"FightingA_Part11",
    r"FightingA_Part2",
    r"FightingA_Part3",
    r"Anomaly-Videos-Part_2\Anomaly-Videos-Part-2\Fighting",
]
NORMAL_FOLDERS = [
    r"Testing_Normal_Videos_Anomaly\Testing_Normal_Videos_Anomaly",
    r"Normal_Videos_for_Event_Recognition\Normal_Videos_for_Event_Recognition",
]
SPLIT_DIR       = r"UCF_Crimes-Train-Test-Split\Anomaly_Detection_splits"
ANNOTATION_FILE = "Temporal_Anomaly_Annotation_for_Testing_Videos.txt"

# Feature size: 4 + 8 + 16 + 16 = 44 raw per frame
RAW_FEATURES = 4 + FLOW_BINS + GRID_ROWS * GRID_COLS + GRID_ROWS * GRID_COLS
# With velocity + acceleration: 44 * 3 = 132
FEATURE_SIZE = RAW_FEATURES * 3

random.seed(SEED)
np.random.seed(SEED)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Pose features: 99 keypoints + 99 velocity + 99 acceleration + 5 distances + 6 angles = 308
# Flow features: 44 raw + 44 velocity + 44 acceleration = 132
# Combined: 308 + 132 = 440
POSE_FEATURE_SIZE = 308
FLOW_FEATURE_SIZE = FEATURE_SIZE   # 132
COMBINED_SIZE     = POSE_FEATURE_SIZE + FLOW_FEATURE_SIZE  # 440
print(f"Feature size per frame: {COMBINED_SIZE} (pose={POSE_FEATURE_SIZE} + flow={FLOW_FEATURE_SIZE})")


# ── Optical flow feature extraction ──────────────────────────────────────────
def extract_flow_features(flow: np.ndarray) -> np.ndarray:
    """
    Extract a compact feature vector from a dense optical flow field.

    flow: np.ndarray (H, W, 2) — output of cv2.calcOpticalFlowFarneback

    Returns np.ndarray (44,) with:
      [0:4]   global stats: mean_mag, std_mag, max_mag, p75_mag
      [4:12]  direction histogram (8 bins)
      [12:28] 4×4 grid mean magnitude (16 values)
      [28:44] 4×4 grid mean angle     (16 values)
    """
    fx, fy   = flow[..., 0], flow[..., 1]
    mag      = np.sqrt(fx**2 + fy**2)
    angle    = np.arctan2(fy, fx)   # -π to π

    # ── Global stats ──────────────────────────────────────────────────────
    stats = np.array([
        mag.mean(),
        mag.std(),
        mag.max(),
        np.percentile(mag, 75),
    ], dtype=np.float32)

    # ── Direction histogram ───────────────────────────────────────────────
    # Bin angles into 8 directions weighted by magnitude
    # (strong motion in a direction counts more than weak motion)
    hist, _ = np.histogram(angle, bins=FLOW_BINS,
                           range=(-np.pi, np.pi), weights=mag)
    hist    = hist.astype(np.float32)
    hist_sum = hist.sum()
    if hist_sum > 0:
        hist /= hist_sum   # normalize to sum=1

    # ── Spatial grid ──────────────────────────────────────────────────────
    H, W      = mag.shape
    cell_h    = H // GRID_ROWS
    cell_w    = W // GRID_COLS
    grid_mag  = np.zeros(GRID_ROWS * GRID_COLS, dtype=np.float32)
    grid_ang  = np.zeros(GRID_ROWS * GRID_COLS, dtype=np.float32)

    for r in range(GRID_ROWS):
        for c in range(GRID_COLS):
            r0, r1 = r * cell_h, (r + 1) * cell_h
            c0, c1 = c * cell_w, (c + 1) * cell_w
            cell_m = mag[r0:r1, c0:c1]
            cell_a = angle[r0:r1, c0:c1]
            idx    = r * GRID_COLS + c
            grid_mag[idx] = cell_m.mean()
            # Weighted circular mean angle
            wx = np.cos(cell_a) * cell_m
            wy = np.sin(cell_a) * cell_m
            grid_ang[idx] = np.arctan2(wy.mean(), wx.mean())

    return np.concatenate([stats, hist, grid_mag, grid_ang])  # (44,)


def compute_velocity_1d(features: np.ndarray) -> np.ndarray:
    """Central difference velocity. features: (T, D) → (T, D)"""
    vel        = np.zeros_like(features)
    vel[1:-1]  = (features[2:] - features[:-2]) / 2.0
    vel[0]     = features[1] - features[0]
    vel[-1]    = features[-1] - features[-2]
    return vel


# ── Pose feature helpers (from vision.py) ────────────────────────────────────
def normalize_keypoints(keypoints: np.ndarray) -> np.ndarray:
    kp       = keypoints.copy().astype(np.float32)
    n_joints = len(kp) // 3   # x, y, z per joint
    xy       = kp.reshape(n_joints, 3)[:, :2]
    visible  = np.ones(n_joints, dtype=bool)

    if visible.sum() < 2:
        return np.zeros_like(kp)

    visible_xy = xy[visible]
    min_xy     = visible_xy.min(axis=0)
    max_xy     = visible_xy.max(axis=0)
    centre     = (min_xy + max_xy) / 2.0
    diag       = np.linalg.norm(max_xy - min_xy)
    if diag < 1e-6:
        diag = 1.0

    xy_norm        = (xy - centre) / diag
    kp_out         = kp.reshape(n_joints, 3).copy()
    kp_out[:, :2]  = xy_norm
    return kp_out.flatten()


def compute_angle(a, b, c):
    ba = a - b
    bc = c - b
    cos_angle = np.dot(ba, bc) / (np.linalg.norm(ba) * np.linalg.norm(bc) + 1e-6)
    return float(np.arccos(np.clip(cos_angle, -1.0, 1.0)))


def compute_distances(kp: np.ndarray) -> np.ndarray:
    k     = kp.reshape(33, 3)
    pairs = [(11,12),(13,14),(15,16),(23,24),(27,28)]
    return np.array([np.linalg.norm(k[a]-k[b]) for a,b in pairs], dtype=np.float32)


def compute_angles(kp: np.ndarray) -> np.ndarray:
    k = kp.reshape(33, 3)
    return np.array([
        compute_angle(k[11], k[13], k[15]),
        compute_angle(k[12], k[14], k[16]),
        compute_angle(k[23], k[25], k[27]),
        compute_angle(k[24], k[26], k[28]),
        compute_angle(k[13], k[11], k[23]),
        compute_angle(k[14], k[12], k[24]),
    ], dtype=np.float32)


def pose_to_features(raw_kp: np.ndarray) -> np.ndarray:
    """
    Convert raw keypoints (99,) to full pose feature vector (99,).
    Returns normalized keypoints only — velocity/acceleration added later.
    """
    if raw_kp is None or np.all(raw_kp == 0):
        return np.zeros(99, dtype=np.float32)
    return normalize_keypoints(raw_kp)


def build_pose_sequence(pose_list: list) -> np.ndarray:
    """
    Build full pose feature matrix from list of raw keypoints.
    pose_list: list of np.ndarray (99,)
    Returns: np.ndarray (T, 308)
    """
    poses        = np.array(pose_list, dtype=np.float32)    # (T, 99)
    velocity     = compute_velocity_1d(poses)                # (T, 99)
    acceleration = compute_velocity_1d(velocity)             # (T, 99)
    distances    = np.array([compute_distances(p) for p in poses], dtype=np.float32)  # (T, 5)
    angles       = np.array([compute_angles(p)    for p in poses], dtype=np.float32)  # (T, 6)
    return np.concatenate([poses, velocity, acceleration, distances, angles], axis=1)  # (T, 308)


def process_video(video_path: str):
    """
    Extract COMBINED optical flow + pose features from a video.
    Returns (features [T, 440], total_frame_count) or (None, 0).

    Feature breakdown per frame:
      Pose : 99 kp + 99 vel + 99 acc + 5 dist + 6 ang = 308
      Flow : 44 raw + 44 vel + 44 acc                 = 132
      Total: 440

    Policy: never skip a video — forward-fill missing poses with last known,
    use zero flow for first frame.
    """
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return None, 0

    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    fps          = cap.get(cv2.CAP_PROP_FPS) or 25.0
    duration_s   = total_frames / fps
    frame_sample = FRAME_SAMPLE if duration_s > 3.0 else 1

    flow_raw   = []   # list of (44,) flow features
    pose_raw   = []   # list of (99,) normalized keypoints
    last_pose  = np.zeros(99, dtype=np.float32)
    prev_gray  = None
    frame_idx  = 0
    zero_flow  = np.zeros(RAW_FEATURES, dtype=np.float32)

    with vision.VideoProcessor() as vp:
        while cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            frame_idx += 1
            if frame_idx % frame_sample != 0:
                continue

            # ── Pose extraction (full resolution for accuracy) ────────────
            timestamp_ms = int(frame_idx / fps * 1000)
            raw_kp       = vp.process(frame, timestamp_ms)   # (99,)

            if np.all(raw_kp == 0):
                pose_raw.append(last_pose.copy())  # forward fill
            else:
                norm_kp   = pose_to_features(raw_kp)
                last_pose = norm_kp
                pose_raw.append(norm_kp)

            # ── Optical flow (resized for speed) ──────────────────────────
            small = cv2.resize(frame, (RESIZE_W, RESIZE_H),
                               interpolation=cv2.INTER_LINEAR)
            gray  = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)

            if prev_gray is None:
                flow_raw.append(zero_flow.copy())
            else:
                flow = cv2.calcOpticalFlowFarneback(
                    prev_gray, gray, None,
                    pyr_scale=0.5, levels=3, winsize=15,
                    iterations=3, poly_n=5, poly_sigma=1.2, flags=0
                )
                flow_raw.append(extract_flow_features(flow))

            prev_gray = gray

    cap.release()

    if len(flow_raw) == 0:
        return None, total_frames

    # Pad short videos
    while len(flow_raw) < SEQUENCE_LENGTH:
        flow_raw.append(flow_raw[-1].copy())
        pose_raw.append(pose_raw[-1].copy())

    # ── Build pose feature matrix (T, 308) ────────────────────────────────
    pose_features = build_pose_sequence(pose_raw)   # (T, 308)

    # ── Build flow feature matrix (T, 132) ────────────────────────────────
    raw_f        = np.array(flow_raw, dtype=np.float32)
    vel_f        = compute_velocity_1d(raw_f)
    acc_f        = compute_velocity_1d(vel_f)
    flow_features = np.concatenate([raw_f, vel_f, acc_f], axis=1)  # (T, 132)

    # ── Concatenate → (T, 440) ────────────────────────────────────────────
    return np.concatenate([pose_features, flow_features], axis=1), total_frames


# ── Metadata loaders (same as pose builder) ───────────────────────────────────
def load_temporal_annotations(dataset_dir):
    ann_path    = os.path.join(dataset_dir, ANNOTATION_FILE)
    annotations = {}
    if not os.path.exists(ann_path):
        print(f"[WARN] Annotation file not found: {ann_path}")
        return annotations
    with open(ann_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            if 'fight' not in parts[1].lower():
                continue
            try:
                onset = int(parts[2])
            except ValueError:
                continue
            if onset <= 0:
                continue
            stem = os.path.splitext(os.path.basename(parts[0]))[0].lower()
            annotations[stem] = onset
    print(f"[✓] Loaded annotations for {len(annotations)} fight videos")
    return annotations


def load_split_lists(dataset_dir):
    split_dir   = os.path.join(dataset_dir, SPLIT_DIR)
    train_stems = set()
    test_stems  = set()
    if not os.path.isdir(split_dir):
        print(f"[WARN] Split dir not found: {split_dir}")
        return train_stems, test_stems
    for fname in os.listdir(split_dir):
        if 'fight' not in fname.lower():
            continue
        fpath    = os.path.join(split_dir, fname)
        is_train = 'train' in fname.lower()
        with open(fpath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                stem = os.path.splitext(os.path.basename(line))[0].lower()
                (train_stems if is_train else test_stems).add(stem)
    print(f"[✓] Split: {len(train_stems)} train, {len(test_stems)} test fight videos")
    return train_stems, test_stems


def find_videos(dataset_dir, folder_list):
    videos = []
    for rel in folder_list:
        folder = os.path.join(dataset_dir, rel)
        if not os.path.isdir(folder):
            print(f"[WARN] Folder not found: {folder}")
            continue
        for fname in os.listdir(folder):
            if fname.lower().endswith(('.mp4', '.avi')):
                stem = os.path.splitext(fname)[0].lower()
                videos.append((os.path.join(folder, fname), stem))
    return videos


# ── Sequence labeling ─────────────────────────────────────────────────────────
def create_sequences_normal(features: np.ndarray):
    X, y = [], []
    T    = len(features)
    for i in range(0, T - SEQUENCE_LENGTH + 1, STEP):
        seq = features[i: i + SEQUENCE_LENGTH]
        if len(seq) == SEQUENCE_LENGTH:
            X.append(seq)
            y.append(CLASS_MAP['SAFE'])
    if len(X) > MAX_SAFE_WINDOWS:
        idx = sorted(random.sample(range(len(X)), MAX_SAFE_WINDOWS))
        X   = [X[i] for i in idx]
        y   = [y[i] for i in idx]
    return X, y


def create_sequences_fight(features, onset_frame=None, video_total_frames=None):
    """
    All windows from a fight video → DANGER (1).
    Binary approach: we don't split pre-violence vs violence.
    The rising confidence score over time gives the 2-3s early warning.
    No transition zone needed — every window is a danger signal.
    """
    X, y = [], []
    T    = len(features)

    for i in range(0, T - SEQUENCE_LENGTH + 1, STEP):
        seq = features[i: i + SEQUENCE_LENGTH]
        if len(seq) == SEQUENCE_LENGTH:
            X.append(seq)
            y.append(CLASS_MAP['DANGER'])

    if len(X) > MAX_FIGHT_WINDOWS:
        idx = sorted(random.sample(range(len(X)), MAX_FIGHT_WINDOWS))
        X   = [X[i] for i in idx]
        y   = [y[i] for i in idx]
    return X, y


# ── Chunk I/O ─────────────────────────────────────────────────────────────────
def save_chunk(X, y, split, chunk_id):
    np.save(os.path.join(OUTPUT_DIR, f"{split}_X_{chunk_id}.npy"),
            np.array(X, dtype=np.float32))
    np.save(os.path.join(OUTPUT_DIR, f"{split}_y_{chunk_id}.npy"),
            np.array(y, dtype=np.int8))
    print(f"  Saved {split} chunk {chunk_id} — {len(X)} sequences")


def flush(X_buf, y_buf, split, chunk_id):
    while len(X_buf) >= CHUNK_SIZE:
        save_chunk(X_buf[:CHUNK_SIZE], y_buf[:CHUNK_SIZE], split, chunk_id)
        chunk_id += 1
        X_buf = X_buf[CHUNK_SIZE:]
        y_buf = y_buf[CHUNK_SIZE:]
    return X_buf, y_buf, chunk_id


# ── Main ──────────────────────────────────────────────────────────────────────
def build_dataset():
    print("===== UCF-Crime Optical Flow Dataset Builder =====")
    print(f"Source      : {DATASET_DIR}")
    print(f"Output      : {OUTPUT_DIR}")
    print(f"Features    : {FEATURE_SIZE} per frame "
          f"({RAW_FEATURES} flow + {RAW_FEATURES} velocity + {RAW_FEATURES} accel)")
    print(f"Labels      : 0=SAFE  1=PRE_VIOLENCE  2=VIOLENCE\n")

    annotations          = load_temporal_annotations(DATASET_DIR)
    train_stems, test_stems = load_split_lists(DATASET_DIR)
    fight_videos         = find_videos(DATASET_DIR, FIGHT_FOLDERS)
    normal_videos        = find_videos(DATASET_DIR, NORMAL_FOLDERS)

    # Deduplicate fight videos
    seen  = set()
    dedup = []
    for path, stem in fight_videos:
        if stem not in seen:
            seen.add(stem)
            dedup.append((path, stem))
    fight_videos = dedup
    print(f"[✓] {len(fight_videos)} unique fight videos, "
          f"{len(normal_videos)} normal videos")

    # Assign to splits
    splits = {'train': {'fight': [], 'normal': []},
              'val':   {'fight': [], 'normal': []}}

    for path, stem in fight_videos:
        if stem in train_stems:
            splits['train']['fight'].append((path, stem))
        elif stem in test_stems:
            splits['val']['fight'].append((path, stem))
        else:
            bucket = 'train' if random.random() < 0.8 else 'val'
            splits[bucket]['fight'].append((path, stem))

    random.shuffle(normal_videos)
    cut = int(len(normal_videos) * 0.8)
    splits['train']['normal'] = normal_videos[:cut]
    splits['val']['normal']   = normal_videos[cut:]

    for split in ['train', 'val']:
        fight_list  = splits[split]['fight']
        normal_list = splits[split]['normal']
        print(f"\n--- {split.upper()} | "
              f"{len(fight_list)} fight + {len(normal_list)} normal ---")

        all_vids = (
            [(p, s, 'fight')  for p, s in fight_list] +
            [(p, s, 'normal') for p, s in normal_list]
        )
        random.shuffle(all_vids)

        X_buf, y_buf = [], []
        chunk_id     = 0
        skipped      = 0
        annotated    = 0
        label_counts = Counter()

        # ── Threaded video processing ─────────────────────────────────
        # cv2.calcOpticalFlowFarneback releases the GIL so threads
        # run truly in parallel — significant speedup on multi-core CPUs
        NUM_WORKERS = min(8, os.cpu_count() or 4)
        print(f"  Using {NUM_WORKERS} worker threads")

        def process_one(args):
            path, stem, vtype = args
            features, vid_frames = process_video(path)
            if features is None:
                return None, stem, vtype, None, None
            onset = None
            if vtype == 'fight':
                onset = annotations.get(stem)
            return features, stem, vtype, onset, vid_frames

        pbar = tqdm(total=len(all_vids), desc=split,
                    unit="vid", dynamic_ncols=True)

        with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
            futures = {
                executor.submit(process_one, item): item
                for item in all_vids
            }
            for future in as_completed(futures):
                features, stem, vtype, onset, vid_frames = future.result()
                pbar.update(1)

                if features is None:
                    tqdm.write(f"  [SKIP - unreadable] {stem}")
                    skipped += 1
                    continue

                if vtype == 'normal':
                    X, y = create_sequences_normal(features)
                else:
                    if onset:
                        annotated += 1
                    X, y = create_sequences_fight(features, onset, vid_frames)

                label_counts.update(y)
                X_buf.extend(X)
                y_buf.extend(y)
                X_buf, y_buf, chunk_id = flush(X_buf, y_buf, split, chunk_id)

        pbar.close()

        if X_buf:
            save_chunk(X_buf, y_buf, split, chunk_id)
            chunk_id += 1

        total   = sum(label_counts.values())
        inv_map = {v: k for k, v in CLASS_MAP.items()}

        print(f"\n  {split.upper()} summary")
        print(f"  {'─'*45}")
        print(f"  Chunks    : {chunk_id}")
        print(f"  Sequences : {total}")
        print(f"  Skipped   : {skipped} (unreadable files only)")
        print(f"  Annotated : {annotated} fight videos (frame-level onset)")
        print(f"  Class distribution:")
        for cls_id in sorted(label_counts):
            n   = label_counts[cls_id]
            pct = n / max(total, 1) * 100
            bar = '█' * int(pct / 3)
            print(f"    [{cls_id}] {inv_map[cls_id]:<14} {n:>6}  ({pct:5.1f}%)  {bar}")
        for cls_id, n in label_counts.items():
            if n / max(total, 1) < 0.15:
                print(f"  [!] WARNING: class {cls_id} only "
                      f"{n/total*100:.1f}% of data")

    print("\n===== Done =====")
    print(f"Output: {OUTPUT_DIR}")
    print(f"\nUpdate training script:")
    print(f"  INPUT_SIZE = {FEATURE_SIZE}")
    print(f"  data_dir   = '{OUTPUT_DIR}'")


if __name__ == "__main__":
    build_dataset()