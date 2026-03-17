"""
test_model.py — SafeVision model tester

Modes:
  dummy    — sanity check with random tensors (no data needed)
  dataset  — full evaluation on processed .npy chunks
  video    — live inference on a raw .mp4 / .avi file
  webcam   — live inference from webcam feed

Usage:
  python test_model.py --mode dummy
  python test_model.py --mode dataset --data_dir ../processed_data_ucf_crime
  python test_model.py --mode video   --video path/to/clip.mp4
  python test_model.py --mode webcam
"""

import os
import sys
import time
import argparse
import collections

import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

import lstm_model

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_PATH    = 'safeVision_model.pth'
INPUT_SIZE    = 297       # must match your training input_size
HIDDEN_SIZE   = 256       # must match your training hidden_size
NUM_CLASSES   = 3
OBSERVE_RATIO = 0.6
BATCH_SIZE    = 16
SEQUENCE_LEN  = 30

CLASS_NAMES = {
    0: 'Safe',
    1: 'Pre-Violence',
    2: 'Violence',
}

# Color per class for webcam/video overlay (BGR)
CLASS_COLORS = {
    0: (0, 200, 0),    # green
    1: (0, 165, 255),  # orange
    2: (0, 0, 220),    # red
}

DEVICE = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


# ── Model loader ──────────────────────────────────────────────────────────────
def load_model(path):
    if not os.path.exists(path):
        print(f"[ERROR] Model not found: {path}")
        print("        Train the model first or pass --model <path>")
        sys.exit(1)

    model = lstm_model.SafeVisionLSTM(
        input_size=INPUT_SIZE,
        hidden_size=HIDDEN_SIZE,
        num_classes=NUM_CLASSES,
    ).to(DEVICE)

    state = torch.load(path, map_location=DEVICE, weights_only=True)
    model.load_state_dict(state)
    model.eval()
    print(f"[✓] Model loaded from '{path}'  (device={DEVICE})")
    return model


# ── Inference ─────────────────────────────────────────────────────────────────
def predict(model, X: torch.Tensor):
    """
    X: [B, T, F]
    Returns (pred_classes, confidences, all_probs)
    """
    with torch.no_grad():
        logits = model(X.to(DEVICE), observe_ratio=OBSERVE_RATIO)
        probs  = F.softmax(logits, dim=1)
        confs, preds = probs.max(dim=1)
    return preds.cpu(), confs.cpu(), probs.cpu()


# ── Mode 1: Dummy sanity check ────────────────────────────────────────────────
def run_dummy(model):
    print(f"\n{'═'*55}")
    print(f"  MODE: Dummy Sanity Check")
    print(f"  Input : [1, {SEQUENCE_LEN}, {INPUT_SIZE}]")
    print(f"{'═'*55}\n")

    X = torch.randn(1, SEQUENCE_LEN, INPUT_SIZE)

    t0 = time.perf_counter()
    preds, confs, probs = predict(model, X)
    ms = (time.perf_counter() - t0) * 1000

    pred_cls = preds[0].item()
    print(f"  Prediction : {CLASS_NAMES[pred_cls]}  (class {pred_cls})")
    print(f"  Confidence : {confs[0].item()*100:.1f}%")
    print(f"  All probs  : { {CLASS_NAMES[i]: f'{p*100:.1f}%' for i, p in enumerate(probs[0].tolist())} }")
    print(f"  Latency    : {ms:.1f} ms")

    assert probs.shape == (1, NUM_CLASSES), f"Bad output shape: {probs.shape}"
    assert abs(probs[0].sum().item() - 1.0) < 1e-4, "Probs don't sum to 1"

    print(f"\n  [✓] All checks passed.\n")


# ── Mode 2: Dataset evaluation ────────────────────────────────────────────────
class NpyDataset(Dataset):
    def __init__(self, directory, split='val'):
        self.X_chunks = []
        self.y_chunks = []
        self.indices  = []

        files = sorted([f for f in os.listdir(directory)
                        if f.startswith(f"{split}_X_")])
        if not files:
            print(f"[ERROR] No '{split}_X_*' files in {directory}")
            sys.exit(1)

        for i, f in enumerate(files):
            X = np.load(os.path.join(directory, f), mmap_mode='r')
            y = np.load(
                os.path.join(directory,
                             f.replace(f"{split}_X_", f"{split}_y_")),
                mmap_mode='r'
            )
            self.X_chunks.append(X)
            self.y_chunks.append(y)
            for j in range(len(X)):
                self.indices.append((i, j))

        print(f"[✓] {len(self.indices)} samples loaded  (split='{split}')")

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, idx):
        fi, si = self.indices[idx]
        return (torch.tensor(self.X_chunks[fi][si], dtype=torch.float32),
                torch.tensor(self.y_chunks[fi][si], dtype=torch.long))


def run_dataset(model, data_dir, split='val'):
    print(f"\n{'═'*55}")
    print(f"  MODE: Dataset Evaluation  |  split='{split}'")
    print(f"  Dir : {data_dir}")
    print(f"{'═'*55}\n")

    dataset = NpyDataset(data_dir, split)
    loader  = DataLoader(dataset, batch_size=BATCH_SIZE,
                         shuffle=False, num_workers=0)

    all_preds  = []
    all_labels = []
    all_confs  = []

    t0 = time.perf_counter()
    for X_batch, y_batch in loader:
        preds, confs, _ = predict(model, X_batch)
        all_preds.append(preds)
        all_labels.append(y_batch)
        all_confs.append(confs)

    elapsed    = time.perf_counter() - t0
    all_preds  = torch.cat(all_preds)
    all_labels = torch.cat(all_labels)
    all_confs  = torch.cat(all_confs)

    total   = len(all_labels)
    correct = (all_preds == all_labels).sum().item()
    acc     = correct / total

    print(f"  Overall Accuracy : {acc*100:.2f}%  ({correct}/{total})")
    print(f"  Avg Confidence   : {all_confs.mean().item()*100:.1f}%")
    print(f"  Inference time   : {elapsed:.2f}s  "
          f"({elapsed/total*1000:.1f} ms/sample)\n")

    # ── Per-class breakdown ───────────────────────────────────────────────
    print(f"  {'Class':<16} {'Samples':>8} {'Correct':>8} "
          f"{'Accuracy':>9} {'Avg Conf':>9}")
    print(f"  {'─'*52}")
    for cls_idx, cls_name in CLASS_NAMES.items():
        mask = (all_labels == cls_idx)
        n    = mask.sum().item()
        if n == 0:
            print(f"  {cls_name:<16} {'N/A':>8}")
            continue
        c    = (all_preds[mask] == cls_idx).sum().item()
        conf = all_confs[mask].mean().item()
        bar  = '█' * int(c / n * 20)
        print(f"  {cls_name:<16} {n:>8} {c:>8} "
              f"  {c/n*100:>6.1f}%   {conf*100:>6.1f}%   {bar}")

    # ── Confusion matrix ──────────────────────────────────────────────────
    print(f"\n  Confusion Matrix (row=actual, col=predicted)")
    header = f"  {'':16}" + "".join(f"{n[:10]:>12}" for n in CLASS_NAMES.values())
    print(header)
    print(f"  {'─'*( 16 + 12*NUM_CLASSES )}")
    for true_cls, true_name in CLASS_NAMES.items():
        mask = (all_labels == true_cls)
        if mask.sum() == 0:
            continue
        row = f"  {true_name:<16}"
        for pred_cls in CLASS_NAMES:
            count = ((all_preds == pred_cls) & mask).sum().item()
            # Highlight diagonal
            marker = '*' if pred_cls == true_cls else ' '
            row += f"{count:>11}{marker}"
        print(row)

    # ── Anticipation metric ───────────────────────────────────────────────
    # How often does the model correctly flag Pre-Violence BEFORE Violence?
    if 1 in CLASS_NAMES and 2 in CLASS_NAMES:
        pre_mask     = (all_labels == 1)
        pre_detected = (all_preds[pre_mask] == 1).sum().item()
        pre_total    = pre_mask.sum().item()
        if pre_total > 0:
            print(f"\n  Anticipation Rate : "
                  f"{pre_detected/pre_total*100:.1f}%  "
                  f"({pre_detected}/{pre_total} pre-violent windows caught)")

    print(f"\n{'═'*55}\n")


# ── Mode 3: Video inference ───────────────────────────────────────────────────
def run_video(model, video_path, show=True):
    try:
        import cv2
    except ImportError:
        print("[ERROR] pip install opencv-python")
        sys.exit(1)

    print(f"\n{'═'*55}")
    print(f"  MODE: Video Inference")
    print(f"  File         : {video_path}")
    print(f"  Observe ratio: {OBSERVE_RATIO*100:.0f}%")
    print(f"{'═'*55}\n")

    if not os.path.exists(video_path):
        print(f"[ERROR] File not found: {video_path}")
        sys.exit(1)

    cap = cv2.VideoCapture(video_path)
    fps = cap.get(cv2.CAP_PROP_FPS) or 25
    W   = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    H   = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    print(f"  Resolution: {W}x{H}  FPS: {fps:.1f}")

    frame_buffer   = []
    feature_buffer = []
    results_log    = []
    prev_kp = prev_vel = None
    frame_idx      = 0
    last_pred      = 0
    last_conf      = 0.0
    last_probs     = [1.0, 0.0, 0.0]

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        frame_idx += 1

        # Extract pose features
        try:
            features, curr_kp, curr_vel = lstm_model.extract_features(
                frame, prev_kp, prev_vel
            )
            prev_kp, prev_vel = curr_kp, curr_vel
        except Exception:
            features = np.zeros(INPUT_SIZE, dtype=np.float32)

        feature_buffer.append(features)
        frame_buffer.append(frame.copy())

        # Run prediction every SEQUENCE_LEN frames (50% overlap slide)
        if len(feature_buffer) == SEQUENCE_LEN:
            X = torch.tensor(
                np.array(feature_buffer), dtype=torch.float32
            ).unsqueeze(0)

            preds, confs, probs = predict(model, X)
            last_pred  = preds[0].item()
            last_conf  = confs[0].item()
            last_probs = probs[0].tolist()
            timestamp  = frame_idx / fps

            results_log.append({
                'time': timestamp, 'frame': frame_idx,
                'pred': last_pred, 'conf': last_conf,
            })

            print(f"  t={timestamp:6.2f}s  frame={frame_idx:5d}  "
                  f"→  {CLASS_NAMES[last_pred]:<14}  "
                  f"conf={last_conf*100:.1f}%  "
                  f"[{', '.join(f'{p*100:.0f}%' for p in last_probs)}]")

            # Slide by 50%
            slide = SEQUENCE_LEN // 2
            feature_buffer = feature_buffer[slide:]
            frame_buffer   = frame_buffer[slide:]

        # ── Overlay on frame ──────────────────────────────────────────────
        if show:
            overlay = frame.copy()
            color   = CLASS_COLORS[last_pred]

            # Top bar
            cv2.rectangle(overlay, (0, 0), (W, 60), (0, 0, 0), -1)
            cv2.addWeighted(overlay, 0.6, frame, 0.4, 0, frame)

            label = f"{CLASS_NAMES[last_pred]}  {last_conf*100:.0f}%"
            cv2.putText(frame, label, (10, 40),
                        cv2.FONT_HERSHEY_SIMPLEX, 1.2, color, 2)

            # Probability bars
            bar_y = H - 20
            for cls_idx, prob in enumerate(last_probs):
                bar_w = int(prob * 150)
                bx    = 10 + cls_idx * 160
                cv2.rectangle(frame, (bx, bar_y - 15),
                              (bx + bar_w, bar_y),
                              CLASS_COLORS[cls_idx], -1)
                cv2.putText(frame, CLASS_NAMES[cls_idx][:3],
                            (bx, bar_y - 18),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.4,
                            CLASS_COLORS[cls_idx], 1)

            cv2.imshow('SafeVision', frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                print("  [Stopped by user]")
                break

    cap.release()
    if show:
        cv2.destroyAllWindows()

    # ── Summary ───────────────────────────────────────────────────────────
    if not results_log:
        print("[WARN] No predictions made — video shorter than one window.")
        return

    counts   = collections.Counter(r['pred'] for r in results_log)
    total_w  = len(results_log)
    dominant = counts.most_common(1)[0][0]

    print(f"\n  ── Summary {'─'*38}")
    print(f"  Windows analysed : {total_w}")
    for cls_idx, cls_name in CLASS_NAMES.items():
        n   = counts.get(cls_idx, 0)
        pct = n / total_w * 100
        bar = '█' * int(pct / 3)
        print(f"  {cls_name:<16} {n:>3}x  {pct:5.1f}%  {bar}")
    print(f"\n  Dominant : {CLASS_NAMES[dominant]}")
    print(f"{'═'*55}\n")


# ── Mode 4: Webcam ────────────────────────────────────────────────────────────
def run_webcam(model, cam_id=0):
    try:
        import cv2
    except ImportError:
        print("[ERROR] pip install opencv-python")
        sys.exit(1)

    print(f"\n{'═'*55}")
    print(f"  MODE: Webcam  (press Q to quit)")
    print(f"{'═'*55}\n")

    cap = cv2.VideoCapture(cam_id)
    if not cap.isOpened():
        print(f"[ERROR] Cannot open camera {cam_id}")
        sys.exit(1)

    W = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    H = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

    feature_buffer = []
    prev_kp = prev_vel = None
    last_pred  = 0
    last_conf  = 0.0
    last_probs = [1.0, 0.0, 0.0]

    # Rolling prediction history for smoothing (last 5 predictions)
    pred_history = collections.deque(maxlen=5)

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Extract features
        try:
            features, curr_kp, curr_vel = lstm_model.extract_features(
                frame, prev_kp, prev_vel
            )
            prev_kp, prev_vel = curr_kp, curr_vel
        except Exception:
            features = np.zeros(INPUT_SIZE, dtype=np.float32)

        feature_buffer.append(features)

        if len(feature_buffer) == SEQUENCE_LEN:
            X = torch.tensor(
                np.array(feature_buffer), dtype=torch.float32
            ).unsqueeze(0)

            preds, confs, probs = predict(model, X)
            last_pred  = preds[0].item()
            last_conf  = confs[0].item()
            last_probs = probs[0].tolist()

            pred_history.append(last_pred)

            # Slide by 50%
            feature_buffer = feature_buffer[SEQUENCE_LEN // 2:]

        # Smoothed prediction (majority vote over last 5 windows)
        if pred_history:
            smooth_pred = collections.Counter(pred_history).most_common(1)[0][0]
        else:
            smooth_pred = 0

        color = CLASS_COLORS[smooth_pred]

        # ── Draw overlay ──────────────────────────────────────────────────
        # Top status bar
        cv2.rectangle(frame, (0, 0), (W, 65), (20, 20, 20), -1)

        status = f"{CLASS_NAMES[smooth_pred]}  {last_conf*100:.0f}%"
        cv2.putText(frame, status, (10, 45),
                    cv2.FONT_HERSHEY_SIMPLEX, 1.3, color, 2)

        # Buffer fill indicator
        buf_pct = len(feature_buffer) / SEQUENCE_LEN
        cv2.rectangle(frame, (W-120, 10), (W-10, 30), (60, 60, 60), -1)
        cv2.rectangle(frame, (W-120, 10),
                      (W-120 + int(buf_pct * 110), 30), (180, 180, 180), -1)
        cv2.putText(frame, "buf", (W-120, 45),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.4, (180, 180, 180), 1)

        # Probability bars at bottom
        for cls_idx, prob in enumerate(last_probs):
            bar_w = int(prob * 160)
            bx    = 10 + cls_idx * 180
            by    = H - 10
            cv2.rectangle(frame, (bx, by - 18),
                          (bx + bar_w, by),
                          CLASS_COLORS[cls_idx], -1)
            cv2.putText(frame, f"{CLASS_NAMES[cls_idx][:3]} {prob*100:.0f}%",
                        (bx, by - 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.4,
                        CLASS_COLORS[cls_idx], 1)

        # Alert border if pre-violence or violence detected
        if smooth_pred > 0:
            thickness = 4 if smooth_pred == 1 else 6
            cv2.rectangle(frame, (0, 0), (W-1, H-1), color, thickness)

        cv2.imshow('SafeVision — Live', frame)
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    print("Webcam session ended.")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SafeVision Model Tester')
    parser.add_argument('--mode',     choices=['dummy', 'dataset', 'video', 'webcam'],
                        default='dummy')
    parser.add_argument('--model',    default=MODEL_PATH,
                        help=f'Path to .pth weights (default: {MODEL_PATH})')
    parser.add_argument('--data_dir', default=r'..\processed_data_ucf_crime',
                        help='Path to processed .npy directory (dataset mode)')
    parser.add_argument('--split',    default='val',
                        choices=['train', 'val'],
                        help='Which split to evaluate (dataset mode)')
    parser.add_argument('--video',    default=None,
                        help='Path to video file (video mode)')
    parser.add_argument('--no_show',  action='store_true',
                        help='Disable OpenCV window (video mode)')
    parser.add_argument('--cam',      type=int, default=0,
                        help='Camera device index (webcam mode, default: 0)')
    parser.add_argument('--observe',  type=float, default=OBSERVE_RATIO,
                        help=f'Observe ratio (default: {OBSERVE_RATIO})')

    args = parser.parse_args()
    OBSERVE_RATIO = args.observe

    print(f"\n  SafeVision Tester")
    print(f"  Device        : {DEVICE}")
    print(f"  Observe ratio : {OBSERVE_RATIO*100:.0f}%")

    model = load_model(args.model)

    if args.mode == 'dummy':
        run_dummy(model)

    elif args.mode == 'dataset':
        run_dataset(model, args.data_dir, split=args.split)

    elif args.mode == 'video':
        if not args.video:
            print("[ERROR] --video <path> required")
            sys.exit(1)
        run_video(model, args.video, show=not args.no_show)

    elif args.mode == 'webcam':
        run_webcam(model, cam_id=args.cam)