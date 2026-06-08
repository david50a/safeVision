import cv2
import torch
import numpy as np
import argparse
import collections
from pathlib import Path
import torch.nn.functional as F

# Import from local project
from tester import load_checkpoint, CLASS_NAMES
from lstm_model_v15 import extract_features, build_sequence_features

def main():
    parser = argparse.ArgumentParser(description="Live Webcam Inference for SafeVision")
    parser.add_argument('--checkpoint', type=str, required=True, help="Path to checkpoint (.pt)")
    parser.add_argument('--device', type=str, default='auto', help="Device (cpu, cuda, auto)")
    parser.add_argument('--seq_len', type=int, default=30, help="Frames per sequence window")
    parser.add_argument('--camera', type=str, default=r"C:\Users\meir\Documents\datasets\RWF-2000\val\NonFight\Fwhi4UNI_0.avi", help="Camera index (default: 0)")
    parser.add_argument('--fps_target', type=int, default=10, help="Target FPS for sampling (default: 10)")
    parser.add_argument('--save_video', type=str, default=None, help="Path to save the output video (e.g. output.mp4)")
    args = parser.parse_args()

    # Setup device
    if args.device == 'auto':
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    else:
        device = torch.device(args.device)

    print(f"Loading checkpoint '{args.checkpoint}' on {device}...")
    model, ckpt, train_observe_ratio = load_checkpoint(args.checkpoint, device)
    model.eval()

    # Open webcam
    cap = cv2.VideoCapture(args.camera)
    if not cap.isOpened():
        print(f"Error: Could not open camera {args.camera}.")
        return

    # Try to set a lower resolution to keep fps high
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    fps_src = cap.get(cv2.CAP_PROP_FPS)
    if not fps_src or fps_src <= 0 or np.isnan(fps_src):
        fps_src = 30.0
    sample_interval = max(1, int(fps_src / args.fps_target))

    print(f"Camera opened successfully. Source FPS: {fps_src:.1f}, Target FPS: {args.fps_target}")
    print(f"Sampling every {sample_interval} frames. Press 'q' to quit.")

    video_writer = None
    if args.save_video:
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        video_writer = cv2.VideoWriter(args.save_video, fourcc, fps_src, (width, height))
        print(f"Saving output video to: {args.save_video}")

    # Rolling buffer for raw features
    raw_sequence = collections.deque(maxlen=args.seq_len)
    
    # State variables for feature extraction
    prev_kp = None
    prev_vel = None
    prev_gray = None

    # UI variables
    current_pred_text = "Buffering..."
    current_color = (255, 255, 255)
    colors = {
        0: (0, 255, 0),    # Safe (Green)
        1: (0, 165, 255),  # Pre-violence (Orange)
        2: (0, 0, 255)     # Violence (Red)
    }

    frame_idx = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            print("Failed to grab frame.")
            break

        # Only extract features at the target FPS
        if frame_idx % sample_interval == 0:
            # Extract features for the current frame
            feat, prev_kp, prev_vel, prev_gray, _ = extract_features(
                frame, prev_kp, prev_vel, prev_gray
            )
            
            raw_sequence.append(feat)

            # Run inference if we have a full sequence
            if len(raw_sequence) == args.seq_len:
                with torch.no_grad():
                    # Build (T, 440) feature array
                    feat_array = build_sequence_features(list(raw_sequence))
                    feat_t = torch.tensor(feat_array, dtype=torch.float32).unsqueeze(0).to(device)
                    
                    # Model forward pass
                    logits, _ = model(feat_t, observe_ratio=train_observe_ratio)
                    probs = F.softmax(logits, dim=1).squeeze(0).cpu().numpy()
                    
                    pred = int(probs.argmax())
                    conf = float(probs.max())
                    
                    label = CLASS_NAMES[pred]
                    current_pred_text = f"{label.upper()}: {conf*100:.1f}%"
                    current_color = colors.get(pred, (255, 255, 255))
                    
                    # Simple pose heuristic check
                    win_poses = [float(np.abs(f[:99]).max()) > 1e-6 for f in raw_sequence]
                    pose_frac = sum(win_poses) / len(win_poses)
                    if pose_frac < 0.3:
                        current_pred_text += " [No Pose Found]"

        frame_idx += 1

        # Overlay text on the frame
        # Shadow
        cv2.putText(frame, current_pred_text, (22, 52), cv2.FONT_HERSHEY_SIMPLEX, 
                    1.0, (0, 0, 0), 3, cv2.LINE_AA)
        # Main text
        cv2.putText(frame, current_pred_text, (20, 50), cv2.FONT_HERSHEY_SIMPLEX, 
                    1.0, current_color, 2, cv2.LINE_AA)

        # Display the frame
        cv2.imshow("SafeVision Live Inference", frame)

        if video_writer is not None:
            video_writer.write(frame)

        # Press 'q' to quit
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    if video_writer is not None:
        video_writer.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    main()
