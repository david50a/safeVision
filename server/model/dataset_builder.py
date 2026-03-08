import os
import numpy as np

# --- Configuration ---
SEQUENCE_LENGTH = 30
STEP = 5  # Jump frames to reduce redundancy (1 = every window, 5 = every 5th window)
DATA_PATH = r"C:\Users\meir\Documents\datasets\ntu-rgbd-v2\nturgb+d_skeletons"
OUTPUT_DIR = "processed_data"
CHUNK_SIZE = 2000  # Number of sequences to hold in RAM before saving to disk

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)


def extract_label(filename):
    # Extracts the Action ID (e.g., A001 -> 1)
    return int(filename.split('A')[-1].split('.')[0])


def load_skeleton_file(filepath):
    frames = []
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            if not lines: return None

            num_frames = int(lines[0].strip())
            current_line = 1

            for _ in range(num_frames):
                if current_line >= len(lines): break
                num_bodies = int(lines[current_line].strip())
                current_line += 1

                if num_bodies == 0:
                    continue

                # Skip body info line
                current_line += 1
                num_joints = int(lines[current_line].strip())
                current_line += 1

                joints = []
                for _ in range(num_joints):
                    joint_data = lines[current_line].strip().split()
                    # Only take X, Y, Z
                    joints.extend([float(joint_data[0]), float(joint_data[1]), float(joint_data[2])])
                    current_line += 1

                frames.append(joints)

                # Skip extra bodies if present
                for _ in range(num_bodies - 1):
                    current_line += 1  # body info
                    extra_joints = int(lines[current_line].strip())
                    current_line += 1 + extra_joints
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return None

    return np.array(frames, dtype='float32')


def add_velocity(sequence):
    """Calculates velocity and concatenates with position."""
    velocity = np.zeros_like(sequence)
    velocity[1:] = sequence[1:] - sequence[:-1]
    return np.concatenate([sequence, velocity], axis=1).astype('float32')


def build_dataset():
    X_chunk, y_chunk = [], []
    chunk_count = 0
    total_sequences = 0

    files = [f for f in os.listdir(DATA_PATH) if f.endswith(".skeleton")]
    print(f"Found {len(files)} files. Starting processing...")

    for idx, file in enumerate(files):
        label = extract_label(file)
        skeleton_path = os.path.join(DATA_PATH, file)
        sequence = load_skeleton_file(skeleton_path)

        if sequence is None or len(sequence) < SEQUENCE_LENGTH:
            continue

        # Sliding window with STEP to save memory
        for i in range(0, len(sequence) - SEQUENCE_LENGTH, STEP):
            window = sequence[i:i + SEQUENCE_LENGTH]
            features = add_velocity(window)

            X_chunk.append(features)
            y_chunk.append(label)

            # When chunk is full, save to disk and clear RAM
            if len(X_chunk) >= CHUNK_SIZE:
                save_path_X = os.path.join(OUTPUT_DIR, f"X_{chunk_count}.npy")
                save_path_y = os.path.join(OUTPUT_DIR, f"y_{chunk_count}.npy")

                np.save(save_path_X, np.array(X_chunk))
                np.save(save_path_y, np.array(y_chunk))

                total_sequences += len(X_chunk)
                print(f"Saved chunk {chunk_count} (Total: {total_sequences} sequences)")

                X_chunk, y_chunk = [], []
                chunk_count += 1

        if idx % 500 == 0:
            print(f"Processed {idx}/{len(files)} skeleton files...")

    # Save any remaining data
    if X_chunk:
        np.save(os.path.join(OUTPUT_DIR, f"X_{chunk_count}.npy"), np.array(X_chunk))
        np.save(os.path.join(OUTPUT_DIR, f"y_{chunk_count}.npy"), np.array(y_chunk))

    print(f"Done! Data saved in shards in '{OUTPUT_DIR}'")


if __name__ == "__main__":
    build_dataset()