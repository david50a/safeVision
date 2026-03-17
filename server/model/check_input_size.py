"""
Run this BEFORE training to confirm the correct input_size
for your processed UCF-Crime dataset.

Usage:
  python check_input_size.py --data_dir ../processed_data_ucf_crime
"""

import os
import sys
import argparse
import numpy as np

def check(data_dir, split='train'):
    files = sorted([
        f for f in os.listdir(data_dir)
        if f.startswith(f"{split}_X_")
    ])

    if not files:
        print(f"[ERROR] No '{split}_X_*' files found in {data_dir}")
        sys.exit(1)

    # Load just the first chunk
    first = np.load(os.path.join(data_dir, files[0]), mmap_mode='r')
    y     = np.load(os.path.join(data_dir,
                    files[0].replace(f"{split}_X_", f"{split}_y_")),
                    mmap_mode='r')

    print(f"\n{'═'*50}")
    print(f"  Dataset check: {data_dir}")
    print(f"{'═'*50}")
    print(f"  First chunk file : {files[0]}")
    print(f"  Chunk shape      : {first.shape}")
    print(f"    → samples      : {first.shape[0]}")
    print(f"    → sequence_len : {first.shape[1]}")
    print(f"    → input_size   : {first.shape[2]}  ← use this in training!")
    print(f"\n  Labels shape     : {y.shape}")
    print(f"  Unique labels    : {sorted(set(y.tolist()))}")

    from collections import Counter
    counts = Counter(y.tolist())
    total  = len(y)
    names  = {0: 'Safe', 1: 'Pre-Violence', 2: 'Violence'}
    print(f"\n  Label distribution (this chunk):")
    for cls, count in sorted(counts.items()):
        pct = count / total * 100
        print(f"    [{cls}] {names.get(cls, '?'):<14} "
              f"{count:>6} ({pct:.1f}%)")

    print(f"\n  Total chunks : {len(files)}")
    total_samples = sum(
        np.load(os.path.join(data_dir, f), mmap_mode='r').shape[0]
        for f in files
    )
    print(f"  Total samples: {total_samples}")
    print(f"\n{'═'*50}")
    print(f"\n  ✅ Set in rwf_2000_training.py:")
    print(f"     INPUT_SIZE = {first.shape[2]}")
    print(f"{'═'*50}\n")

    return first.shape[2]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_dir', default=r'..\processed_data_ucf_crime')
    parser.add_argument('--split',    default='train')
    args = parser.parse_args()
    check(args.data_dir, args.split)