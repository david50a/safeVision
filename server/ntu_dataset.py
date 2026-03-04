# ntu_dataset.py

import os
import numpy as np
import torch
from torch.utils.data import Dataset

class NTUSkeletonDataset(Dataset):
    def __init__(self, root_dir, seq_len=60):
        self.root_dir = root_dir
        self.seq_len = seq_len
        self.files = [f for f in os.listdir(root_dir) if f.endswith(".npy")]

    def __len__(self):
        return len(self.files)

    def pad_or_truncate(self, data):
        T = data.shape[0]

        if T > self.seq_len:
            return data[:self.seq_len]

        elif T < self.seq_len:
            pad = np.zeros((self.seq_len - T, data.shape[1]))
            return np.concatenate([data, pad], axis=0)

        return data

    def __getitem__(self, idx):
        file_path = os.path.join(self.root_dir, self.files[idx])
        data = np.load(file_path)  # (T, 150) לדוגמה

        label = int(self.files[idx].split("A")[-1][:3]) - 1  # action label

        data = self.pad_or_truncate(data)

        return torch.tensor(data, dtype=torch.float32), torch.tensor(label)