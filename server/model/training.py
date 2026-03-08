import os
import math
import time
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.utils.data import random_split
from torch.utils.data import Dataset, DataLoader
from torch.utils.tensorboard import SummaryWriter
from torch.amp import autocast,GradScaler
import lstm_model


DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

BATCH_SIZE = 8
EPOCHS = 100
LR = 1e-3
WARMUP_EPOCHS = 5
GRAD_CLIP = 1.0
SAVE_EVERY_BATCHES = 200

CHECKPOINT_PATH = "checkpoint.pth"
BEST_MODEL_PATH = "best_model.pth"
LOG_DIR = "runs/safevision"

class PoseDataset(Dataset):
    def __init__(self, directory):
        self.directory = directory
        self.X_chunks = []
        self.y_chunks = []
        self.indices = []

        files = sorted([f for f in os.listdir(directory) if f.startswith("X_")])

        for i, f in enumerate(files):
            X_chunk = np.load(os.path.join(directory, f), mmap_mode='r')
            # Subtract 1 from labels to make them 0-indexed [0, 119]
            y_chunk = np.load(os.path.join(directory, f.replace("X_", "y_")), mmap_mode='r') - 1

            self.X_chunks.append(X_chunk)
            self.y_chunks.append(y_chunk)

            for j in range(len(X_chunk)):
                self.indices.append((i, j))

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, idx):
        file_idx, seq_idx = self.indices[idx]

        return (
            torch.tensor(self.X_chunks[file_idx][seq_idx], dtype=torch.float32),
            torch.tensor(self.y_chunks[file_idx][seq_idx], dtype=torch.long)
        )
directory = r'..\processed_data'


dataset = PoseDataset(directory)
train_size = int(0.8 * len(dataset))
val_size = len(dataset) - train_size

train_dataset, val_dataset = random_split(dataset, [train_size, val_size])

train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True, pin_memory=True)
val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, pin_memory=True)

model = lstm_model.SafeVisionLSTM(
    input_size=150,
    hidden_size=128,
    num_classes=120
).to(DEVICE)

criterion = nn.CrossEntropyLoss()
optimizer = optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)

scaler = GradScaler(enabled=torch.cuda.is_available())

def lr_lambda(epoch):
    if epoch < WARMUP_EPOCHS:
        return epoch / WARMUP_EPOCHS
    return 0.5 * (1 + math.cos(math.pi * (epoch - WARMUP_EPOCHS) / (EPOCHS - WARMUP_EPOCHS)))

scheduler = torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)



start_epoch = 0
best_acc = 0
early_stop_counter = 0
EARLY_STOP_PATIENCE = 10

if os.path.exists(CHECKPOINT_PATH):
    print("Loading checkpoint...")
    checkpoint = torch.load(CHECKPOINT_PATH, map_location=DEVICE,weights_only=True)


    model.load_state_dict(checkpoint["model"])
    optimizer.load_state_dict(checkpoint["optimizer"])
    scaler.load_state_dict(checkpoint["scaler"])
    scheduler.load_state_dict(checkpoint["scheduler"])

    start_epoch = checkpoint["epoch"] + 1
    best_acc = checkpoint["best_acc"]
    early_stop_counter = checkpoint["early_stop"]

    print(f"Resumed from epoch {start_epoch}")


writer = SummaryWriter(LOG_DIR)

try:
    for epoch in range(start_epoch, EPOCHS):

        model.train()
        total_loss = 0
        batch_count = 0

        for X_batch, y_batch in train_loader:

            X_batch = X_batch.to(DEVICE)
            y_batch = y_batch.to(DEVICE)

            optimizer.zero_grad()

            with autocast(device_type='cuda'):
                outputs = model(X_batch)
                loss = criterion(outputs, y_batch)

            scaler.scale(loss).backward()

            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)

            scaler.step(optimizer)
            scaler.update()

            total_loss += loss.item()
            batch_count += 1

            # Auto-save mid epoch
            if batch_count % SAVE_EVERY_BATCHES == 0:
                torch.save({
                    "epoch": epoch,
                    "model": model.state_dict(),
                    "optimizer": optimizer.state_dict(),
                    "scaler": scaler.state_dict(),
                    "scheduler": scheduler.state_dict(),
                    "best_acc": best_acc,
                    "early_stop": early_stop_counter
                }, CHECKPOINT_PATH)

        scheduler.step()

        model.eval()
        correct = 0
        total = 0

        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch = X_batch.to(DEVICE)
                y_batch = y_batch.to(DEVICE)

                outputs = model(X_batch)
                preds = torch.argmax(outputs, dim=1)

                correct += (preds == y_batch).sum().item()
                total += y_batch.size(0)

        acc = correct / total
        avg_loss = total_loss / batch_count


        writer.add_scalar("Loss/train", avg_loss, epoch)
        writer.add_scalar("Accuracy/val", acc, epoch)
        writer.add_scalar("LR", optimizer.param_groups[0]['lr'], epoch)

        print(f"\nEpoch {epoch+1}/{EPOCHS}")
        print(f"Loss: {avg_loss:.4f}")
        print(f"Val Acc: {acc:.4f}")
        print(f"LR: {optimizer.param_groups[0]['lr']:.6f}")
        print("-" * 50)


        torch.save({
            "epoch": epoch,
            "model": model.state_dict(),
            "optimizer": optimizer.state_dict(),
            "scaler": scaler.state_dict(),
            "scheduler": scheduler.state_dict(),
            "best_acc": best_acc,
            "early_stop": early_stop_counter
        }, CHECKPOINT_PATH)


        if acc > best_acc:
            best_acc = acc
            early_stop_counter = 0
            torch.save(model.state_dict(), BEST_MODEL_PATH)
            print("New best model saved!")
        else:
            early_stop_counter += 1

        if early_stop_counter >= EARLY_STOP_PATIENCE:
            print("Early stopping triggered.")
            break

except KeyboardInterrupt:

    print("\nTraining interrupted — checkpoint saved.")

writer.close()
print("Training finished.")
