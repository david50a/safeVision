import os
import math
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from torch.utils.data import Dataset, DataLoader
from torch.utils.tensorboard import SummaryWriter
from torch.amp import autocast, GradScaler
import lstm_model

# ── Constants ─────────────────────────────────────────────────────────────────
BATCH_SIZE          = 16
EPOCHS              = 150
LR                  = 1e-3
WARMUP_EPOCHS       = 0   # no warmup — NTU120 has no benefit for optical flow features
GRAD_CLIP           = 1.0
SAVE_EVERY_BATCHES  = 200
EARLY_STOP_PATIENCE = 35

OBSERVE_START = 1.0
OBSERVE_END   = 0.6
OBSERVE_VAL   = 0.6

INPUT_SIZE  = 440      # 308 pose + 132 optical flow
HIDDEN_SIZE = 256
NUM_CLASSES = 2  # binary: Safe (0) vs Danger (1)

ARCH_VERSION    = 'v2'
LOG_DIR         = 'runs/safevision'
CHECKPOINT_PATH = 'safeVision_checkpoint.pth'
BEST_MODEL_PATH = 'safeVision_model.pth'
DEVICE          = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

print(f"Using device: {DEVICE}")


# ── Dataset ───────────────────────────────────────────────────────────────────
class ViolenceDataset(Dataset):
    def __init__(self, directory, dataset_type: str = 'train'):
        self.X_chunks = []
        self.y_chunks = []
        self.indices  = []

        files = sorted([
            f for f in os.listdir(directory)
            if f.startswith(f"{dataset_type}_X_")
        ])
        if not files:
            raise FileNotFoundError(
                f"No '{dataset_type}_X_*' files found in {directory}"
            )

        for i, f in enumerate(files):
            X = np.load(os.path.join(directory, f), mmap_mode='r')
            y = np.load(
                os.path.join(directory,
                             f.replace(f"{dataset_type}_X_", f"{dataset_type}_y_")),
                mmap_mode='r'
            )
            self.X_chunks.append(X)
            self.y_chunks.append(y)
            for j in range(len(X)):
                self.indices.append((i, j))

        print(f"[Dataset '{dataset_type}'] {len(self.indices)} samples")

    def __len__(self):
        return len(self.indices)

    def __getitem__(self, idx):
        fi, si = self.indices[idx]
        return (
            torch.tensor(self.X_chunks[fi][si], dtype=torch.float32),
            torch.tensor(self.y_chunks[fi][si], dtype=torch.long),
        )


# ── Helpers ───────────────────────────────────────────────────────────────────
def compute_class_weights(dataset, num_classes, device):
    counts = torch.zeros(num_classes)
    loader = DataLoader(dataset, batch_size=512, shuffle=False, num_workers=0)
    with torch.no_grad():
        for _, y in loader:
            for cls in range(num_classes):
                counts[cls] += (y == cls).sum()

    weights = 1.0 / (counts + 1e-6)
    weights = weights / weights.sum() * num_classes

    # Binary — no class collapse issue, pure inverse frequency is enough
    # Slight boost for Danger class since missing a fight is worse than false alarm
    DANGER_BOOST = 1.5
    weights[1] *= DANGER_BOOST
    weights = weights / weights.sum() * num_classes

    print(f"Class counts : {counts.long().tolist()}")
    print(f"Class weights: {[f'{w:.3f}' for w in weights.tolist()]}")
    return weights.to(device)


def load_pretrained_backbone(model, path, device):
    pretrained   = torch.load(path, map_location=device, weights_only=True)
    model_dict   = model.state_dict()
    transferable = {
        k: v for k, v in pretrained.items()
        if k in model_dict and model_dict[k].shape == v.shape
    }
    skipped = [k for k in pretrained if k not in transferable]
    model_dict.update(transferable)
    model.load_state_dict(model_dict)
    print(f"Transferred {len(transferable)} layers from NTU120")
    print(f"Skipped     {len(skipped)} layers (shape mismatch)")
    return model


def set_backbone_frozen(model, frozen: bool):
    for name, param in model.named_parameters():
        if 'classifier' not in name:
            param.requires_grad = not frozen


def get_optimizer(model, lr):
    backbone_params   = [p for n, p in model.named_parameters()
                         if 'classifier' not in n and p.requires_grad]
    classifier_params = [p for n, p in model.named_parameters()
                         if 'classifier' in n and p.requires_grad]
    return optim.AdamW([
        {'params': backbone_params,   'lr': lr},        # same LR — training from scratch
        {'params': classifier_params, 'lr': lr},
    ], weight_decay=1e-4)


def get_observe_ratio(epoch, epochs, start=OBSERVE_START, end=OBSERVE_END):
    progress = epoch / max(epochs - 1, 1)
    return round(max(end, start - progress * (start - end)), 4)


def make_scheduler(optimizer, epoch):
    """
    Single scheduler type for the entire training run.
    ReduceLROnPlateau — reduces LR when val accuracy stops improving.
    Using one scheduler type avoids incompatible state_dict on resume.
    """
    return torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer,
        mode='max',       # maximize val accuracy
        factor=0.5,       # halve LR on plateau
        patience=10,      # wait 10 epochs before reducing
        min_lr=1e-7,      # never go below this
    )


def checkpoint_is_compatible(ckpt):
    return ckpt.get('arch_version') == ARCH_VERSION


# ── Data ──────────────────────────────────────────────────────────────────────
dataset_train = ViolenceDataset(r'..\processed_data_ucf_flow', 'train')  # combined pose+flow
dataset_val   = ViolenceDataset(r'..\processed_data_ucf_flow', 'val')

train_loader = DataLoader(dataset_train, batch_size=BATCH_SIZE,
                          shuffle=True,  num_workers=0, pin_memory=True)
val_loader   = DataLoader(dataset_val,   batch_size=BATCH_SIZE,
                          shuffle=False, num_workers=0, pin_memory=True)

# ── Model ──────────────────────────────────────────────────────────────────────
model = lstm_model.SafeVisionLSTM(
    input_size=INPUT_SIZE,
    hidden_size=HIDDEN_SIZE,
    num_classes=NUM_CLASSES,
).to(DEVICE)

class_weights = compute_class_weights(dataset_train, NUM_CLASSES, DEVICE)
criterion     = nn.CrossEntropyLoss(weight=class_weights, label_smoothing=0.05)
scaler        = GradScaler(enabled=torch.cuda.is_available())

# ── Resume or fresh start ──────────────────────────────────────────────────────
start_epoch        = 0
best_acc           = 0.0
early_stop_counter = 0
optimizer          = None

if os.path.exists(CHECKPOINT_PATH):
    print("Found checkpoint — checking compatibility...")
    checkpoint = torch.load(CHECKPOINT_PATH, map_location=DEVICE, weights_only=True)

    if not checkpoint_is_compatible(checkpoint):
        old_ver = checkpoint.get('arch_version', 'v1')
        print(f"[!] Incompatible checkpoint (saved={old_ver}, current={ARCH_VERSION})")
        print(f"[!] Renaming to '{CHECKPOINT_PATH}.old' and starting fresh.")
        os.rename(CHECKPOINT_PATH, CHECKPOINT_PATH + '.old')

        print("Training from scratch (optical flow features)")
        optimizer = get_optimizer(model, LR)
        scheduler = make_scheduler(optimizer, 0)

    else:
        model.load_state_dict(checkpoint['model'])
        start_epoch        = checkpoint['epoch'] + 1
        best_acc           = checkpoint['best_acc']
        early_stop_counter = checkpoint['early_stop']

        if start_epoch < WARMUP_EPOCHS:
            set_backbone_frozen(model, frozen=True)
            print(f"Resumed epoch {start_epoch} — backbone frozen")
        else:
            set_backbone_frozen(model, frozen=False)
            print(f"Resumed epoch {start_epoch} — backbone unfrozen")

        optimizer = get_optimizer(model, LR)
        for group in optimizer.param_groups:
            group.setdefault('initial_lr', group['lr'])

        saved_opt = checkpoint['optimizer']
        if len(saved_opt['param_groups']) == len(optimizer.param_groups):
            optimizer.load_state_dict(saved_opt)
            print("  Optimizer state restored.")
        else:
            print(f"  [!] Optimizer group mismatch — skipping optimizer state.")

        scaler.load_state_dict(checkpoint['scaler'])
        scheduler = make_scheduler(optimizer, start_epoch)
        scheduler.load_state_dict(checkpoint['scheduler'])
        print(f"Resumed from epoch {start_epoch}, best_acc={best_acc:.4f}")

else:
    # Optical flow features are completely different from NTU120 pose features
    # — loading NTU120 weights only adds noise. Train from scratch.
    print("Fresh start — training from scratch (optical flow features)")
    optimizer = get_optimizer(model, LR)
    scheduler = make_scheduler(optimizer, 0)


# ── Training loop ──────────────────────────────────────────────────────────────
writer = SummaryWriter(LOG_DIR)

try:
    for epoch in range(start_epoch, EPOCHS):

        observe_ratio = get_observe_ratio(epoch, EPOCHS)

        # ── Backbone unfreeze at WARMUP_EPOCHS ────────────────────────────
        # No freeze/unfreeze — training from scratch on optical flow

        # ── Train ──────────────────────────────────────────────────────────
        model.train()
        total_loss  = 0.0
        batch_count = 0

        for X_batch, y_batch in train_loader:
            X_batch = X_batch.to(DEVICE, non_blocking=True)
            y_batch = y_batch.to(DEVICE, non_blocking=True)

            optimizer.zero_grad()

            with autocast(device_type=DEVICE.type):
                outputs = model(X_batch, observe_ratio=observe_ratio)
                loss    = criterion(outputs, y_batch)

            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), GRAD_CLIP)
            scaler.step(optimizer)
            scaler.update()

            total_loss  += loss.item()
            batch_count += 1

            if batch_count % SAVE_EVERY_BATCHES == 0:
                torch.save({
                    'epoch':        epoch,
                    'model':        model.state_dict(),
                    'optimizer':    optimizer.state_dict(),
                    'scaler':       scaler.state_dict(),
                    'scheduler':    scheduler.state_dict(),
                    'best_acc':     best_acc,
                    'early_stop':   early_stop_counter,
                    'arch_version': ARCH_VERSION,
                }, CHECKPOINT_PATH)
                print(f"  [Mid-epoch checkpoint at batch {batch_count}]")

        # ── Validate ───────────────────────────────────────────────────────
        model.eval()
        correct       = 0
        total         = 0
        class_correct = torch.zeros(NUM_CLASSES)
        class_total   = torch.zeros(NUM_CLASSES)

        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch = X_batch.to(DEVICE, non_blocking=True)
                y_batch = y_batch.to(DEVICE, non_blocking=True)

                outputs = model(X_batch, observe_ratio=OBSERVE_VAL)
                preds   = torch.argmax(outputs, dim=1)

                correct += (preds == y_batch).sum().item()
                total   += y_batch.size(0)

                for cls in range(NUM_CLASSES):
                    mask = (y_batch == cls)
                    class_correct[cls] += (preds[mask] == cls).sum().item()
                    class_total[cls]   += mask.sum().item()

        acc      = correct / total
        avg_loss = total_loss / batch_count

        # ✅ Step scheduler ONCE here with val accuracy — no duplicate call
        scheduler.step(acc)

        # ── Logging ────────────────────────────────────────────────────────
        writer.add_scalar('Loss/train',    avg_loss,      epoch)
        writer.add_scalar('Accuracy/val',  acc,           epoch)
        writer.add_scalar('ObserveRatio',  observe_ratio, epoch)
        writer.add_scalar('LR/backbone',   optimizer.param_groups[0]['lr'], epoch)
        writer.add_scalar('LR/classifier', optimizer.param_groups[1]['lr'], epoch)
        for cls in range(NUM_CLASSES):
            if class_total[cls] > 0:
                writer.add_scalar(f'Accuracy/class_{cls}',
                                  class_correct[cls] / class_total[cls], epoch)

        CLASS_NAMES = {0: 'Safe', 1: 'Pre-Violence', 2: 'Violence'}
        print(f"\nEpoch {epoch+1}/{EPOCHS}  |  observe={observe_ratio:.2f}")
        print(f"  Loss    : {avg_loss:.4f}")
        print(f"  Val Acc : {acc:.4f}")
        for cls in range(NUM_CLASSES):
            if class_total[cls] > 0:
                print(f"  {CLASS_NAMES[cls]:<14}: "
                      f"{class_correct[cls]/class_total[cls]*100:.1f}%"
                      f"  ({int(class_total[cls])} samples)")
        print(f"  LR back/head : "
              f"{optimizer.param_groups[0]['lr']:.2e} / "
              f"{optimizer.param_groups[1]['lr']:.2e}")
        print('─' * 55)

        # ── End-of-epoch checkpoint ────────────────────────────────────────
        torch.save({
            'epoch':        epoch,
            'model':        model.state_dict(),
            'optimizer':    optimizer.state_dict(),
            'scaler':       scaler.state_dict(),
            'scheduler':    scheduler.state_dict(),
            'best_acc':     best_acc,
            'early_stop':   early_stop_counter,
            'arch_version': ARCH_VERSION,
        }, CHECKPOINT_PATH)

        # ── Best model & early stopping ────────────────────────────────────
        if acc > best_acc:
            best_acc           = acc
            early_stop_counter = 0
            torch.save(model.state_dict(), BEST_MODEL_PATH)
            print(f"  ✅ New best model saved! (acc={best_acc:.4f})")
        else:
            early_stop_counter += 1
            print(f"  No improvement "
                  f"({early_stop_counter}/{EARLY_STOP_PATIENCE})")

        if early_stop_counter >= EARLY_STOP_PATIENCE:
            print("Early stopping triggered.")
            break

except KeyboardInterrupt:
    print("\nTraining interrupted — checkpoint already saved.")

finally:
    writer.close()
    print(f"Training finished. Best val accuracy: {best_acc:.4f}")