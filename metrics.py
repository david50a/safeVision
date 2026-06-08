import pandas as pd
import matplotlib.pyplot as plt
import os
import torch
import seaborn as sns
import numpy as np

# Set style for a premium look
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')

fig = plt.figure(figsize=(24, 15))
ax1 = plt.subplot2grid((3, 3), (0, 0))
ax2 = plt.subplot2grid((3, 3), (0, 1))
ax3 = plt.subplot2grid((3, 3), (0, 2))
ax_cm = plt.subplot2grid((3, 3), (1, 0))
ax_cr = plt.subplot2grid((3, 3), (1, 1), colspan=2)
ax4 = plt.subplot2grid((3, 3), (2, 0), colspan=3)

# Read training log
csv_path = r"c:\safeVision\server\model\previolence_model\logs\training_log.csv"
df = pd.read_csv(csv_path)

# Plot 1: Loss
ax1.plot(df['epoch'], df['train_loss'], label='Train Loss', color='#3b82f6', linewidth=2)
ax1.plot(df['epoch'], df['val_loss'], label='Val Loss', color='#ef4444', linewidth=2)
ax1.set_title('Loss Convergence', fontsize=14, fontweight='bold', pad=15)
ax1.set_xlabel('Epoch', fontsize=12)
ax1.set_ylabel('Loss', fontsize=12)
ax1.legend(frameon=True, facecolor='white', framealpha=0.9)
ax1.grid(True, linestyle='--', alpha=0.6)

# Plot 2: Accuracy
ax2.plot(df['epoch'], df['train_acc'] * 100, label='Train Acc', color='#3b82f6', linewidth=2)
ax2.plot(df['epoch'], df['val_acc'] * 100, label='Val Acc', color='#10b981', linewidth=2)
ax2.set_title('Accuracy Trend', fontsize=14, fontweight='bold', pad=15)
ax2.set_xlabel('Epoch', fontsize=12)
ax2.set_ylabel('Accuracy (%)', fontsize=12)
ax2.legend(frameon=True, facecolor='white', framealpha=0.9)
ax2.grid(True, linestyle='--', alpha=0.6)

# Plot 3: F1-Scores
ax3.plot(df['epoch'], df['safe_f1'], label='Safe F1', color='#10b981', linewidth=2)
ax3.plot(df['epoch'], df['pre_violence_f1'], label='Pre-Violence F1', color='#f59e0b', linewidth=2)
ax3.plot(df['epoch'], df['violence_f1'], label='Violence F1', color='#ef4444', linewidth=2)
ax3.set_title('Validation F1-Scores by Class', fontsize=14, fontweight='bold', pad=15)
ax3.set_xlabel('Epoch', fontsize=12)
ax3.set_ylabel('F1-Score', fontsize=12)
ax3.legend(frameon=True, facecolor='white', framealpha=0.9)
ax3.grid(True, linestyle='--', alpha=0.6)

# Plot 4 & 5: Confusion Matrix & Classification Report
ckpt_path = r"c:\safeVision\server\model\previolence_model\checkpoints\best.pt"
class_names = ['safe', 'pre_violence', 'violence']
if os.path.exists(ckpt_path):
    checkpoint = torch.load(ckpt_path, map_location='cpu', weights_only=False)
    if 'metrics' in checkpoint and 'val' in checkpoint['metrics']:
        val_metrics = checkpoint['metrics']['val']
        
        # Confusion Matrix
        if 'confusion_matrix' in val_metrics:
            cm = np.array(val_metrics['confusion_matrix'])
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax_cm, 
                        xticklabels=class_names, yticklabels=class_names, cbar=False)
            ax_cm.set_title('Validation Confusion Matrix', fontsize=14, fontweight='bold', pad=15)
            ax_cm.set_xlabel('Predicted', fontsize=12)
            ax_cm.set_ylabel('Actual', fontsize=12)
            
        # Classification Report Table
        class_metrics = []
        for name in class_names:
            class_metrics.append({
                'Class': name.replace('_', ' ').title(),
                'Precision': val_metrics.get(f'{name}_precision', 0),
                'Recall': val_metrics.get(f'{name}_recall', 0),
                'F1-Score': val_metrics.get(f'{name}_f1', 0)
            })
        cr_df = pd.DataFrame(class_metrics).round(4)
        ax_cr.axis('tight')
        ax_cr.axis('off')
        ax_cr.set_title('Best Epoch: Precision, Recall & F1-Score', fontsize=14, fontweight='bold', pad=15)
        table_cr = ax_cr.table(cellText=cr_df.values, colLabels=cr_df.columns, loc='center', cellLoc='center')
        table_cr.auto_set_font_size(False)
        table_cr.set_fontsize(13)
        table_cr.scale(1, 2)
    else:
        ax_cm.text(0.5, 0.5, 'Metrics not found in checkpoint', ha='center', va='center')
        ax_cm.axis('off')
        ax_cr.axis('off')
else:
    ax_cm.text(0.5, 0.5, 'Checkpoint file not found', ha='center', va='center')
    ax_cm.axis('off')
    ax_cr.axis('off')

# Plot 6: Table
ax4.axis('tight')
ax4.axis('off')
ax4.set_title('Final 5 Epochs Metrics Summary', fontsize=14, fontweight='bold', pad=15)
summary_cols = ['epoch', 'train_loss', 'val_loss', 'train_acc', 'val_acc', 'safe_f1', 'pre_violence_f1', 'violence_f1']
summary_df = df[summary_cols].tail(5).round(4)
table = ax4.table(cellText=summary_df.values, colLabels=summary_df.columns, loc='center', cellLoc='center')
table.auto_set_font_size(False)
table.set_fontsize(12)
table.scale(1, 1.8)

plt.tight_layout()

# Save plot to brain directory
output_path = r"C:\Users\meir\.gemini\antigravity-ide\brain\5161570c-073e-4997-a230-1f2757aa62de\metrics.png"
plt.savefig(output_path, dpi=300, bbox_inches='tight')
print(f"Plot successfully saved to {output_path}")
