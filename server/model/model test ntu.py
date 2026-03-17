import torch
import numpy as np
from torch.utils.data import DataLoader
import lstm_model
from training import PoseDataset
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BATCH_SIZE = 16
MODEL_PATH = "best_model.pth"
DATA_DIR = r'..\processed_data'


def evaluate_model():
    print(f"using device: {DEVICE}")
    print("loading dataset")
    full_dataset = PoseDataset(DATA_DIR)
    train_size=int(0.8*len(full_dataset))
    test_size=len(full_dataset)-train_size
    _,test_dataset=torch.utils.data.random_split(full_dataset,[train_size,test_size],generator=torch.Generator().manual_seed(42))
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    model = lstm_model.SafeVisionLSTM(
        input_size=150,
        hidden_size=128,
        num_classes=120
    ).to(DEVICE)
    print("loading weights of model")
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()
    all_predictions = []
    all_labels = []

    print("evaluating model")
    with torch.no_grad():
        for x,y in test_loader:
            x = x.to(DEVICE)
            y = y.to(DEVICE)
            outputs=model(x)
            predictions = torch.argmax(outputs, dim=1)
            all_predictions.append(predictions.cpu().numpy())
            all_labels.append(y.cpu().numpy())
    accuracy=np.mean(np.array(all_predictions) == np.array(all_labels))
    print(f"accuracy: {accuracy*100}%")
    print("classification report")
    print(classification_report(np.array(all_predictions), np.array(all_labels)))
    plot_conf_matrix(all_labels, all_predictions)

def plot_conf_matrix(all_labels, all_predictions):
    cm=confusion_matrix(all_labels, all_predictions)
    plt.figure(figsize=(20,15))
    sns.heatmap(cm,annot=False,cmap="Blues")
    plt.xlabel("Predicted")
    plt.ylabel("True")
    plt.title("Confusion Matrix")
    plt.show()
    
if __name__ == "__main__":
    evaluate_model()