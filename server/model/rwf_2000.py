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

DEVICE=torch.device("cuda" if torch.cuda.is_available() else "cpu")
