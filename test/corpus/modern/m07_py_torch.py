import torch
import numpy as np

def load_model(path, npz):
    model = torch.load(path)
    arr = np.load(npz, allow_pickle=True)
    return model, arr
