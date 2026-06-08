import os
import torch
import torch.nn as nn
import numpy as np

class SafeVisionONNXWrapper(nn.Module):
    """
    Wraps SafeVisionLSTM to make it ONNX-exportable by baking in observe_ratio.
    """
    def __init__(self, model, observe_ratio, sequence_len=30):
        super().__init__()
        self.model = model
        self.observe_ratio = observe_ratio
        self.sequence_len = sequence_len
        self.observe_len = max(2, int(sequence_len * observe_ratio))

    def forward(self, x):
        # We must re-implement the forward logic if the original model's forward
        # is not directly traceable with the observe_ratio as an argument.
        # Since SafeVisionLSTMv15 takes observe_ratio as a float, we call it with a fixed value.
        logits, _ = self.model(x, observe_ratio=self.observe_ratio)
        return logits

def export_to_onnx(model, onnx_path, input_size, sequence_len=30, observe_ratio=0.4):
    """
    Exports a PyTorch model to ONNX.
    """
    model.eval()
    wrapper = SafeVisionONNXWrapper(model, observe_ratio, sequence_len)
    wrapper.eval()

    dummy_input = torch.randn(1, sequence_len, input_size)
    
    torch.onnx.export(
        wrapper,
        dummy_input,
        onnx_path,
        export_params=True,
        opset_version=17,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={
            'input': {0: 'batch_size'},
            'output': {0: 'batch_size'}
        }
    )
    return onnx_path
