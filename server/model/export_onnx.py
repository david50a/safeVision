"""
export_onnx.py — Export SafeVisionLSTM to ONNX

The model's forward() takes `observe_ratio` as a Python float, which ONNX
can't trace. We wrap the model to bake in a fixed observe_ratio at export time.

Usage:
  python export_onnx.py
  python export_onnx.py --model safeVision_model.pth --observe 0.6 --out safeVision.onnx

After export, verify with:
  python export_onnx.py --verify
"""

import argparse
import os
import sys
import getpass
import numpy as np
import torch
import torch.nn as nn
import lstm_model
# Try to import encryption utilities
try:
    from model_protection import FileEncryptor
except ImportError:
    # If run from server root
    try:
        from model.model_protection import FileEncryptor
    except ImportError:
        FileEncryptor = None

#   Config (must match your training script)                 ─
INPUT_SIZE   = 440
HIDDEN_SIZE  = 128
NUM_CLASSES  = 3       # change to 2 if you used binary model
SEQUENCE_LEN = 30
OBSERVE_RATIO = 0.6

MODEL_PATH = r"C:\Users\meir\Documents\pyhton\AI\lstm_model\runs\ultimate_accuracy_run\checkpoints\best.pt"
ONNX_PATH  = "safeVision.onnx"

DEVICE = torch.device("cpu")  # always export on CPU for maximum compatibility


#   Wrapper that bakes observe_ratio into the forward pass          ─
class SafeVisionONNX(nn.Module):
    """
    Thin wrapper around SafeVisionLSTM that fixes observe_ratio so that
    torch.onnx.export can trace a single static graph.

    observe_ratio is baked in at export time — change it by re-exporting.
    """
    def __init__(self, model: nn.Module, observe_ratio: float):
        super().__init__()
        self.model         = model
        self.observe_ratio = observe_ratio

        # Pre-compute the observed sequence length once so the graph is static
        self.observe_len = max(1, int(SEQUENCE_LEN * observe_ratio))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: [B, SEQUENCE_LEN, INPUT_SIZE]
        returns: [B, NUM_CLASSES] logits
        """
        logits, _ = self.model(x, observe_ratio=self.observe_ratio)
        return logits


def load_pytorch_model(model_path: str) -> nn.Module:
    # Import your model — adjust the path if needed
    model_dir = os.path.dirname(os.path.abspath(__file__))
    if model_dir not in sys.path:
        sys.path.insert(0, model_dir)

    try:
        import lstm_model
    except ImportError as e:
        print(f"[ERROR] Cannot import lstm_model.py: {e}")
        print("— run this script from the same folder or check its dependencies.")
        sys.exit(1)

    model = lstm_model.SafeVisionLSTM(
        input_size=INPUT_SIZE,
        hidden_size=HIDDEN_SIZE,
        num_classes=NUM_CLASSES,
    ).to(DEVICE)

    if not os.path.exists(model_path):
        print(f"[ERROR] Model weights not found: {model_path}")
        sys.exit(1)

    # Allow numpy globals which are common in older saved models
    try:
        import numpy as np
        torch.serialization.add_safe_globals([
            np._core.multiarray.scalar,
            np.dtype,
            np._core.multiarray._reconstruct,
            np.ndarray
        ])
    except Exception:
        pass

    state = torch.load(model_path, map_location=DEVICE, weights_only=False)
    if 'model_state_dict' in state:
        state = state['model_state_dict']
    model.load_state_dict(state, strict=False)
    model.eval()
    print(f"[OK] PyTorch model loaded from '{model_path}'")
    return model


def export(model_path: str, onnx_path: str, observe_ratio: float):
    model   = load_pytorch_model(model_path)
    wrapper = SafeVisionONNX(model, observe_ratio).to(DEVICE)
    wrapper.eval()

    # Dummy input: batch=1, T=SEQUENCE_LEN, F=INPUT_SIZE
    dummy = torch.randn(1, SEQUENCE_LEN, INPUT_SIZE, device=DEVICE)

    # Sanity-check the wrapper gives the same output as the original model
    with torch.no_grad():
        out_orig    = model(dummy, observe_ratio=observe_ratio)[0]
        out_wrapper = wrapper(dummy)
    assert torch.allclose(out_orig, out_wrapper, atol=1e-5), \
        "Wrapper output doesn't match original model! Check observe_len calculation."
    print(f"[OK] Wrapper output matches original model")

    #   Export                                ─
    torch.onnx.export(
        wrapper,
        dummy,
        onnx_path,
        export_params=True,
        opset_version=17,           # 17 = LSTM + MultiheadAttention support
        do_constant_folding=True,
        input_names=["input"],
        output_names=["logits"],
        verbose=False,
    )
    size_mb = os.path.getsize(onnx_path) / 1024 / 1024
    print(f"[OK] Exported to '{onnx_path}'  ({size_mb:.2f} MB)")
    print(f"    Input shape  : [batch, {SEQUENCE_LEN}, {INPUT_SIZE}]")
    print(f"    Output shape : [batch, {NUM_CLASSES}]  (raw logits — apply softmax)")
    print(f"    Observe ratio: {observe_ratio} (baked in — re-export to change)")


def verify(onnx_path: str):
    """Run a quick sanity check using onnxruntime."""
    try:
        import onnx
        import onnxruntime as ort
    except ImportError:
        print("[ERROR] pip install onnx onnxruntime")
        sys.exit(1)

    #   Validate the graph                           
    model_proto = onnx.load(onnx_path)
    onnx.checker.check_model(model_proto)
    print(f"[OK] ONNX graph is valid")

    #   Run inference with onnxruntime                     
    sess = ort.InferenceSession(onnx_path,
                                providers=["CPUExecutionProvider"])

    dummy_np = np.random.randn(1, SEQUENCE_LEN, INPUT_SIZE).astype(np.float32)
    logits   = sess.run(["logits"], {"input": dummy_np})[0]

    probs    = np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
    pred_cls = int(probs.argmax())

    CLASS_NAMES = {0: "Safe", 1: "Pre-Violence", 2: "Violence"}

    print(f"[OK] ONNXRuntime inference OK")
    print(f"    Logits : {logits[0].tolist()}")
    print(f"    Probs  : {[f'{p*100:.1f}%' for p in probs[0].tolist()]}")
    print(f"    Pred   : {CLASS_NAMES.get(pred_cls, pred_cls)}")


def compare_outputs(model_path: str, onnx_path: str, observe_ratio: float,
                    n_trials: int = 5, tol: float = 1e-4):
    """
    Compare PyTorch vs ONNX outputs on random inputs to confirm correctness.
    Max absolute difference should be < tol (floating-point rounding only).
    """
    try:
        import onnxruntime as ort
    except ImportError:
        print("[SKIP] onnxruntime not installed — skipping output comparison")
        return

    model   = load_pytorch_model(model_path)
    wrapper = SafeVisionONNX(model, observe_ratio).to(DEVICE)
    wrapper.eval()

    sess    = ort.InferenceSession(onnx_path,
                                   providers=["CPUExecutionProvider"])
    max_diff = 0.0

    for i in range(n_trials):
        x_np  = np.random.randn(2, SEQUENCE_LEN, INPUT_SIZE).astype(np.float32)
        x_pt  = torch.tensor(x_np, device=DEVICE)

        with torch.no_grad():
            pt_out = wrapper(x_pt).numpy()

        ort_out = sess.run(["logits"], {"input": x_np})[0]
        diff    = np.abs(pt_out - ort_out).max()
        max_diff = max(max_diff, diff)

    status = " PASS" if max_diff < tol else " FAIL"
    print(f"[{status}] PyTorch vs ONNX max diff over {n_trials} trials: {max_diff:.2e}"
          f"  (tol={tol})")


#   Entry point                                ─
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export SafeVisionLSTM to ONNX")
    parser.add_argument("--model",   default=MODEL_PATH,
                        help=f"PyTorch weights path (default: {MODEL_PATH})")
    parser.add_argument("--out",     default=ONNX_PATH,
                        help=f"Output .onnx path (default: {ONNX_PATH})")
    parser.add_argument("--observe", type=float, default=OBSERVE_RATIO,
                        help=f"Observe ratio to bake in (default: {OBSERVE_RATIO})")
    parser.add_argument("--verify",  action="store_true",
                        help="Only run verification on an existing .onnx file")
    parser.add_argument("--compare", action="store_true",
                        help="Compare PyTorch vs ONNX outputs after export")
    
    # New security arguments
    parser.add_argument("--encrypt", action="store_true",
                        help="Encrypt the exported ONNX file using model_protection")
    parser.add_argument("--cleanup", action="store_true",
                        help="Remove the plaintext .onnx file after encryption")
    
    args = parser.parse_args()

    if args.verify:
        verify(args.out)
    else:
        export(args.model, args.out, args.observe)
        verify(args.out)
        if args.compare:
            compare_outputs(args.model, args.out, args.observe)
        
        # Handle encryption
        if args.encrypt:
            if not FileEncryptor:
                print("[ERROR] model_protection.py not found. Cannot encrypt.")
                sys.exit(1)
            
            print("\n" + "="*40)
            print(" MODEL PROTECTION")
            print("="*40)
            password = getpass.getpass("Enter encryption password: ")
            if not password:
                print("[ERROR] Password cannot be empty.")
                sys.exit(1)
            
            encryptor = FileEncryptor()
            enc_path = args.out + ".enc"
            print(f"Encrypting {args.out}...")
            encryptor.encrypt_file(args.out, enc_path, password)
            print(f"[OK] Encrypted model saved to: {enc_path}")
            
            if args.cleanup:
                os.remove(args.out)
                print(f"[OK] Plaintext file {args.out} removed.")