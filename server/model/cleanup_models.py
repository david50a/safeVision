import os
import sys
from pathlib import Path

def cleanup():
    model_dir = Path(__file__).parent
    print(f"Scanning for unprotected models in: {model_dir.absolute()}")
    
    # Files to check
    extensions = ['.pt', '.onnx', '.pth']
    candidates = []
    
    for file in model_dir.glob("*"):
        if file.suffix in extensions:
            enc_file = file.with_suffix(file.suffix + ".enc")
            if enc_file.exists():
                candidates.append((file, enc_file))
    
    if not candidates:
        print("No plaintext models with encrypted counterparts found.")
        return

    print(f"\nFound {len(candidates)} candidates for cleanup:")
    for pt, enc in candidates:
        size_mb = pt.stat().st_size / 1024 / 1024
        print(f" [!] {pt.name} ({size_mb:.2f} MB) -> Protected by {enc.name}")

    print("\nWARNING: This will permanently delete the plaintext files listed above.")
    confirm = input("Do you want to proceed with deletion? (y/N): ").lower()
    
    if confirm == 'y':
        for pt, _ in candidates:
            try:
                os.remove(pt)
                print(f" [✓] Deleted: {pt.name}")
            except Exception as e:
                print(f" [✗] Failed to delete {pt.name}: {e}")
        print("\nCleanup complete.")
    else:
        print("\nCleanup cancelled.")

if __name__ == "__main__":
    cleanup()
