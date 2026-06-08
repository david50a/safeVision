import os
import subprocess
import urllib.request
import zipfile
import shutil
import sys

# Configuration
SDK_URL = "https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-win-x64-1.20.1.zip"
# Note: using a slightly older version (1.16.3) because I know the structure and compatibility.
# 1.26.0 might have different dependencies.

SDK_ZIP = "onnxruntime_sdk.zip"
SDK_DIR = "onnxruntime_sdk"
MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_EXE = os.path.join(MODEL_DIR, "safevision_inference.exe")
SOURCE_CPP = os.path.join(MODEL_DIR, "onnx.cpp")

def download_sdk():
    if not os.path.exists(SDK_ZIP):
        print(f"Downloading ONNX Runtime SDK from {SDK_URL}...")
        urllib.request.urlretrieve(SDK_URL, SDK_ZIP)
        print("Download complete.")

def extract_sdk():
    if not os.path.exists(SDK_DIR):
        print("Extracting SDK...")
        with zipfile.ZipFile(SDK_ZIP, 'r') as zip_ref:
            zip_ref.extractall(SDK_DIR)
        print("Extraction complete.")

def find_vcvars():
    search_dirs = [
        r"C:\Program Files\Microsoft Visual Studio",
        r"C:\Program Files (x86)\Microsoft Visual Studio"
    ]
    for base in search_dirs:
        if os.path.exists(base):
            for root, dirs, files in os.walk(base):
                if "vcvars64.bat" in files:
                    return os.path.join(root, "vcvars64.bat")
                if "vcvarsall.bat" in files:
                    return os.path.join(root, "vcvarsall.bat")
    return None

def build():
    # Find the actual directory inside the extracted zip
    inner_dir = os.listdir(SDK_DIR)[0]
    sdk_base = os.path.join(SDK_DIR, inner_dir)
    
    include_dir = os.path.join(sdk_base, "include")
    lib_dir = os.path.join(sdk_base, "lib")
    
    # We need to copy the DLL to the model directory so the EXE can find it
    dll_path = os.path.join(lib_dir, "onnxruntime.dll")
    shutil.copy(dll_path, MODEL_DIR)
    
    print(f"Compiling {SOURCE_CPP}...")
    
    # Try g++ first
    gxx_cmd = [
        "g++", "-std=c++17", "-O3",
        SOURCE_CPP,
        f"-I{include_dir}",
        f"-L{lib_dir}",
        "-lonnxruntime",
        "-o", OUTPUT_EXE
    ]
    
    print(f"Attempting compilation with g++: {' '.join(gxx_cmd)}")
    try:
        result = subprocess.run(gxx_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Build successful with g++! Output: {OUTPUT_EXE}")
            return
        else:
            print("g++ build failed. Output:")
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
    except Exception as e:
        print(f"g++ build error: {e}. Trying MSVC compiler...")
        
    # Fallback to MSVC (cl.exe)
    vcvars = find_vcvars()
    if vcvars:
        print(f"Found MSVC environment script: {vcvars}")
        msvc_cmd = f'call "{vcvars}" && cl /EHsc /O2 /std:c++17 "{SOURCE_CPP}" /I"{include_dir}" /link /LIBPATH:"{lib_dir}" onnxruntime.lib /out:"{OUTPUT_EXE}"'
        print(f"Running compilation with MSVC (cl)...")
        try:
            result = subprocess.run(msvc_cmd, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print(f"Build successful with MSVC! Output: {OUTPUT_EXE}")
                # Clean up temporary MSVC files
                for f in ["onnx.obj", "onnx.pdb"]:
                    if os.path.exists(f):
                        try:
                            os.remove(f)
                        except Exception:
                            pass
                return
            else:
                print("MSVC build failed.")
                print("STDOUT:", result.stdout)
                print("STDERR:", result.stderr)
        except Exception as e:
            print(f"MSVC build error: {e}")
    else:
        print("Visual Studio MSVC compiler script not found.")
    
    print("Compilation failed with all compilers.")
    sys.exit(1)

if __name__ == "__main__":
    try:
        download_sdk()
        extract_sdk()
        build()
    except Exception as e:
        print(f"An error occurred: {e}")
