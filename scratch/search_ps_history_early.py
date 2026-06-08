from pathlib import Path

def search_history():
    history_path = Path(r"C:\Users\meir\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    if not history_path.exists():
        print("History file not found!")
        return
        
    content = history_path.read_text(encoding="utf-8", errors="ignore")
    lines = content.splitlines()
    
    # Search for keywords in lines 0 to 570
    keywords = ["SAFEVISION", "password", "key", "secret", "server.py", "camera.py", "master"]
    for idx in range(min(570, len(lines))):
        line = lines[idx]
        for kw in keywords:
            if kw.lower() in line.lower():
                print(f"Line {idx}: {line}")
                break

if __name__ == "__main__":
    search_history()
