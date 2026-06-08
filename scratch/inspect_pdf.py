from pathlib import Path

def inspect():
    pdf_path = Path("test_report_nokey.pdf")
    if not pdf_path.exists():
        print("test_report_nokey.pdf not found!")
        return
        
    data = pdf_path.read_bytes()
    print(f"File size: {len(data)} bytes")
    
    # Search for known text strings
    queries = [
        b"Visual Evidence",
        b"Snapshot encrypted",
        b"Provide key to view",
        b"Decryption failed",
        b"Error loading snapshot"
    ]
    
    for q in queries:
        count = data.count(q)
        print(f"Found '{q.decode()}' occurrences: {count}")

if __name__ == "__main__":
    inspect()
