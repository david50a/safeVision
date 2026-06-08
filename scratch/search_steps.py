import json
from pathlib import Path

def search_transcript():
    transcript_path = Path(r"C:\Users\meir\.gemini\antigravity-ide\brain\f63fbce7-88fd-4799-a52b-8dd7eb053f42\.system_generated\logs\transcript.jsonl")
    if not transcript_path.exists():
        print("Transcript log does not exist!")
        return
        
    with open(transcript_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if 430 <= idx <= 480:
                try:
                    step = json.loads(line)
                    print(f"=== Step {idx} ===")
                    print(step.get("content", ""))
                    tool_calls = step.get("tool_calls", [])
                    if tool_calls:
                        print("Tool calls:", json.dumps(tool_calls, indent=2))
                except Exception as e:
                    pass

if __name__ == "__main__":
    search_transcript()
