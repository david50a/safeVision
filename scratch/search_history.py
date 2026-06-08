import json
from pathlib import Path

def search_transcript():
    transcript_path = Path(r"C:\Users\meir\.gemini\antigravity-ide\brain\f63fbce7-88fd-4799-a52b-8dd7eb053f42\.system_generated\logs\transcript.jsonl")
    if not transcript_path.exists():
        print("Transcript log does not exist!")
        return
        
    print("Searching transcript...")
    with open(transcript_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            try:
                step = json.loads(line)
                content = str(step.get("content", ""))
                tool_calls = step.get("tool_calls", [])
                
                # Check content and tool calls for hints
                query_terms = ["password", "key", "master", "prompt", "safevision", "model", "decryption"]
                matched = False
                for term in query_terms:
                    if term.lower() in content.lower():
                        matched = True
                        break
                
                # Also check tool_calls
                for call in tool_calls:
                    args = str(call.get("args", ""))
                    for term in query_terms:
                        if term.lower() in args.lower():
                            matched = True
                            break
                            
                if matched:
                    # Print snippet
                    print(f"--- Step {idx} (type: {step.get('type')}, source: {step.get('source')}) ---")
                    # Limit content print size
                    print(content[:500])
                    if tool_calls:
                        print("Tool calls:", json.dumps(tool_calls)[:500])
            except Exception as e:
                print(f"Error parsing line {idx}: {e}")

if __name__ == "__main__":
    search_transcript()
