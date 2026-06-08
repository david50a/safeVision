import sys
from pathlib import Path
import datetime

# Add server to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from storage import get_collection
from report_engine import ViolenceReportEngine

def test_generation():
    # Fetch alarms from database
    coll = get_collection("alarms")
    # Let's find alarms with snapshot_path
    alarms = list(coll.find({"snapshot_path": {"$ne": None}}).limit(10))
    print(f"Found {len(alarms)} alarms with snapshots")
    
    # Construct dummy report_data
    report_data = {
        "meta": {
            "from": datetime.datetime.utcnow().isoformat(),
            "to": datetime.datetime.utcnow().isoformat(),
            "camera_id": None,
            "severity": None,
            "generated": datetime.datetime.utcnow().isoformat(),
        },
        "summary": {},
        "by_camera": [],
        "by_hour": [],
        "by_day": [],
        "response_times": {},
        "incidents": alarms
    }
    
    # We try to decrypt with a key. Let's check what keys are in alarms
    # In order to test, let's see if we can run it with no key, and then with a key
    print("Generating PDF with no key...")
    try:
        pdf_bytes = ViolenceReportEngine.export_pdf(report_data, password=None)
        Path("test_report_nokey.pdf").write_bytes(pdf_bytes)
        print("Success! Saved test_report_nokey.pdf")
    except Exception as e:
        print(f"Error without key: {e}")
        
    print("Generating PDF with a dummy/master key...")
    try:
        # We need the master key if they are encrypted. Let's check if they can decrypt.
        # Since we don't know the master key, let's check if the .env or configuration contains it,
        # or if we can guess. Let's pass a dummy password.
        pdf_bytes = ViolenceReportEngine.export_pdf(report_data, password="dummy")
        Path("test_report_dummykey.pdf").write_bytes(pdf_bytes)
        print("Success! Saved test_report_dummykey.pdf")
    except Exception as e:
        print(f"Error with dummy key: {e}")

if __name__ == "__main__":
    test_generation()
