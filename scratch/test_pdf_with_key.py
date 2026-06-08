import sys
from pathlib import Path
import datetime

# Add server to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server"))

from report_engine import ViolenceReportEngine

def test_with_key(password):
    print(f"\n=== Testing PDF with password: '{password}' ===")
    try:
        from_dt = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        report_data = ViolenceReportEngine.get_report_data(from_dt=from_dt)
        
        incidents = report_data.get("incidents", [])
        with_snap = [i for i in incidents if i.get("snapshot_path")]
        print(f"Found {len(incidents)} incidents, {len(with_snap)} have snapshot paths")
        
        if with_snap:
            print(f"Sample snapshot_path: {with_snap[0]['snapshot_path']}")
        
        pdf_bytes = ViolenceReportEngine.export_pdf(report_data, password=password)
        out = f"test_snapshot_{password or 'nokey'}.pdf"
        Path(out).write_bytes(pdf_bytes)
        print(f"SUCCESS — Saved {out} ({len(pdf_bytes):,} bytes)")
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback; traceback.print_exc()

if __name__ == "__main__":
    test_with_key("admin")
