"""
SafeVision — Violence Report Engine
=====================================
Generates structured reports about violence detection events from MongoDB.

Features:
  - Date-range filtering + camera / severity filters
  - Per-camera breakdown, hourly heatmap, daily trend timeline
  - Top incidents list, avg response time (ack latency)
  - CSV export (streaming-friendly)
  - PDF export via reportlab (falls back gracefully if not installed)
"""

from __future__ import annotations

import csv
import datetime
import io
import json
import logging
import os
import tempfile
from typing import Optional
from pathlib import Path
from storage import JsonCollection
from model.model_protection import FileEncryptor

logger = logging.getLogger(__name__)

# ── File-based Storage ───────────────────────────────────────────────────────
_ALARMS_COL = JsonCollection("database/alarms.jsonl")


# Labels that count as violence events (security events excluded)
VIOLENCE_LABELS = {"VIOLENCE", "PRE-VIOLENCE"}


class ViolenceReportEngine:

    # ── Main Query ────────────────────────────────────────────────────────────

    @staticmethod
    def get_report_data(
        from_dt:   Optional[datetime.datetime] = None,
        to_dt:     Optional[datetime.datetime] = None,
        camera_id: Optional[str]               = None,
        severity:  Optional[str]               = None,
        limit:     int                          = 500,
    ) -> dict:
        """
        Query MongoDB alarms and return a rich report dict.
        All datetime objects are serialised to ISO strings before returning.
        """
        from_dt = from_dt or (datetime.datetime.utcnow() - datetime.timedelta(days=30))
        to_dt   = to_dt   or datetime.datetime.utcnow()

        query: dict = {
            "fired_at": {"$gte": from_dt, "$lte": to_dt},
            # Only violence labels — exclude SECURITY:* labels
            "label": {"$in": list(VIOLENCE_LABELS)},
        }
        if camera_id:
            query["camera_id"] = camera_id
        if severity:
            query["severity"]  = severity

        raw = list(
            _ALARMS_COL.find(query, {"_id": 0})
                       .sort("fired_at", -1)
                       .limit(limit)
        )

        # Serialise datetime objects
        incidents = [ViolenceReportEngine._serialise(r) for r in raw]

        return {
            "meta": {
                "from":      from_dt.isoformat(),
                "to":        to_dt.isoformat(),
                "camera_id": camera_id,
                "severity":  severity,
                "generated": datetime.datetime.utcnow().isoformat(),
            },
            "summary":       ViolenceReportEngine._summary(raw, from_dt, to_dt),
            "by_camera":     ViolenceReportEngine._by_camera(raw),
            "by_hour":       ViolenceReportEngine._by_hour(raw),
            "by_day":        ViolenceReportEngine._by_day(raw, from_dt, to_dt),
            "response_times":ViolenceReportEngine._response_times(raw),
            "incidents":     incidents,
        }

    # ── Aggregations ──────────────────────────────────────────────────────────

    @staticmethod
    def _summary(raw: list[dict], from_dt, to_dt) -> dict:
        total     = len(raw)
        critical  = sum(1 for r in raw if r.get("severity") == "CRITICAL")
        warning   = total - critical
        active    = sum(1 for r in raw if r.get("state") == "ACTIVE")
        acked     = sum(1 for r in raw if r.get("state") == "ACKNOWLEDGED")
        dismissed = sum(1 for r in raw if r.get("state") == "DISMISSED")
        sms_count = sum(1 for r in raw if r.get("sms_sent"))
        email_count = sum(1 for r in raw if r.get("email_sent"))
        cameras   = len({r.get("camera_id", "") for r in raw})
        avg_prob  = (
            round(sum(r.get("probability", 0) for r in raw) / total, 3)
            if total else 0
        )

        # Peak hour
        hour_counts: dict[int, int] = {}
        for r in raw:
            dt = r.get("fired_at")
            if isinstance(dt, datetime.datetime):
                h = dt.hour
                hour_counts[h] = hour_counts.get(h, 0) + 1
        peak_hour = max(hour_counts, key=hour_counts.get) if hour_counts else None

        # Peak camera
        cam_counts: dict[str, int] = {}
        for r in raw:
            c = r.get("camera_id", "unknown")
            cam_counts[c] = cam_counts.get(c, 0) + 1
        peak_camera = max(cam_counts, key=cam_counts.get) if cam_counts else None

        days_in_range = max(1, (to_dt - from_dt).days)

        return {
            "total":        total,
            "critical":     critical,
            "warning":      warning,
            "active":       active,
            "acknowledged": acked,
            "dismissed":    dismissed,
            "sms_sent":     sms_count,
            "email_sent":   email_count,
            "cameras_affected": cameras,
            "avg_probability":  avg_prob,
            "peak_hour":        peak_hour,
            "peak_camera":      peak_camera,
            "incidents_per_day": round(total / days_in_range, 2),
        }

    @staticmethod
    def _by_camera(raw: list[dict]) -> list[dict]:
        cams: dict[str, dict] = {}
        for r in raw:
            cam = r.get("camera_id", "unknown")
            loc = r.get("location", "—")
            if cam not in cams:
                cams[cam] = {
                    "camera_id": cam,
                    "location":  loc,
                    "total":     0,
                    "critical":  0,
                    "warning":   0,
                    "avg_probability": 0.0,
                    "_probs":    [],
                }
            cams[cam]["total"]    += 1
            cams[cam]["_probs"].append(r.get("probability", 0))
            if r.get("severity") == "CRITICAL":
                cams[cam]["critical"] += 1
            else:
                cams[cam]["warning"]  += 1
        result = []
        for cam in cams.values():
            probs = cam.pop("_probs")
            cam["avg_probability"] = round(sum(probs) / len(probs), 3) if probs else 0
            result.append(cam)
        return sorted(result, key=lambda x: x["total"], reverse=True)

    @staticmethod
    def _by_hour(raw: list[dict]) -> list[dict]:
        counts = [{"hour": h, "label": f"{h:02d}:00", "count": 0} for h in range(24)]
        for r in raw:
            dt = r.get("fired_at")
            if isinstance(dt, datetime.datetime):
                counts[dt.hour]["count"] += 1
        return counts

    @staticmethod
    def _by_day(raw: list[dict], from_dt: datetime.datetime, to_dt: datetime.datetime) -> list[dict]:
        days: dict[str, dict] = {}
        current = from_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        end     = to_dt.replace(hour=0, minute=0, second=0, microsecond=0)
        while current <= end:
            key = current.strftime("%Y-%m-%d")
            days[key] = {"date": key, "total": 0, "critical": 0, "warning": 0}
            current += datetime.timedelta(days=1)
        for r in raw:
            dt = r.get("fired_at")
            if isinstance(dt, datetime.datetime):
                key = dt.strftime("%Y-%m-%d")
                if key in days:
                    days[key]["total"] += 1
                    if r.get("severity") == "CRITICAL":
                        days[key]["critical"] += 1
                    else:
                        days[key]["warning"]  += 1
        return list(days.values())

    @staticmethod
    def _response_times(raw: list[dict]) -> dict:
        """Average time (seconds) from alarm fired to acknowledged."""
        ack_times = []
        for r in raw:
            fired = r.get("fired_at")
            ack   = r.get("ack_at")
            if isinstance(fired, datetime.datetime) and isinstance(ack, datetime.datetime):
                ack_times.append((ack - fired).total_seconds())
        if not ack_times:
            return {"avg_seconds": None, "min_seconds": None, "max_seconds": None, "count": 0}
        return {
            "avg_seconds": round(sum(ack_times) / len(ack_times), 1),
            "min_seconds": round(min(ack_times), 1),
            "max_seconds": round(max(ack_times), 1),
            "count":       len(ack_times),
        }

    # ── Exports ───────────────────────────────────────────────────────────────

    @staticmethod
    def export_csv(report_data: dict) -> str:
        """Return a CSV string of the incidents list."""
        buf = io.StringIO()
        fieldnames = [
            "alarm_id", "fired_at", "severity", "label", "camera_id",
            "location", "probability", "state", "sms_sent",
            "notified_guards", "ack_at", "dismiss_at",
        ]
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for inc in report_data.get("incidents", []):
            row = {k: inc.get(k, "") for k in fieldnames}
            if isinstance(row.get("notified_guards"), list):
                row["notified_guards"] = "; ".join(row["notified_guards"])
            writer.writerow(row)
        return buf.getvalue()

    @staticmethod
    def export_pdf(report_data: dict, password: Optional[str] = None) -> bytes:
        """Generate a PDF report. Requires `reportlab`."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image
            )
        except ImportError:
            raise RuntimeError("Install reportlab: pip install reportlab")

        buf  = io.BytesIO()
        doc  = SimpleDocTemplate(buf, pagesize=A4,
                                  leftMargin=2*cm, rightMargin=2*cm,
                                  topMargin=2*cm, bottomMargin=2*cm)
        
        # ── Setup Encryption ───────────────────────────────────────────────
        canvas_kwargs = {}
        if password:
            from reportlab.pdfgen import canvas
            # We use a lambda to pass the encrypt argument to the canvas constructor
            canvas_kwargs['canvasmaker'] = lambda *args, **kwargs: canvas.Canvas(*args, encrypt=password, **kwargs)

        styles = getSampleStyleSheet()
        elems  = []

        # ── Logo & Title ───────────────────────────────────────────────────
        logo_path = Path(__file__).resolve().parent.parent / "logo.png"
        
        title_style = ParagraphStyle("title",
            parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#dc2626"),
            alignment=0) # Left align to make room for logo

        header_data = []
        title_para = Paragraph("SafeVision — Violence Incident Report", title_style)
        
        if logo_path.exists():
            img = Image(str(logo_path), width=2.5*cm, height=2.5*cm)
            header_data = [[img, title_para]]
        else:
            header_data = [[title_para]]

        header_table = Table(header_data, colWidths=[3*cm, 14*cm] if len(header_data[0]) > 1 else [17*cm])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
        ]))
        elems.append(header_table)
        elems.append(Spacer(1, 0.3*cm))


        meta = report_data.get("meta", {})
        elems.append(Paragraph(
            f"Period: <b>{meta.get('from','')[:10]}</b> → <b>{meta.get('to','')[:10]}</b>  "
            f"| Generated: <b>{meta.get('generated','')[:19]}</b>",
            styles["Normal"]))
        elems.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#dc2626")))
        elems.append(Spacer(1, 0.4*cm))

        # ── Summary ────────────────────────────────────────────────────────
        s = report_data.get("summary", {})
        elems.append(Paragraph("Executive Summary", styles["Heading2"]))
        summary_data = [
            ["Metric", "Value"],
            ["Total Incidents",         str(s.get("total", 0))],
            ["Critical",                str(s.get("critical", 0))],
            ["Warning",                 str(s.get("warning", 0))],
            ["Cameras Affected",        str(s.get("cameras_affected", 0))],
            ["SMS Alerts Sent",         str(s.get("sms_sent", 0))],
            ["Email Alerts Sent",       str(s.get("email_sent", 0))],
            ["Avg Probability",         f"{s.get('avg_probability',0):.1%}"],
            ["Incidents / Day",         str(s.get("incidents_per_day", 0))],
            ["Peak Hour",               f"{s.get('peak_hour','—'):02}:00" if s.get("peak_hour") is not None else "—"],
            ["Peak Camera",             str(s.get("peak_camera", "—"))],
            ["Avg Ack Time",            f"{report_data.get('response_times',{}).get('avg_seconds','—')} s"],
        ]
        t = Table(summary_data, colWidths=[7*cm, 10*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#dc2626")),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9fafb"), colors.white]),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("PADDING",     (0, 0), (-1, -1), 6),
        ]))
        elems.append(t)
        elems.append(Spacer(1, 0.5*cm))

        # ── By Camera ─────────────────────────────────────────────────────
        elems.append(Paragraph("Breakdown by Camera", styles["Heading2"]))
        cam_data = [["Camera", "Location", "Total", "Critical", "Warning", "Avg Prob"]]
        for cam in report_data.get("by_camera", []):
            cam_data.append([
                cam.get("camera_id", "—"),
                cam.get("location", "—"),
                str(cam.get("total", 0)),
                str(cam.get("critical", 0)),
                str(cam.get("warning", 0)),
                f"{cam.get('avg_probability',0):.1%}",
            ])
        if len(cam_data) > 1:
            ct = Table(cam_data, colWidths=[3*cm, 5*cm, 2*cm, 2.5*cm, 2.5*cm, 2*cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9fafb"), colors.white]),
                ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("FONTSIZE",    (0, 0), (-1, -1), 9),
                ("PADDING",     (0, 0), (-1, -1), 5),
            ]))
            elems.append(ct)
        else:
            elems.append(Paragraph("No incidents in this period.", styles["Normal"]))
        elems.append(Spacer(1, 0.5*cm))

        # ── Incident Log ──────────────────────────────────────────────────
        elems.append(Paragraph("Incident Log (latest 50)", styles["Heading2"]))
        inc_data = [["Time (UTC)", "Camera", "Label", "Severity", "Prob", "State"]]
        for inc in report_data.get("incidents", [])[:50]:
            inc_data.append([
                str(inc.get("fired_at", ""))[:16],
                inc.get("camera_id", "—"),
                inc.get("label", "—"),
                inc.get("severity", "—"),
                f"{float(inc.get('probability',0)):.1%}",
                inc.get("state", "—"),
            ])
        if len(inc_data) > 1:
            it = Table(inc_data, colWidths=[3.5*cm, 3*cm, 3*cm, 2.5*cm, 2*cm, 3*cm])
            it.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#f9fafb"), colors.white]),
                ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                ("FONTSIZE",    (0, 0), (-1, -1), 8),
                ("PADDING",     (0, 0), (-1, -1), 4),
            ]))
            elems.append(it)
        else:
            elems.append(Paragraph("No incidents in this period.", styles["Normal"]))

        # ── Visual Evidence (Snapshots) ────────────────────────────────────
        # Only show for critical or the most recent ones to keep report size sane
        snapshots = [inc for inc in report_data.get("incidents", []) if inc.get("snapshot_path")]
        if snapshots:
            elems.append(Spacer(1, 1.0*cm))
            elems.append(Paragraph("Visual Evidence (Incident Snapshots)", styles["Heading2"]))
            
            base_dir = Path(__file__).resolve().parent
            encryptor = FileEncryptor()
            temp_files = []
            
            for i, inc in enumerate(snapshots[:10]): # Limit to latest 10 for report size
                snap_rel = inc.get("snapshot_path")
                snap_path = base_dir / snap_rel
                
                # Decrypt if necessary
                current_img_path = str(snap_path)
                is_encrypted = snap_rel.endswith(".enc")
                
                if is_encrypted:
                    if not password:
                        logger.warning(f"Snapshot {snap_rel} is encrypted but no password provided.")
                        elems.append(Paragraph(f"<i>[Snapshot encrypted - Provide key to view]</i>", styles["Normal"]))
                        continue
                    
                    try:
                        fd, temp_path = tempfile.mkstemp(suffix=".png")
                        os.close(fd)
                        if encryptor.decrypt_file(str(snap_path), temp_path, password):
                            current_img_path = temp_path
                            temp_files.append(temp_path)
                        else:
                            raise RuntimeError("Decryption failed")
                    except Exception as e:
                        logger.error(f"Failed to decrypt snapshot {snap_rel}: {e}")
                        elems.append(Paragraph(f"<i>[Decryption failed for snapshot {snap_rel}: {e}]</i>", styles["Normal"]))
                        continue

                if os.path.exists(current_img_path):
                    try:
                        # Add metadata for the snapshot
                        time_str = str(inc.get("fired_at", ""))[:19].replace("T", " ")
                        cam_id = inc.get("camera_id", "—")
                        label = inc.get("label", "—")
                        
                        elems.append(Paragraph(
                            f"<b>Incident {i+1}:</b> {time_str} | Camera: {cam_id} | Type: {label}",
                            styles["Normal"]
                        ))
                        elems.append(Spacer(1, 0.2*cm))
                        
                        # Add the image - resize to fit page width (roughly 15cm)
                        img = Image(current_img_path, width=15*cm, height=9*cm)
                        img.hAlign = 'CENTER'
                        elems.append(img)
                        elems.append(Spacer(1, 0.8*cm))
                        
                        # Add page break after every 2 snapshots to keep it clean
                        if (i + 1) % 2 == 0 and i < len(snapshots) - 1:
                            from reportlab.platypus import PageBreak
                            elems.append(PageBreak())
                            
                    except Exception as e:
                        logger.error(f"Failed to add snapshot to PDF: {e}")
                        elems.append(Paragraph(f"<i>[Error loading snapshot {snap_rel}: {e}]</i>", styles["Normal"]))

            # ── Build & Cleanup ──────────────────────────────────────────
            try:
                doc.build(elems, **canvas_kwargs)
            finally:
                # Securely delete temp files
                for tf in temp_files:
                    try:
                        if os.path.exists(tf):
                            os.remove(tf)
                    except Exception:
                        pass
        else:
            doc.build(elems, **canvas_kwargs)

        return buf.getvalue()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _serialise(doc: dict) -> dict:
        """Convert datetime objects in a MongoDB document to ISO strings."""
        out = {}
        for k, v in doc.items():
            if isinstance(v, datetime.datetime):
                out[k] = v.isoformat()
            elif isinstance(v, list):
                out[k] = [i.isoformat() if isinstance(i, datetime.datetime) else i for i in v]
            else:
                out[k] = v
        return out
