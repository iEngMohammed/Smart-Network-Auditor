import csv
import io
import html
from datetime import datetime, timezone
from fpdf import FPDF
from auditor import compliance_score, severity_counts, SEV_ORDER

COLORS = {"critical": (255, 69, 96), "high": (255, 140, 66),
          "medium": (255, 200, 60), "low": (60, 200, 170)}


def _s(t):
    return str(t).encode("latin-1", "replace").decode("latin-1")


def build_csv(violations):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ID", "Severity", "Category", "Issue", "Impact", "Remediation"])
    for v in violations:
        w.writerow([v["id"], v["severity"], v["category_en"], v["en_issue"],
                    v["en_impact"], v["remediation"].replace("\n", " | ")])
    return "\ufeff" + buf.getvalue()


def build_pdf(violations, device, dtype):
    """Formal audit PDF (English, for external auditors)."""
    score, counts = compliance_score(violations), severity_counts(violations)
    pdf = FPDF()
    pdf.set_auto_page_break(True, 15)
    pdf.add_page()
    pdf.set_fill_color(7, 12, 22)
    pdf.rect(0, 0, 210, 38, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_xy(12, 10)
    pdf.cell(0, 10, "CYBERGUARD - Security Compliance Audit Report")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_xy(12, 22)
    pdf.cell(0, 6, _s(f"Asset: {device} ({dtype})   |   Generated: "
                      f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC   |   CONFIDENTIAL"))
    pdf.set_text_color(20, 20, 20)
    pdf.set_xy(12, 46)
    pdf.set_font("Helvetica", "B", 13)
    status = "FAILED" if violations else "PASSED"
    pdf.cell(0, 8, f"Compliance Score: {score}/100   Status: {status}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, "   ".join(f"{k.title()}: {counts[k]}" for k in SEV_ORDER),
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    for i, v in enumerate(violations, 1):
        r, g, b = COLORS[v["severity"]]
        pdf.set_fill_color(r, g, b)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 7, _s(f" #{i}  [{v['id']}]  {v['severity'].upper()}  -  {v['category_en']}"),
                 fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 5.5, _s(f"Issue: {v['en_issue']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 5.5, _s(f"Impact: {v['en_impact']}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Courier", "", 9)
        pdf.set_fill_color(240, 242, 246)
        pdf.multi_cell(0, 5, _s(v["remediation"]), fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)
    if not violations:
        pdf.multi_cell(0, 6, "No violations detected. Asset is fully compliant.")
    return bytes(pdf.output())


def build_html(violations, device, dtype, arabic=False):
    """Standalone HTML evidence report (supports Arabic/RTL)."""
    e = html.escape
    score, counts = compliance_score(violations), severity_counts(violations)
    col = {"critical": "#ff4560", "high": "#ff8c42", "medium": "#ffc83c", "low": "#3cc8aa"}
    rows = ""
    for i, v in enumerate(violations, 1):
        issue = v["ar_issue"] if arabic else v["en_issue"]
        imp = v["ar_impact"] if arabic else v["en_impact"]
        cat = v["category_ar"] if arabic else v["category_en"]
        rows += (f"<section style='border-inline-start:4px solid {col[v['severity']]}'>"
                 f"<h3>#{i} {e(v['id'])} · {v['severity'].upper()} · {e(cat)}</h3>"
                 f"<p>{e(issue)}</p><p><i>{e(imp)}</i></p>"
                 f"<pre>{e(v['remediation'])}</pre></section>")
    d = "rtl" if arabic else "ltr"
    return (f"<!doctype html><html dir='{d}'><meta charset='utf-8'><title>Audit {e(device)}</title>"
            "<style>body{font-family:Segoe UI,Tahoma,sans-serif;background:#05080f;color:#e6edf3;"
            "max-width:860px;margin:30px auto;padding:0 18px}section{background:#0d1420;"
            "padding:12px 16px;margin:12px 0;border-radius:6px}pre{direction:ltr;text-align:left;"
            "background:#000;padding:10px;border-radius:4px;color:#7ee787}</style>"
            f"<h1>CyberGuard Audit Report</h1><p>{e(device)} ({e(dtype)}) · "
            f"{datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC</p>"
            f"<h2>Score: {score}/100 — {'FAILED' if violations else 'PASSED'}</h2>"
            f"<p>{' | '.join(f'{k.title()}: {counts[k]}' for k in SEV_ORDER)}</p>{rows}</html>")
