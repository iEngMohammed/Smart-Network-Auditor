import streamlit as st
from dotenv import load_dotenv
from auditor import (audit_compliance, severity_counts, compliance_score,
                     generate_audit_report_json, SEV_ORDER)
from report import build_pdf, build_html, build_csv

load_dotenv()
st.set_page_config(page_title="CyberGuard Enterprise", page_icon="🛡", layout="wide")

SEV_COL = {"critical": "#ff4560", "high": "#ff8c42", "medium": "#ffc83c", "low": "#3cc8aa"}
ICON = {  # inline SVG icons (stroke = currentColor)
    "shield": '<path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z"/><path d="M9 12l2 2 4-4"/>',
    "alert": '<path d="M12 3l10 18H2z"/><path d="M12 10v5M12 18h.01"/>',
    "file": '<path d="M6 2h9l5 5v15H6z"/><path d="M14 2v6h6M9 13h6M9 17h6"/>',
    "chart": '<path d="M4 20V4M4 20h16"/><path d="M8 16v-5M12 16V8M16 16v-3"/>',
    "server": '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 7h.01M7 17h.01"/>',
    "dl": '<path d="M12 3v12M7 11l5 5 5-5M4 21h16"/>',
}


def svg(name, size=20, color="currentColor"):
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="{color}" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">{ICON[name]}</svg>')


T = {
    "en": {
        "title": "CyberGuard Enterprise", "sub": "Security & Compliance Operations Center",
        "lang": "Display language", "asset": "Asset category", "src": "Configuration source",
        "assets": ["Cisco Router / Switch (IOS)", "Production Linux Server"],
        "srcs": ["Standard vulnerability samples", "Upload config file"],
        "upload": "Choose config file (.cfg / .conf / .txt)", "preview": "Configuration preview",
        "analysis": "Risk & compliance analytics", "run": "Run security audit",
        "spin": "Analyzing configuration...", "score": "Compliance score",
        "total": "Total findings", "status": "Status", "fail": "FAILED", "pass": "PASSED",
        "dist": "Risk distribution by severity", "findings": "Findings & remediation",
        "desc": "Description", "impact": "Security impact", "fix": "Recommended fix",
        "ok": "The asset is fully compliant. No violations found.",
        "empty": "Select a sample or upload a configuration file from the sidebar to begin.",
        "export": "Audit evidence & export", "lines": "lines", "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
        "hint": "Run the audit to see the analytics dashboard.", "cat": "category_en", "iss": "en_issue", "imp": "en_impact",
        "dir": "ltr",
    },
    "ar": {
        "title": "CyberGuard Enterprise", "sub": "مركز عمليات Security & Compliance",
        "lang": "لغة العرض", "asset": "تصنيف Asset", "src": "مصدر ملف Configuration",
        "assets": ["Cisco Router / Switch (IOS)", "Production Linux Server"],
        "srcs": ["نماذج Vulnerability جاهزة", "رفع ملف Configuration"],
        "upload": "اختر ملف Config (.cfg / .conf / .txt)", "preview": "معاينة ملف Configuration",
        "analysis": "تحليلات Risk و Compliance", "run": "بدء Security Audit",
        "spin": "جاري تحليل Configuration...", "score": "نسبة Compliance",
        "total": "إجمالي Findings", "status": "الحالة", "fail": "FAILED", "pass": "PASSED",
        "dist": "توزيع Risk حسب Severity", "findings": "Findings و Remediation",
        "desc": "الوصف", "impact": "التأثير الأمني", "fix": "أوامر الإصلاح",
        "ok": "الجهاز مطابق بالكامل لمعايير Compliance. لا توجد مخالفات.",
        "empty": "اختر نموذجاً أو ارفع ملف Configuration من القائمة الجانبية للبدء.",
        "export": "Audit Evidence والتصدير", "lines": "سطر", "sev": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"},
        "hint": "ابدأ الـ Audit لعرض لوحة التحليلات.", "cat": "category_ar", "iss": "ar_issue", "imp": "ar_impact",
        "dir": "rtl",
    },
}

st.sidebar.markdown("**🌐 Language / اللغة**")
lang_pick = st.sidebar.selectbox("lang", ("English", "العربية"), label_visibility="collapsed")
L = "ar" if lang_pick == "العربية" else "en"
t = T[L]
rtl = t["dir"] == "rtl"

st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;500;700&family=JetBrains+Mono:wght@400;600&display=swap');
:root{{--bg:#030508;--line:rgba(80,140,255,.22);--cyan:#38bdf8;--green:#34d399}}
.stApp{{background-color:var(--bg);
 background-image:radial-gradient(circle at 15% 0%,rgba(56,189,248,.10),transparent 40%),
 radial-gradient(circle at 90% 10%,rgba(52,211,153,.07),transparent 35%),
 linear-gradient(rgba(80,140,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(80,140,255,.05) 1px,transparent 1px);
 background-size:100% 100%,100% 100%,42px 42px,42px 42px;color:#e6edf3;
 font-family:'IBM Plex Sans Arabic','Segoe UI',sans-serif}}
header[data-testid="stHeader"]{{background:transparent}}
[data-testid="stSidebar"]{{background:rgba(8,12,20,.92);border-inline-end:1px solid var(--line)}}
.block-container{{direction:{t['dir']};padding-top:2rem;max-width:1500px}}
[data-testid="stSidebar"] *{{direction:{t['dir']}}}
pre,code,.stCode{{direction:ltr!important;text-align:left!important;font-family:'JetBrains Mono',monospace!important}}
.cg-head{{display:flex;align-items:center;gap:14px;margin-bottom:6px}}
.cg-logo{{width:48px;height:48px;border-radius:12px;display:grid;place-items:center;color:var(--cyan);
 background:linear-gradient(135deg,rgba(56,189,248,.18),rgba(52,211,153,.12));border:1px solid var(--line);
 box-shadow:0 0 22px rgba(56,189,248,.25)}}
.cg-title{{font-size:28px;font-weight:700;letter-spacing:.3px;margin:0;
 background:linear-gradient(90deg,#7dd3fc,#34d399);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.cg-sub{{color:#8b9bb4;font-size:14px;margin:0}}
.cg-live{{margin-inline-start:auto;font-size:12px;color:var(--green);border:1px solid rgba(52,211,153,.35);
 padding:4px 12px;border-radius:99px;background:rgba(52,211,153,.08)}}
.glass{{background:linear-gradient(145deg,rgba(18,26,42,.72),rgba(10,15,26,.60));backdrop-filter:blur(14px);
 border:1px solid var(--line);border-radius:14px;padding:16px 18px;box-shadow:0 8px 32px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.04)}}
.sec{{display:flex;align-items:center;gap:10px;font-size:17px;font-weight:600;margin:6px 0 12px;color:#cfe3ff}}
.mc-label{{color:#8b9bb4;font-size:13px;display:flex;align-items:center;gap:8px}}
.mc-val{{font-size:30px;font-weight:700;margin-top:6px;font-family:'JetBrains Mono',monospace}}
.bar-row{{display:flex;align-items:center;gap:12px;margin:10px 0;font-size:13px}}
.bar-name{{width:72px;color:#aab8cf}}
.bar-track{{flex:1;height:12px;background:rgba(255,255,255,.06);border-radius:99px;overflow:hidden}}
.bar-fill{{height:100%;border-radius:99px}}
.bar-n{{width:24px;text-align:end;font-family:'JetBrains Mono',monospace}}
.pill{{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600;margin-inline-end:8px}}
.stButton>button{{background:linear-gradient(90deg,#0ea5e9,#10b981);color:#04121a;font-weight:700;border:0;
 border-radius:10px;padding:.65rem 1rem;box-shadow:0 0 24px rgba(14,165,233,.35)}}
.stButton>button:hover{{filter:brightness(1.1);color:#04121a}}
.stDownloadButton>button{{background:rgba(18,26,42,.8);color:#cfe3ff;border:1px solid var(--line);border-radius:10px}}
.stDownloadButton>button:hover{{border-color:var(--cyan);color:#fff;box-shadow:0 0 16px rgba(56,189,248,.3)}}
[data-testid="stExpander"]{{background:rgba(14,20,32,.7);border:1px solid var(--line);border-radius:12px}}
@media (max-width:900px){{.mc-val{{font-size:24px}}}}
</style>""", unsafe_allow_html=True)

st.markdown(
    f'<div class="cg-head"><div class="cg-logo">{svg("shield", 28)}</div><div>'
    f'<p class="cg-title">{t["title"]}</p><p class="cg-sub">{t["sub"]}</p></div>'
    f'<span class="cg-live">● LIVE</span></div>', unsafe_allow_html=True)

asset = st.sidebar.selectbox(t["asset"], t["assets"])
source = st.sidebar.selectbox(t["src"], t["srcs"])
dtype = "router" if asset == t["assets"][0] else "server"

SAMPLES = {
    "router": ("Cisco-Core-Router-Prod",
               "version 16.9\nservice timestamps debug datetime msec\n!\nhostname Cisco-Core-Router-Prod\n!\n"
               "ip routing\nip http server\nsnmp-server community public RO\n!\nline vty 0 4\n"
               " transport input telnet\n login\n!\nend"),
    "server": ("Linux-Ubuntu-Prod-Server",
               "# /etc/ssh/sshd_config\nProtocol 2\nPermitRootLogin yes\nPasswordAuthentication yes\n"
               "PermitEmptyPasswords no\nX11Forwarding yes\n"),
}
config, device = "", "Unknown-Asset"
if source == t["srcs"][0]:
    device, config = SAMPLES[dtype]
else:
    up = st.sidebar.file_uploader(t["upload"], type=["cfg", "conf", "txt"])
    if up is not None:
        config, device = up.read().decode("utf-8", errors="replace"), up.name

if not config:
    st.info(t["empty"])
    st.stop()

# reset stored results when the target changes
key = (device, dtype, hash(config))
if st.session_state.get("key") != key:
    st.session_state["key"], st.session_state["res"] = key, None

left, right = st.columns(2, gap="large")

with left:
    st.markdown(f'<div class="sec">{svg("file")} {t["preview"]} — {device} '
                f'<span class="pill" style="background:rgba(56,189,248,.15);color:#7dd3fc">'
                f'{len(config.splitlines())} {t["lines"]}</span></div>', unsafe_allow_html=True)
    st.code(config, language="text", line_numbers=True)

with right:
    st.markdown(f'<div class="sec">{svg("chart")} {t["analysis"]}</div>', unsafe_allow_html=True)
    if st.button(t["run"], use_container_width=True):
        with st.spinner(t["spin"]):
            st.session_state["res"] = audit_compliance(config, device_type=dtype)
    res = st.session_state.get("res")

    if res is None:
        st.markdown(f'<div class="glass" style="color:#8b9bb4">{t["hint"]}</div>', unsafe_allow_html=True)
    else:
        score, counts = compliance_score(res), severity_counts(res)
        scol = "#34d399" if score >= 80 else "#ffc83c" if score >= 50 else "#ff4560"
        circ = 2 * 3.14159 * 54
        gauge = (f'<svg width="150" height="150" viewBox="0 0 140 140"><circle cx="70" cy="70" r="54" fill="none" '
                 f'stroke="rgba(255,255,255,.07)" stroke-width="12"/><circle cx="70" cy="70" r="54" fill="none" '
                 f'stroke="{scol}" stroke-width="12" stroke-linecap="round" stroke-dasharray="{circ*score/100:.1f} {circ:.1f}" '
                 f'transform="rotate(-90 70 70)" style="filter:drop-shadow(0 0 8px {scol})"/>'
                 f'<text x="70" y="76" text-anchor="middle" fill="#fff" font-size="30" font-weight="700" '
                 f'font-family="JetBrains Mono">{score}%</text></svg>')
        status = t["fail"] if res else t["pass"]
        stcol = "#ff4560" if res else "#34d399"
        st.markdown(
            f'<div class="glass" style="display:flex;align-items:center;gap:22px;flex-wrap:wrap">{gauge}'
            f'<div style="flex:1;min-width:180px"><div class="mc-label">{svg("shield",18)} {t["score"]}</div>'
            f'<div class="mc-val" style="color:{scol}">{score}/100</div>'
            f'<div class="mc-label" style="margin-top:10px">{svg("alert",18)} {t["total"]}: '
            f'<b style="color:#fff">{len(res)}</b></div>'
            f'<div style="margin-top:10px"><span class="pill" style="background:{stcol}22;color:{stcol};'
            f'border:1px solid {stcol}66">{t["status"]}: {status}</span></div></div></div>',
            unsafe_allow_html=True)

        cards = "".join(
            f'<div class="glass" style="flex:1;min-width:110px;border-color:{SEV_COL[s]}55;'
            f'box-shadow:0 0 18px {SEV_COL[s]}22"><div class="mc-label" style="color:{SEV_COL[s]}">'
            f'{svg("alert",16)} {t["sev"][s]}</div><div class="mc-val">{counts[s]}</div></div>' for s in SEV_ORDER)
        st.markdown(f'<div style="display:flex;gap:10px;flex-wrap:wrap;margin:12px 0">{cards}</div>',
                    unsafe_allow_html=True)

        mx = max(max(counts.values()), 1)
        bars = "".join(
            f'<div class="bar-row"><span class="bar-name">{t["sev"][s]}</span><div class="bar-track">'
            f'<div class="bar-fill" style="width:{counts[s]/mx*100:.0f}%;background:linear-gradient(90deg,'
            f'{SEV_COL[s]}99,{SEV_COL[s]});box-shadow:0 0 10px {SEV_COL[s]}88"></div></div>'
            f'<span class="bar-n">{counts[s]}</span></div>' for s in SEV_ORDER)
        st.markdown(f'<div class="glass"><div class="sec" style="margin-top:0">{svg("chart")} {t["dist"]}</div>'
                    f'{bars}</div>', unsafe_allow_html=True)

if st.session_state.get("res") is not None:
    res = st.session_state["res"]
    st.markdown(f'<div class="sec" style="margin-top:28px">{svg("server")} {t["findings"]}</div>',
                unsafe_allow_html=True)
    if not res:
        st.success(t["ok"])
    for i, v in enumerate(res, 1):
        c = SEV_COL[v["severity"]]
        with st.expander(f'#{i}  [{v["id"]}]  {v[t["cat"]]}  —  {t["sev"][v["severity"]]}'):
            st.markdown(f'<span class="pill" style="background:{c}22;color:{c};border:1px solid {c}66">'
                        f'{t["sev"][v["severity"]]}</span>', unsafe_allow_html=True)
            st.markdown(f'**{t["desc"]}:** {v[t["iss"]]}')
            st.markdown(f'**{t["impact"]}:** {v[t["imp"]]}')
            st.markdown(f'**{t["fix"]}:**')
            st.code(v["remediation"], language="bash")

    st.markdown(f'<div class="sec" style="margin-top:28px">{svg("dl")} {t["export"]}</div>',
                unsafe_allow_html=True)
    safe = device.replace(" ", "_")
    e1, e2, e3, e4 = st.columns(4)
    e1.download_button("PDF (Auditor)", build_pdf(res, device, dtype), f"audit_{safe}.pdf",
                       "application/pdf", use_container_width=True)
    e2.download_button("JSON (Evidence)", generate_audit_report_json(res, device, dtype),
                       f"audit_{safe}.json", "application/json", use_container_width=True)
    e3.download_button("HTML Report", build_html(res, device, dtype, arabic=rtl),
                       f"audit_{safe}.html", "text/html", use_container_width=True)
    e4.download_button("CSV (Excel)", build_csv(res), f"audit_{safe}.csv", "text/csv",
                       use_container_width=True)
