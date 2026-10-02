import re
import json
from datetime import datetime, timezone

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_WEIGHT = {"critical": 30, "high": 20, "medium": 10, "low": 5}


def _f(fid, sev, cat_en, cat_ar, en_issue, ar_issue, en_impact, ar_impact, fix):
    return {
        "id": fid, "severity": sev,
        "category_en": cat_en, "category_ar": cat_ar,
        "en_issue": en_issue, "ar_issue": ar_issue,
        "en_impact": en_impact, "ar_impact": ar_impact,
        "remediation": fix,
    }


def audit_compliance(config_text, device_type="router"):
    """Rule-based audit aligned with CIS-style hardening controls."""
    v = []
    has = lambda p: re.search(p, config_text, re.MULTILINE | re.IGNORECASE)

    if device_type in ("router", "switch"):
        if has(r"transport input .*telnet"):
            v.append(_f("CIS-NET-01", "high", "Access Control & Encryption", "Access Control و Encryption",
                "Unencrypted Telnet is enabled on VTY lines.",
                "بروتوكول Telnet غير المشفر مفعّل على خطوط VTY.",
                "Credentials and sessions can be sniffed on the network.",
                "يمكن اعتراض بيانات الدخول والجلسات عبر Network Sniffing.",
                "line vty 0 4\n transport input ssh"))
        if not has(r"service password-encryption"):
            v.append(_f("CIS-NET-02", "medium", "Credential Protection", "حماية Credentials",
                "Global password-encryption is disabled.",
                "خاصية service password-encryption غير مفعّلة.",
                "Passwords are stored in clear text in the config file.",
                "تُخزَّن كلمات المرور بنص واضح (Plain Text) داخل ملف الإعدادات.",
                "service password-encryption"))
        if not has(r"enable secret"):
            v.append(_f("CIS-NET-03", "critical", "Privilege Management", "إدارة Privileges",
                "No 'enable secret' is defined for privileged EXEC.",
                "لم يتم تعريف enable secret لوضع Privileged EXEC.",
                "Unauthorized users may gain full administrative access.",
                "إمكانية حصول مستخدمين غير مصرح لهم على صلاحيات Admin كاملة.",
                "enable secret <strong-password>"))
        if has(r"^\s*ip http server") and not has(r"ip http secure-server"):
            v.append(_f("CIS-NET-04", "high", "Web Management Security", "أمن Web Management",
                "HTTP server is enabled without HTTPS.",
                "خادم HTTP مفعّل دون استخدام HTTPS.",
                "Administrative web traffic is exposed in plaintext.",
                "حركة الإدارة عبر الويب مكشوفة بنص واضح.",
                "no ip http server\nip http secure-server"))
        if has(r"snmp-server community (public|private)\b"):
            v.append(_f("CIS-NET-05", "high", "Monitoring Protocol Security", "أمن بروتوكولات Monitoring",
                "Default SNMP community string (public/private) in use.",
                "استخدام SNMP community افتراضية (public/private).",
                "Attackers can read or modify device data via SNMP.",
                "يمكن للمهاجم قراءة أو تعديل بيانات الجهاز عبر SNMP.",
                "no snmp-server community public\nsnmp-server group <name> v3 priv"))
        if not has(r"^\s*logging (host|\d|buffered)"):
            v.append(_f("CIS-NET-06", "low", "Logging & Audit Trail", "Logging و Audit Trail",
                "No remote or buffered logging is configured.",
                "لا يوجد Logging محلي أو عن بعد (Syslog).",
                "Security events cannot be investigated after an incident.",
                "يصعب التحقيق في الحوادث الأمنية لغياب سجل الأحداث.",
                "logging buffered 16384\nlogging host <syslog-ip>"))
        if not has(r"^\s*banner (login|motd)"):
            v.append(_f("CIS-NET-07", "low", "Legal Notice", "الإشعار القانوني",
                "No login banner is configured.",
                "لا توجد Login Banner مُعرّفة.",
                "Weakens legal standing against unauthorized access.",
                "يضعف الموقف القانوني عند الوصول غير المصرح به.",
                "banner login ^Authorized access only^"))

    elif device_type == "server":
        if has(r"^\s*Protocol\s+1\b"):
            v.append(_f("CIS-LNX-01", "critical", "Protocol Hardening", "تشديد Protocol",
                "Legacy SSH Protocol 1 is allowed.",
                "السماح ببروتوكول SSH Protocol 1 القديم.",
                "Known cryptographic weaknesses allow session hijacking.",
                "ثغرات تشفير معروفة تسمح باختطاف الجلسات.",
                "Protocol 2"))
        if has(r"^\s*PermitRootLogin\s+yes"):
            v.append(_f("CIS-LNX-02", "critical", "Remote Access Hardening", "تشديد Remote Access",
                "SSH PermitRootLogin is set to 'yes'.",
                "خاصية PermitRootLogin مضبوطة على yes.",
                "Root account becomes a direct brute-force target.",
                "حساب root يصبح هدفاً مباشراً لهجمات Brute-force.",
                "PermitRootLogin no"))
        if has(r"^\s*PermitEmptyPasswords\s+yes"):
            v.append(_f("CIS-LNX-03", "critical", "Authentication Protocols", "بروتوكولات Authentication",
                "Empty passwords are permitted over SSH.",
                "السماح بكلمات مرور فارغة عبر SSH.",
                "Accounts without passwords can be accessed by anyone.",
                "الحسابات بلا كلمة مرور يمكن لأي شخص الدخول إليها.",
                "PermitEmptyPasswords no"))
        if has(r"^\s*PasswordAuthentication\s+yes"):
            v.append(_f("CIS-LNX-04", "medium", "Authentication Protocols", "بروتوكولات Authentication",
                "SSH Password Authentication is enabled.",
                "مصادقة Password عبر SSH مفعّلة.",
                "Exposed to weak passwords and dictionary attacks.",
                "عرضة لهجمات Dictionary وكلمات المرور الضعيفة.",
                "PasswordAuthentication no"))
        if has(r"^\s*X11Forwarding\s+yes"):
            v.append(_f("CIS-LNX-05", "low", "Attack Surface Reduction", "تقليل Attack Surface",
                "X11 forwarding is enabled.",
                "خاصية X11Forwarding مفعّلة.",
                "Increases attack surface for GUI session hijacking.",
                "تزيد سطح الهجوم عبر اختطاف جلسات GUI.",
                "X11Forwarding no"))
    return v


def severity_counts(violations):
    return {s: sum(1 for x in violations if x["severity"] == s) for s in SEV_ORDER}


def compliance_score(violations):
    penalty = sum(SEV_WEIGHT[x["severity"]] for x in violations)
    return max(0, 100 - penalty)


def generate_audit_report_json(violations, device_name, device_type):
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_device": device_name,
        "asset_type": device_type,
        "total_violations": len(violations),
        "severity_breakdown": severity_counts(violations),
        "compliance_score": compliance_score(violations),
        "compliance_status": "FAILED" if violations else "PASSED",
        "findings": violations,
    }
    return json.dumps(report, indent=4, ensure_ascii=False)
