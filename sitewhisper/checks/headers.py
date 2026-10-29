"""فحص رؤوس الأمان (Security Headers)."""

from typing import Any

# (اسم الرأس، التوصية العربية عند غيابه)
HEADERS = [
    ("strict-transport-security", "HSTS — يمنع الاتصال عبر HTTP ويكسر هجمات SSL-stripping."),
    ("content-security-policy", "CSP — خط الدفاع الأول ضد XSS وحقن الموارد."),
    ("x-frame-options", "يمنع تضمين موقعك داخل iframe (clickjacking)."),
    ("x-content-type-options", "يجب أن يكون nosniff — يمنع تخمين نوع الملف."),
    ("referrer-policy", "يقلل تسريب بيانات التصفح إلى مواقع خارجية."),
    ("permissions-policy", "يقيد الوصول إلى الميزات الحساسة (كاميرا، ميكروفون، موقع)."),
    ("cross-origin-opener-policy", "يعزل نافذة التصفح عن النوافذ الخبيثة."),
    ("cross-origin-resource-policy", "يمنع تحميل مواردك من مواقع أخرى."),
]


def check_headers(headers: dict[str, str]) -> dict[str, Any]:
    """يفحص الرؤوس المُستلَمة ويعيد بنية موحدة للتقارير.

    headers: dict بأسماء مفاتيح صغيرة (lowercase) كما يعيدها requests.
    """
    lowered = {k.lower(): v for k, v in headers.items()}

    found: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []

    for name, hint in HEADERS:
        value = lowered.get(name)
        if value:
            found.append({"name": name, "value": value, "hint": hint})
        else:
            missing.append({"name": name, "hint": hint})

    return {
        "ok": len(missing) == 0,
        "found": found,
        "missing": missing,
        "score": len(found),
        "total": len(HEADERS),
    }
