"""توليد التقارير: نص للطرفية + HTML."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape


TEMPLATE_DIR = Path(__file__).parent / "templates"


def _make_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _build_summary(results: dict[str, Any]) -> dict[str, Any]:
    """يحسب النتيجة الكلية والتصنيف النصي."""
    scores = [
        (results["headers"]["score"], results["headers"]["total"]),
        (results["email"]["score"], results["email"]["total"]),
        (1 if results["tls"]["ok"] else 0, 1),
    ]
    earned = sum(s for s, _ in scores)
    possible = sum(t for _, t in scores)
    percent = round(earned * 100 / possible) if possible else 0

    if percent >= 90:
        grade = "ممتاز"
    elif percent >= 70:
        grade = "جيد"
    elif percent >= 50:
        grade = "متوسط"
    else:
        grade = "ضعيف"

    return {
        "earned": earned,
        "possible": possible,
        "percent": percent,
        "grade": grade,
    }


def _ok(flag: bool) -> str:
    return "✅" if flag else "❌"


def render_terminal(domain: str, results: dict[str, Any]) -> str:
    """يبني تقريرًا نصيًا بالعربية للطرفية."""
    lines: list[str] = []
    lines.append(f"فحص: {domain}")
    lines.append("─" * 30)
    lines.append("")

    # رؤوس الأمان
    h = results["headers"]
    lines.append(f"🛡️  رؤوس الأمان ............ {h['score']}/{h['total']}")
    for item in h["found"]:
        value = item["value"][:60]
        lines.append(f"   {_ok(True)} {item['name']:32s} {value}")
    for item in h["missing"]:
        lines.append(f"   {_ok(False)} {item['name']:32s} (مفقود)")
    lines.append("")

    # البريد
    e = results["email"]
    lines.append(f"📧  البريد ................. {e['score']}/{e['total']}")
    lines.append(f"   {_ok(e['spf']['ok'])} SPF")
    if e["spf"]["found"]:
        lines.append(f"        {e['spf']['value'][:70]}")
    lines.append(f"   {_ok(e['dmarc']['ok'])} DMARC")
    if e["dmarc"]["found"]:
        lines.append(f"        policy={e['dmarc']['policy'] or '?'}")
    lines.append("")

    # TLS
    t = results["tls"]
    lines.append(f"🔒  TLS .................... {_ok(t['ok'])}")
    if t["error"]:
        lines.append(f"   خطأ: {t['error']}")
    else:
        lines.append(f"   المُصدر: {t['issuer']}")
        lines.append(f"   ينتهي: {t['not_after'][:10]} ({t['days_left']} يومًا)")
        if t["expired"]:
            lines.append("   ⚠️  الشهادة منتهية.")
        elif t["warning"]:
            lines.append(f"   ⚠️  تنتهي خلال أقل من 30 يومًا.")

    lines.append("")
    lines.append("─" * 30)
    s = _build_summary(results)
    lines.append(f"النتيجة: {s['earned']}/{s['possible']} ({s['percent']}% — {s['grade']})")

    return "\n".join(lines)


def render_html(domain: str, results: dict[str, Any], out_dir: Path | None = None) -> Path:
    """يولّد تقرير HTML ويحفظه في ملف. يعيد مسار الملف."""
    env = _make_env()
    template = env.get_template("report.html")

    summary = _build_summary(results)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    html = template.render(
        domain=domain,
        results=results,
        summary=summary,
        generated_at=generated_at,
    )

    out_dir = out_dir or Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_domain = domain.replace("/", "_").replace(":", "_")
    out_path = out_dir / f"report-{safe_domain}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path
