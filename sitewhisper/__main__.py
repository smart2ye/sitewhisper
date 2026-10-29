"""نقطة الدخول: python -m sitewhisper <domain>."""

import argparse
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests

from sitewhisper.checks.headers import check_headers
from sitewhisper.checks.email_auth import check_email_auth
from sitewhisper.checks.tls import check_tls
from sitewhisper.report import render_html, render_terminal


def _normalize(target: str) -> tuple[str, str]:
    """يقبل دومينًا أو URL كاملًا، ويعيد (scheme, host)."""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
        scheme = parsed.scheme or "https"
    else:
        host = target.split("/")[0]
        scheme = "https"
    return scheme, host.strip().lower().rstrip(".")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sitewhisper",
        description="فاحص أمني سلبي للمواقع (رؤوس، SPF/DMARC، TLS).",
    )
    parser.add_argument("target", help="النطاق أو الرابط، مثل: example.com")
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="مجلد حفظ تقرير HTML (الافتراضي: المجلد الحالي).",
    )
    parser.add_argument(
        "--no-html",
        action="store_true",
        help="عدم توليد تقرير HTML.",
    )
    args = parser.parse_args(argv)
    return _run(args.target, args.output, args.no_html)


def _fetch_page(scheme: str, host: str) -> requests.Response | None:
    """يجلب الصفحة الرئيسية مرة واحدة، بلا متابعة روابط، بلا JS."""
    url = f"{scheme}://{host}/"
    try:
        return requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "SiteWhisper/0.1 (passive scan)"},
        )
    except requests.RequestException:
        return None


def _run(target: str, output: Path | None, no_html: bool) -> int:
    """ينفّذ الفحص الكامل، ويطبع التقرير النصي، ويولّد HTML."""
    scheme, host = _normalize(target)
    if not host:
        print(f"خطأ: لم أتمكن من استخراج النطاق من: {target}", file=sys.stderr)
        return 2

    print(f"جارٍ فحص: {host} ...", file=sys.stderr)
    print("", file=sys.stderr)

    # 1. جلب رؤوس الصفحة
    response = _fetch_page(scheme, host)
    if response is None:
        print(f"خطأ: تعذّر الاتصال بـ {scheme}://{host}/", file=sys.stderr)
        return 3

    headers_result = check_headers(dict(response.headers))

    # 2. مصادقة البريد (DNS)
    email_result = check_email_auth(host)

    # 3. TLS
    tls_result = check_tls(host)

    results = {
        "headers": headers_result,
        "email": email_result,
        "tls": tls_result,
    }

    # التقرير النصي
    print(render_terminal(host, results))

    # التقرير HTML
    if not no_html:
        try:
            path = render_html(host, results, out_dir=output)
            print("")
            print(f"📄 تقرير HTML: {path}")
        except Exception as exc:
            print(f"تعذّر توليد HTML: {exc}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
