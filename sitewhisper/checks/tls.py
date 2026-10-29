"""فحص شهادة TLS — باستخدام مكتبة ssl المدمجة فقط."""

import socket
import ssl
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


def _fetch_peer_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict[str, Any]:
    """يفتح اتصال TLS ويقرأ الشهادة كـ dict من ssl المدمج.

    لا نتحقق من صلاحية الشهادة (نريد قراءتها حتى لو منتهية).
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("الخادم لم يُرجع شهادة")
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
                f.write(pem)
                tmp_path = f.name
            try:
                cert = ssl._ssl._test_decode_cert(tmp_path)
            finally:
                Path(tmp_path).unlink(missing_ok=True)
            return {"cert": cert, "tls_version": tls_sock.version()}


def _parse_ssl_date(value: str) -> datetime:
    """يحوّل تاريخ SSL ('Mar 31 23:59:59 2026 GMT') إلى datetime UTC."""
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def _first_name(issuer_tuple: tuple, oid: str) -> str | None:
    """يستخرج أول قيمة مطابقة من issuer."""
    for rdn in issuer_tuple:
        for key, value in rdn:
            if key == oid:
                return value
    return None


def _extract_fields(cert: dict[str, Any]) -> dict[str, Any]:
    """يستخرج الحقول المفيدة من قاموس الشهادة الذي يعيده ssl."""
    not_before = _parse_ssl_date(cert["notBefore"])
    not_after = _parse_ssl_date(cert["notAfter"])
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    issuer = (
        _first_name(cert.get("issuer", ()), "organizationName")
        or _first_name(cert.get("issuer", ()), "commonName")
        or "غير معروف"
    )

    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]

    return {
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_left": days_left,
        "sans": sans,
        "expired": days_left < 0,
    }


def check_tls(host: str, port: int = 443, warn_days: int = 30) -> dict[str, Any]:
    """يفحص شهادة TLS ويعيد بنية موحدة للتقارير.

    warn_days: عدد الأيام الذي يُعدّ ما دونه تحذيرًا.
    """
    try:
        data = _fetch_peer_cert(host, port)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "tls_version": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "days_left": None,
            "sans": [],
            "expired": None,
            "warning": False,
        }

    fields = _extract_fields(data["cert"])
    expired = fields["expired"]
    near_expiry = (not expired) and fields["days_left"] < warn_days

    return {
        "ok": (not expired) and (not near_expiry),
        "error": None,
        "tls_version": data["tls_version"],
        "issuer": fields["issuer"],
        "not_before": fields["not_before"],
        "not_after": fields["not_after"],
        "days_left": fields["days_left"],
        "sans": fields["sans"],
        "expired": expired,
        "warning": near_expiry,
    }
