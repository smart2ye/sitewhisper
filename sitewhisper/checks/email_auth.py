"""فحص مصادقة البريد: SPF و DMARC (سجلات DNS عامة)."""

from typing import Any

import dns.exception
import dns.resolver


_FALLBACK_NS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def _make_resolver(ns: str | None):
    if ns is None:
        r = dns.resolver.Resolver()
    else:
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = [ns]
    r.lifetime = 8.0
    r.timeout = 4.0
    return r


def _query_txt(domain: str) -> list[str]:
    """يعيد كل سجلات TXT لنطاق. يجرّب المُحلّل الافتراضي ثم العام (8.8.8.8/1.1.1.1)."""
    for ns in [None, *_FALLBACK_NS]:
        try:
            r = _make_resolver(ns)
            answers = r.resolve(domain, "TXT", raise_on_no_answer=False)
            if answers is None:
                continue
            records: list[str] = []
            for rdata in answers:
                try:
                    records.append(b"".join(rdata.strings).decode("utf-8", errors="replace"))
                except Exception:
                    continue
            if records:
                return records
        except (dns.exception.DNSException, Exception):
            continue
    return []


def check_spf(domain: str) -> dict[str, Any]:
    """يبحث عن سجل SPF (v=spf1) في سجلات TXT."""
    for record in _query_txt(domain):
        if record.strip().lower().startswith("v=spf1"):
            return {
                "ok": True,
                "found": True,
                "value": record.strip(),
                "recommendation": None,
            }
    return {
        "ok": False,
        "found": False,
        "value": None,
        "recommendation": (
            "لا يوجد سجل SPF. أي شخص قد يرسل بريدًا باسم نطاقك. "
            "أضف: v=spf1 include:_spf.<مزوّدك> ~all"
        ),
    }


def check_dmarc(domain: str) -> dict[str, Any]:
    """يبحث عن سجل DMARC في _dmarc.<domain>."""
    target = f"_dmarc.{domain}"
    for record in _query_txt(target):
        if record.strip().lower().startswith("v=dmarc1"):
            policy = _extract_policy(record)
            return {
                "ok": True,
                "found": True,
                "value": record.strip(),
                "policy": policy,
                "recommendation": None,
            }
    return {
        "ok": False,
        "found": False,
        "value": None,
        "policy": None,
        "recommendation": (
            "لا يوجد سجل DMARC. غيابه يعني أن أي شخص قد ينتحل بريد نطاقك. "
            "أضف سجل TXT باسم _dmarc.<نطاقك> بالقيمة: "
            "v=DMARC1; p=quarantine; rua=mailto:dmarc@<نطاقك>"
        ),
    }


def _extract_policy(record: str) -> str | None:
    """يستخرج قيمة p= (none/quarantine/reject) من سجل DMARC."""
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key.strip().lower() == "p":
            return value.strip().lower()
    return None


def check_email_auth(domain: str) -> dict[str, Any]:
    """يجمع فحص SPF و DMARC في بنية موحدة."""
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    score = int(spf["ok"]) + int(dmarc["ok"])
    return {
        "ok": score == 2,
        "spf": spf,
        "dmarc": dmarc,
        "score": score,
        "total": 2,
    }
