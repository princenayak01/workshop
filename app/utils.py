"""Pure utility functions used by the cybersecurity toolkit routes."""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import string
from email.parser import Parser
from urllib.parse import urlparse


def analyze_password(password: str) -> dict:
    """Score a password and produce actionable improvement tips."""
    suggestions = []
    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    score = min(len(password) * 4, 40)
    score += sum(12 for passed in checks.values() if passed)

    if not checks["length"]:
        suggestions.append("Use at least 12 characters; 16+ is better for sensitive accounts.")
    if not checks["uppercase"]:
        suggestions.append("Add uppercase letters.")
    if not checks["lowercase"]:
        suggestions.append("Add lowercase letters.")
    if not checks["number"]:
        suggestions.append("Add numbers.")
    if not checks["symbol"]:
        suggestions.append("Add symbols such as !, @, #, or %.")
    if re.search(r"(password|admin|qwerty|letmein|1234)", password, re.I):
        score -= 25
        suggestions.append("Avoid common words and keyboard patterns.")

    score = max(0, min(100, score))
    label = "Weak" if score < 45 else "Moderate" if score < 75 else "Strong"

    return {
        "score": score,
        "label": label,
        "suggestions": suggestions or ["Great structure. Store it in a password manager."],
    }


def generate_password(length: int, uppercase: bool, lowercase: bool, numbers: bool, symbols: bool) -> str:
    """Generate a cryptographically secure password from selected character groups."""
    safe_length = max(8, min(128, length))
    pool = ""
    pool += string.ascii_uppercase if uppercase else ""
    pool += string.ascii_lowercase if lowercase else ""
    pool += string.digits if numbers else ""
    pool += "!@#$%^&*()-_=+[]{};:,.?/" if symbols else ""
    pool = pool or string.ascii_letters + string.digits
    return "".join(secrets.choice(pool) for _ in range(safe_length))


def file_hashes(data: bytes) -> dict:
    """Return MD5, SHA1, and SHA256 hashes for uploaded bytes."""
    return {
        "MD5": hashlib.md5(data).hexdigest(),
        "SHA1": hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }


def analyze_url(url: str) -> dict:
    """Run transparent phishing heuristics and calculate a risk score."""
    normalized = url.strip()
    parsed = urlparse(normalized if "://" in normalized else f"http://{normalized}")
    reasons = []
    score = 0

    if parsed.scheme != "https":
        score += 20
        reasons.append("URL does not use HTTPS.")
    if re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc):
        score += 20
        reasons.append("URL uses an IP address instead of a domain.")
    if len(parsed.netloc) > 35 or parsed.netloc.count("-") > 2:
        score += 15
        reasons.append("Domain is unusually long or hyphenated.")
    if any(word in normalized.lower() for word in ["login", "verify", "update", "secure", "account", "bank"]):
        score += 20
        reasons.append("URL contains social-engineering keywords.")
    if "@" in normalized or normalized.count("//") > 1:
        score += 25
        reasons.append("URL contains suspicious redirect/userinfo patterns.")

    score = min(score, 100)
    return {
        "score": score,
        "level": "High" if score >= 60 else "Medium" if score >= 30 else "Low",
        "reasons": reasons or ["No obvious phishing indicators found."],
        "tips": [
            "Verify the sender through a trusted channel.",
            "Do not enter passwords from unsolicited links.",
            "Use browser safe-browsing warnings.",
        ],
    }


def analyze_email_header(header: str) -> dict:
    """Extract sender IP and authentication fields from raw email headers."""
    message = Parser().parsestr(header)
    received = message.get_all("Received", [])
    ip_match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", " ".join(received))
    return {
        "sender_ip": ip_match.group(1) if ip_match else "Not found",
        "spf": message.get("Received-SPF", "Not found"),
        "dkim": "Present" if message.get("DKIM-Signature") else "Not found",
        "dmarc": message.get("Authentication-Results", "Check Authentication-Results for DMARC status"),
    }


def derive_fernet_key(secret_key: str) -> bytes:
    """Derive a Fernet-compatible key from a user-provided secret."""
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)
