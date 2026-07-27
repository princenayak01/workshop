"""Route handlers and security utility functions."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import re
import secrets
import string
from email.parser import Parser
from urllib.parse import urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, current_app, jsonify, render_template, request

from .models import dashboard_metrics, log_usage

main = Blueprint("main", __name__)


def record(tool_name: str, risk_score: int = 0) -> None:
    """Record tool usage without cluttering route handlers."""
    log_usage(current_app.config["DATABASE"], tool_name, risk_score)


def password_analysis(password: str) -> dict:
    """Score a password and produce actionable improvement tips."""
    suggestions = []
    score = 0
    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score += min(len(password) * 4, 40)
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
    return {"score": score, "label": label, "suggestions": suggestions or ["Great structure. Store it in a password manager."]}


def derive_fernet_key(secret_key: str) -> bytes:
    """Derive a Fernet-compatible key from a user-provided secret."""
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


@main.route("/")
def home():
    return render_template("home.html")


@main.route("/password-checker", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        result = password_analysis(request.form.get("password", ""))
        record("Password Strength Checker", result["score"])
    return render_template("password_checker.html", result=result)


@main.route("/password-generator", methods=["GET", "POST"])
def password_generator():
    generated = None
    if request.method == "POST":
        length = max(8, min(128, int(request.form.get("length", 16))))
        pool = ""
        pool += string.ascii_uppercase if request.form.get("uppercase") else ""
        pool += string.ascii_lowercase if request.form.get("lowercase") else ""
        pool += string.digits if request.form.get("numbers") else ""
        pool += "!@#$%^&*()-_=+[]{};:,.?/" if request.form.get("symbols") else ""
        pool = pool or string.ascii_letters + string.digits
        generated = "".join(secrets.choice(pool) for _ in range(length))
        record("Password Generator")
    return render_template("password_generator.html", generated=generated)


@main.route("/file-hash", methods=["GET", "POST"])
def file_hash():
    hashes = None
    if request.method == "POST" and "file" in request.files:
        data = request.files["file"].read()
        hashes = {"MD5": hashlib.md5(data).hexdigest(), "SHA1": hashlib.sha1(data).hexdigest(), "SHA256": hashlib.sha256(data).hexdigest()}
        record("File Hash Generator")
    return render_template("file_hash.html", hashes=hashes)


@main.route("/url-phishing", methods=["GET", "POST"])
def url_phishing():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        parsed = urlparse(url if "://" in url else f"http://{url}")
        reasons = []
        score = 0
        if parsed.scheme != "https":
            score += 20; reasons.append("URL does not use HTTPS.")
        if re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc):
            score += 20; reasons.append("URL uses an IP address instead of a domain.")
        if len(parsed.netloc) > 35 or parsed.netloc.count("-") > 2:
            score += 15; reasons.append("Domain is unusually long or hyphenated.")
        if any(word in url.lower() for word in ["login", "verify", "update", "secure", "account", "bank"]):
            score += 20; reasons.append("URL contains social-engineering keywords.")
        if "@" in url or url.count("//") > 1:
            score += 25; reasons.append("URL contains suspicious redirect/userinfo patterns.")
        score = min(score, 100)
        result = {"score": score, "level": "High" if score >= 60 else "Medium" if score >= 30 else "Low", "reasons": reasons or ["No obvious phishing indicators found."], "tips": ["Verify the sender through a trusted channel.", "Do not enter passwords from unsolicited links.", "Use browser safe-browsing warnings."]}
        record("URL Phishing Detector", score)
    return render_template("url_phishing.html", result=result)


@main.route("/email-header", methods=["GET", "POST"])
def email_header():
    result = None
    if request.method == "POST":
        header = request.form.get("header", "")
        message = Parser().parsestr(header)
        received = message.get_all("Received", [])
        ip_match = re.search(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", " ".join(received))
        result = {"sender_ip": ip_match.group(1) if ip_match else "Not found", "spf": message.get("Received-SPF", "Not found"), "dkim": "Present" if message.get("DKIM-Signature") else "Not found", "dmarc": message.get("Authentication-Results", "Check Authentication-Results for DMARC status")}
        record("Email Header Analyzer")
    return render_template("email_header.html", result=result)


@main.route("/ip-lookup", methods=["GET", "POST"])
def ip_lookup():
    result = None
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        try:
            ipaddress.ip_address(ip)
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,timezone", timeout=5)
            result = response.json()
        except Exception as exc:
            result = {"status": "fail", "message": str(exc)}
        record("IP Address Lookup")
    return render_template("ip_lookup.html", result=result)


@main.route("/aes", methods=["GET", "POST"])
def aes_tool():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        secret_key = request.form.get("secret_key", "")
        action = request.form.get("action")
        if not secret_key:
            result = {"error": "Secret key is required."}
        else:
            fernet = Fernet(derive_fernet_key(secret_key))
            try:
                output = fernet.encrypt(text.encode()).decode() if action == "encrypt" else fernet.decrypt(text.encode()).decode()
                result = {"output": output}
            except InvalidToken:
                result = {"error": "Unable to decrypt. Check the text and secret key."}
        record("AES Encryption Tool")
    return render_template("aes.html", result=result)


@main.route("/dashboard")
def dashboard():
    metrics = dashboard_metrics(current_app.config["DATABASE"])
    return render_template("dashboard.html", metrics=metrics)


@main.route("/dashboard-data")
def dashboard_data():
    return jsonify(dashboard_metrics(current_app.config["DATABASE"]))


@main.route("/contact")
def contact():
    return render_template("contact.html")
