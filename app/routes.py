"""Route handlers and security utility functions."""
from __future__ import annotations

import ipaddress
import json
from urllib.error import URLError
from urllib.request import urlopen
from cryptography.fernet import Fernet, InvalidToken
from flask import Blueprint, current_app, jsonify, render_template, request

from .models import dashboard_metrics, log_usage
from .utils import (
    analyze_email_header,
    analyze_password,
    analyze_url,
    derive_fernet_key,
    file_hashes,
    generate_password,
)

main = Blueprint("main", __name__)


def record(tool_name: str, risk_score: int = 0) -> None:
    """Record tool usage without cluttering route handlers."""
    log_usage(current_app.config["DATABASE"], tool_name, risk_score)


@main.route("/")
def home():
    return render_template("home.html")


@main.route("/password-checker", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        result = analyze_password(request.form.get("password", ""))
        record("Password Strength Checker", result["score"])
    return render_template("password_checker.html", result=result)


@main.route("/password-generator", methods=["GET", "POST"])
def password_generator():
    generated = None
    if request.method == "POST":
        generated = generate_password(
            int(request.form.get("length", 16)),
            bool(request.form.get("uppercase")),
            bool(request.form.get("lowercase")),
            bool(request.form.get("numbers")),
            bool(request.form.get("symbols")),
        )
        record("Password Generator")
    return render_template("password_generator.html", generated=generated)


@main.route("/file-hash", methods=["GET", "POST"])
def file_hash():
    hashes = None
    if request.method == "POST" and "file" in request.files:
        data = request.files["file"].read()
        hashes = file_hashes(data)
        record("File Hash Generator")
    return render_template("file_hash.html", hashes=hashes)


@main.route("/url-phishing", methods=["GET", "POST"])
def url_phishing():
    result = None
    if request.method == "POST":
        result = analyze_url(request.form.get("url", ""))
        record("URL Phishing Detector", result["score"])
    return render_template("url_phishing.html", result=result)


@main.route("/email-header", methods=["GET", "POST"])
def email_header():
    result = None
    if request.method == "POST":
        result = analyze_email_header(request.form.get("header", ""))
        record("Email Header Analyzer")
    return render_template("email_header.html", result=result)


@main.route("/ip-lookup", methods=["GET", "POST"])
def ip_lookup():
    result = None
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        try:
            ipaddress.ip_address(ip)
            lookup_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,as,timezone"
            with urlopen(lookup_url, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (ValueError, URLError, TimeoutError) as exc:
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
                if action == "encrypt":
                    output = fernet.encrypt(text.encode()).decode()
                else:
                    output = fernet.decrypt(text.encode()).decode()
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
