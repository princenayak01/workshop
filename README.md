# Cybersecurity Toolkit

A professional full-stack defensive security web application built with Flask, SQLite, Bootstrap 5, Chart.js, Font Awesome, HTML5, CSS3, and JavaScript.

## Features

- Modern animated home page with cybersecurity themed statistic cards.
- Password strength checker with a score, meter, and improvement suggestions.
- Secure password generator with length and character-set controls plus copy support.
- File hash generator for MD5, SHA1, and SHA256.
- URL phishing detector with heuristic risk scoring and security tips.
- Email header analyzer for sender IP, SPF, DKIM, and DMARC clues.
- IP address lookup for country, city, ISP, ASN, and timezone using Python standard-library HTTP calls.
- AES-style symmetric text encryption/decryption using Fernet with a secret-derived key.
- SQLite dashboard with Chart.js usage and risk charts.
- Contact page.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000>.

## Project structure

```text
app/
  __init__.py          # Flask app factory
  models.py            # SQLite initialization and metrics
  routes.py            # Web routes
  utils.py             # Dependency-light toolkit logic
  static/css/styles.css
  static/js/app.js
  templates/           # Jinja2 pages
run.py                 # Development entry point
requirements.txt       # Python dependencies
tests/                 # Standard-library utility regression tests
```

## Security note

This toolkit is intended for authorized defensive analysis and education. Replace the development secret key before production use and place the app behind HTTPS.

## Checks

Run dependency-light regression tests before starting the Flask app:

```bash
python -m unittest discover -s tests -v
python -m compileall app run.py
```
