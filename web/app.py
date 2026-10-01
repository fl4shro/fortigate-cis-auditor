import os
import json
import sys
import io
import time
import secrets
import threading
from pathlib import Path
from datetime import datetime

from flask import Flask, Request, render_template, request, redirect, url_for, session, send_file, jsonify
from werkzeug.utils import secure_filename

BASE_DIR = Path("/opt/fortigate-cis")
sys.path.insert(0, str(BASE_DIR))

from cis_benchmark.config_parser import FortiGateConfigParser
from cis_benchmark.rules import get_all_rules, get_level1_rules, get_level2_rules
from cis_benchmark.scoring import ComplianceScorer
from cis_benchmark.remediation import RemediationEngine
from cis_benchmark.reporting import HTMLReportGenerator, JSONReportGenerator, PDFReportGenerator

class MemoryRequest(Request):
    """
    Mantém uploads multipart em memória.
    O conteúdo do .conf não é gravado em arquivo temporário pela aplicação.
    """
    max_form_memory_size = 50 * 1024 * 1024

    def _get_file_stream(
        self,
        total_content_length,
        content_type,
        filename=None,
        content_length=None,
    ):
        return io.BytesIO()


app = Flask(__name__)
app.request_class = MemoryRequest

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["MAX_FORM_MEMORY_SIZE"] = 50 * 1024 * 1024
app.config["SECRET_KEY"] = (BASE_DIR / "config/secret.key").read_text().strip()

# Sessão exclusiva por navegador.
# O cookie contém apenas um identificador aleatório.
# O relatório permanece somente na memória do processo.
app.config["SESSION_COOKIE_NAME"] = "cis_sid"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = 7200

SESSION_TTL = 7200

audit_sessions = {}
audit_sessions_lock = threading.Lock()


def get_browser_sid():
    """Get or create the anonymous browser session."""

    sid = session.get("sid")

    if not sid or not isinstance(sid, str) or len(sid) < 32:
        sid = secrets.token_urlsafe(32)
        session.clear()
        session.permanent = True
        session["sid"] = sid

    session.permanent = True

    now = time.time()

    with audit_sessions_lock:

        expired = [
            key
            for key, value in audit_sessions.items()
            if now - value.get("last_seen", now) > SESSION_TTL
        ]

        for key in expired:
            audit_sessions.pop(key, None)

        entry = audit_sessions.setdefault(
            sid,
            {
                "report": None,
                "config_file": "",
                "timestamp": None,
                "last_seen": now,
            },
        )

        entry["last_seen"] = now

    return sid


def run_audit(config_path: str, level_filter: str = "all"):
    """Run CIS audit on a config file."""

    parser = FortiGateConfigParser()
    config = parser.parse_file(config_path)

    if level_filter == "1":
        rules = get_level1_rules()
    elif level_filter == "2":
        rules = get_level2_rules()
    else:
        rules = get_all_rules()

    results = []

    for rule in rules:
        result = rule.evaluate(config)
        results.append(result)

    scorer = ComplianceScorer()
    report = scorer.calculate(results)

    return report


def run_audit_content(content: str, level_filter: str = "all"):
    """Run CIS audit directly from configuration content in RAM."""

    parser = FortiGateConfigParser()
    config = parser.parse_content(content)

    if level_filter == "1":
        rules = get_level1_rules()
    elif level_filter == "2":
        rules = get_level2_rules()
    else:
        rules = get_all_rules()

    results = []

    for rule in rules:
        result = rule.evaluate(config)
        results.append(result)

    scorer = ComplianceScorer()
    report = scorer.calculate(results)

    return report


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/")
def index():
    sid = get_browser_sid()

    with audit_sessions_lock:
        audit = audit_sessions.get(sid)

    return render_template(
        "dashboard.html",
        audit=audit,
    )


@app.route("/upload", methods=["POST"])
def upload_config():
    sid = get_browser_sid()

    if "config_file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files["config_file"]

    if not file.filename:
        return jsonify({"error": "Nenhum arquivo selecionado"}), 400

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(".conf"):
        return jsonify({"error": "Somente arquivos .conf são permitidos"}), 400

    try:
        raw_bytes = file.stream.read()

        if not raw_bytes:
            return jsonify({"error": "O arquivo está vazio"}), 400

        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content = raw_bytes.decode("latin-1")

        level_filter = request.form.get("level", "all")
        report = run_audit_content(content, level_filter)

        with audit_sessions_lock:
            audit_sessions[sid] = {
                "report": report,
                "config_file": filename,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_seen": time.time(),
            }

        return redirect(url_for("index"))

    except Exception as e:

        with audit_sessions_lock:
            audit = audit_sessions.get(sid)

        return render_template(
            "dashboard.html",
            audit=audit,
            error=f"Erro na auditoria: {str(e)}"
        )


@app.route("/api/audit", methods=["POST"])
def api_audit():
    get_browser_sid()

    if "config_file" not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files["config_file"]

    if not file.filename:
        return jsonify({"error": "Nenhum arquivo selecionado"}), 400

    filename = secure_filename(file.filename)

    if not filename.lower().endswith(".conf"):
        return jsonify({"error": "Somente arquivos .conf são permitidos"}), 400

    try:
        raw_bytes = file.stream.read()

        if not raw_bytes:
            return jsonify({"error": "O arquivo está vazio"}), 400

        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            content = raw_bytes.decode("latin-1")

        level_filter = request.form.get("level", "all")
        report = run_audit_content(content, level_filter)

        return jsonify(report.to_dict())

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/download/<format_type>")
def download_report(format_type):
    sid = get_browser_sid()

    with audit_sessions_lock:
        audit = audit_sessions.get(sid)

    if not audit or not audit.get("report"):
        return jsonify({
            "error": "Nenhuma auditoria disponível nesta sessão."
        }), 400

    report = audit["report"]
    config_file = audit["config_file"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:

        if format_type == "html":

            gen = HTMLReportGenerator()

            html_content = gen.generate(
                report,
                config_file=config_file
            )

            return send_file(
                io.BytesIO(html_content.encode("utf-8")),
                as_attachment=True,
                download_name=f"CIS_Report_{timestamp}.html",
                mimetype="text/html; charset=utf-8"
            )

        if format_type == "json":

            gen = JSONReportGenerator()

            json_content = gen.generate(
                report,
                config_file=config_file
            )

            return send_file(
                io.BytesIO(json_content.encode("utf-8")),
                as_attachment=True,
                download_name=f"CIS_Report_{timestamp}.json",
                mimetype="application/json"
            )

        if format_type == "pdf":

            html_gen = HTMLReportGenerator()

            html_content = html_gen.generate(
                report,
                config_file=config_file
            )

            pdf_gen = PDFReportGenerator()

            pdf_buffer = io.BytesIO()

            pdf_gen.generate(
                html_content,
                pdf_buffer
            )

            pdf_buffer.seek(0)

            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"CIS_Report_{timestamp}.pdf",
                mimetype="application/pdf"
            )

        if format_type == "remediation":

            engine = RemediationEngine()

            script = engine.generate_script(
                report.failed_results,
                dry_run=True
            )

            return send_file(
                io.BytesIO(script.encode("utf-8")),
                as_attachment=True,
                download_name=f"Remediation_{timestamp}.txt",
                mimetype="text/plain; charset=utf-8"
            )

        return jsonify({"error": "Formato inválido"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=8000
    )

# CIS official benchmark version gate
import re

def detect_fortios_version(config_path):
    with open(config_path, "r", errors="ignore") as f:
        raw = f.read(20000)

    m = re.search(r'#config-version=.*?-(\d+\.\d+\.\d+)-FW-', raw)
    if not m:
        m = re.search(r'FortiOS\s+v?(\d+\.\d+\.\d+)', raw, re.I)

    if not m:
        return None

    return m.group(1)

