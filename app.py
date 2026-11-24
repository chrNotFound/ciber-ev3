"""SecureDev Tickets - versión corregida (OCY1102 EV3).

Cada control de seguridad lleva una referencia VULN-xx que corresponde a la matriz
de docs/INFORME_SEGURIDAD.md, para dar trazabilidad entre hallazgo, corrección y prueba.
"""

import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock

from flask import Flask, Response, abort, g, redirect, render_template, request, session, url_for
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

MAX_COMMENT_LEN = 2000
MAX_QUERY_LEN = 100
LOGIN_MAX_FAILURES = 5      # VULN-07: intentos fallidos permitidos...
LOGIN_WINDOW_SECONDS = 300  # ...dentro de esta ventana (por IP + usuario)

# Hash falso para igualar el tiempo de respuesta cuando el usuario no existe (VULN-07).
_DUMMY_HASH = generate_password_hash("no-existe")

# Métricas para Grafana/Prometheus (monitorización de producción).
SECURITY_EVENTS = Counter("securedev_security_events_total", "Eventos de seguridad", ["event"])
HTTP_RESPONSES = Counter("securedev_http_responses_total", "Respuestas HTTP", ["status"])

security_log = logging.getLogger("securedev.security")


def log_event(event, **fields):
    """Registro estructurado (JSON) de eventos de seguridad: insumo para auditoría y alertas."""
    SECURITY_EVENTS.labels(event=event).inc()
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event": event,
        "ip": request.remote_addr,
        "path": request.path,
        "user_id": session.get("user_id"),
        **fields,
    }
    security_log.warning(json.dumps(record, ensure_ascii=False))


def escape_like(value):
    """Escapa comodines de LIKE para que la entrada del usuario sea texto literal."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def create_app(database_path=None):
    app = Flask(__name__)

    if not security_log.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        security_log.addHandler(handler)
        security_log.setLevel(logging.INFO)
        security_log.propagate = False

    # VULN-06: sin clave por defecto en el código. Si no se define SECRET_KEY se genera una aleatoria
    # (las sesiones no sobreviven a reinicios, pero nunca se usa un secreto conocido).
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    app.config["DATABASE_PATH"] = str(
        database_path or os.getenv("DATABASE_PATH", str(Path(__file__).with_name("securedev.db")))
    )
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "0") == "1",  # activar tras HTTPS
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=16 * 1024,
    )

    failures = defaultdict(deque)  # (ip, usuario) -> instantes de fallos
    failures_lock = Lock()

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    with app.app_context():
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
        connection = db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            # Datos de prueba solo para laboratorio (ver "riesgos aceptados" en el informe).
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [
                    (1, "ana", generate_password_hash("ana123")),
                    (2, "bruno", generate_password_hash("bruno123")),
                ],
            )
            connection.executemany(
                "INSERT INTO tickets (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Revisión de despliegue", "Preparar evidencias de CI/CD."),
                    (2, 2, "Acceso al panel", "Revisar registros de acceso."),
                ],
            )
        connection.commit()

    def current_user():
        return session.get("user_id")

    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    def owned_ticket_or_404(ticket_id):
        """VULN-03: solo el dueño accede al ticket. Se responde 404 para no revelar su existencia."""
        item = db().execute(
            "SELECT id, owner_id, title, body FROM tickets WHERE id = ? AND owner_id = ?",
            (ticket_id, current_user()),
        ).fetchone()
        if item is None:
            if db().execute("SELECT 1 FROM tickets WHERE id = ?", (ticket_id,)).fetchone():
                log_event("authz_denied", ticket_id=ticket_id)
            abort(404)
        return item

    @app.before_request
    def protect_against_csrf():
        # VULN-04: todo método que cambia estado exige token CSRF válido (incluye login y logout).
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(sent, expected):
                log_event("csrf_failed")
                abort(400)

    @app.after_request
    def security_headers(response):
        # VULN-05: cabeceras defensivas (hallazgos típicos de OWASP ZAP baseline).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; "
            "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        HTTP_RESPONSES.labels(status=str(response.status_code)).inc()
        return response

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def client_error(error):
        # Mensajes genéricos: sin trazas ni detalles internos.
        return Response(f"{error.code} {error.name}", status=error.code, mimetype="text/plain")

    @app.errorhandler(500)
    def server_error(_error):
        return Response("500 Internal Server Error", status=500, mimetype="text/plain")

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? ORDER BY id", (current_user(),)
        ).fetchall()
        return render_template("index.html", tickets=tickets)

    def too_many_failures(key):
        now = time.time()
        with failures_lock:
            attempts = failures[key]
            while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
                attempts.popleft()
            return len(attempts) >= LOGIN_MAX_FAILURES

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")[:64]
            password = request.form.get("password", "")[:128]
            key = (request.remote_addr, username.lower())
            if too_many_failures(key):  # VULN-07: bloqueo temporal anti fuerza bruta
                log_event("login_rate_limited", username=username)
                abort(429)
            user = db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
            if user and valid:
                with failures_lock:
                    failures.pop(key, None)
                csrf = session.get("csrf_token")
                session.clear()  # evita fijación de sesión
                session["csrf_token"] = csrf or secrets.token_urlsafe(32)
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session.permanent = True
                log_event("login_success", username=username)
                return redirect(url_for("index"))
            with failures_lock:
                failures[key].append(time.time())
            log_event("login_failed", username=username)
            error = "Credenciales inválidas"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/tickets/<int:ticket_id>")
    def ticket(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        item = owned_ticket_or_404(ticket_id)
        comments = db().execute(
            "SELECT body FROM comments WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        ).fetchall()
        return render_template("ticket.html", ticket=item, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comments")
    def add_comment(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        owned_ticket_or_404(ticket_id)
        body = request.form.get("body", "").strip()
        if not body or len(body) > MAX_COMMENT_LEN:  # validación de entrada
            abort(400)
        db().execute(
            "INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
            (ticket_id, current_user(), body),
        )
        db().commit()
        return redirect(url_for("ticket", ticket_id=ticket_id))

    @app.get("/search")
    def search():
        if not current_user():
            return redirect(url_for("login"))
        query = request.args.get("q", "")[:MAX_QUERY_LEN]
        # VULN-01: consulta parametrizada y limitada a los tickets del usuario (también cierra IDOR).
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE ? ESCAPE '\\' ORDER BY id",
            (current_user(), f"%{escape_like(query)}%"),
        ).fetchall()
        return render_template("search.html", tickets=tickets, query=query)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


if __name__ == "__main__":
    # Solo para desarrollo local; en contenedor se ejecuta con gunicorn (ver Dockerfile).
    create_app().run(host="127.0.0.1", port=8000, debug=False)
