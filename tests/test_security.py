"""Pruebas de seguridad automatizadas: cada prueba corresponde a un hallazgo VULN-xx."""
import re

import pytest

from app import create_app


@pytest.fixture()
def app(tmp_path):
    return create_app(tmp_path / "test.db")


def token_from(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def login(app, user, password):
    client = app.test_client()
    token = token_from(client)
    client.post("/login", data={"username": user, "password": password, "csrf_token": token})
    return client


def post(client, url, **data):
    return client.post(url, data={**data, "csrf_token": token_from(client, "/")})


def test_vuln01_sqli_no_filtra_datos(app):
    ana = login(app, "ana", "ana123")
    page = ana.get("/search?q=zzz' OR '1'='1' -- ").get_data(as_text=True)
    assert "Acceso al panel" not in page
    union = ana.get("/search?q=zzz' UNION SELECT id, password_hash FROM users -- ").get_data(as_text=True)
    assert "scrypt" not in union and "pbkdf2" not in union


def test_busqueda_legitima_y_comodines_literales(app):
    ana = login(app, "ana", "ana123")
    assert "Revisión de despliegue" in ana.get("/search?q=despliegue").get_data(as_text=True)
    assert "Revisión" not in ana.get("/search?q=%25").get_data(as_text=True)  # '%' es literal


def test_vuln02_xss_almacenado_escapado(app):
    ana = login(app, "ana", "ana123")
    post(ana, "/tickets/1/comments", body="<script>alert(1)</script>")
    page = ana.get("/tickets/1").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_vuln03_idor_lectura_y_escritura(app):
    ana = login(app, "ana", "ana123")
    assert ana.get("/tickets/2").status_code == 404
    assert post(ana, "/tickets/2/comments", body="intruso").status_code == 404
    bruno = login(app, "bruno", "bruno123")
    assert "intruso" not in bruno.get("/tickets/2").get_data(as_text=True)


def test_vuln04_csrf_rechaza_post_sin_token(app):
    ana = login(app, "ana", "ana123")
    assert ana.post("/tickets/1/comments", data={"body": "x"}).status_code == 400
    assert ana.post("/logout", data={}).status_code == 400
    assert ana.post("/tickets/1/comments", data={"body": "x", "csrf_token": "falso"}).status_code == 400


def test_vuln05_cabeceras_de_seguridad(app):
    headers = app.test_client().get("/login").headers
    for name in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
        assert name in headers
    assert "script-src 'none'" in headers["Content-Security-Policy"]


def test_vuln06_secret_key_no_es_la_conocida(app):
    assert app.config["SECRET_KEY"] != "clave-insegura-solo-laboratorio"
    assert len(app.config["SECRET_KEY"]) >= 32


def test_vuln06_cookie_httponly_samesite(app):
    cookie = app.test_client().get("/login").headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_vuln07_bloqueo_por_fuerza_bruta(app):
    client = app.test_client()
    token = token_from(client)
    codes = [
        client.post("/login", data={"username": "ana", "password": f"mala{i}", "csrf_token": token}).status_code
        for i in range(8)
    ]
    assert codes[:5] == [200] * 5 and 429 in codes[5:]
    # ni siquiera la clave correcta entra mientras dura el bloqueo
    assert client.post("/login", data={"username": "ana", "password": "ana123", "csrf_token": token}).status_code == 429


def test_login_valido_y_rutas_protegidas(app):
    assert app.test_client().get("/").status_code == 302
    assert app.test_client().get("/search?q=a").status_code == 302
    assert login(app, "ana", "ana123").get("/").status_code == 200


def test_validacion_de_comentarios(app):
    ana = login(app, "ana", "ana123")
    assert post(ana, "/tickets/1/comments", body="   ").status_code == 400
    assert post(ana, "/tickets/1/comments", body="a" * 2001).status_code == 400


def test_errores_genericos_y_metricas(app):
    client = app.test_client()
    assert client.get("/no-existe").get_data(as_text=True) == "404 Not Found"
    assert b"securedev_security_events_total" in client.get("/metrics").data
    assert client.get("/health").get_json() == {"status": "ok"}
