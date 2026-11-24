# Informe de seguridad DevSecOps – SecureDev Tickets
Asignatura OCY1102 · Evaluación Parcial N°3 · Fecha: 20-11-2026

> **Estado de la evidencia.** Las secciones 2, 3, 6 y 7 se ejecutaron y sus salidas están en `docs/evidencia/`.
> Jenkins, OWASP ZAP, Prometheus y Grafana quedaron **configurados como código** (secciones 4, 5 y 8) pero
> requieren Docker activo: la ejecución y las capturas se registran en la sección 9 (checklist) al correrlos en el laboratorio.

## 1. Alcance y metodología
Aplicación Flask (`app.py`, 5 plantillas, SQLite) revisada en cada etapa del SDLC: **código** (revisión manual + Bandit), **dependencias** (pip-audit),
**build/imagen** (revisión del Dockerfile), **ejecución** (pruebas de explotación + ZAP) y **operación** (logs JSON + Prometheus/Grafana).
Marcos de referencia: OWASP Top 10 2021, CWE.

## 2. Vulnerabilidades identificadas y correcciones (IL 3.1 / 3.4)

| ID | Hallazgo | Ubicación original | OWASP / CWE | Sev. | Corrección aplicada | Prueba |
|----|----------|--------------------|-------------|------|---------------------|--------|
| VULN-01 | **Inyección SQL**: consulta construida con f-string (`LIKE '%{query}%'`). Permitía listar tickets ajenos y volcar hashes con `UNION`. | `app.py` `/search` | A03 · CWE-89 | Alta | Consulta parametrizada, comodines `%`/`_` escapados, longitud máxima, filtro por dueño. | `test_vuln01_*` |
| VULN-02 | **XSS almacenado**: `{{ comment.body \| safe }}` desactivaba el autoescape. | `ticket.html` | A03 · CWE-79 | Alta | Se elimina `\|safe`; CSP `script-src 'none'`; validación (≤2000 car.). | `test_vuln02_*` |
| VULN-03 | **IDOR / control de acceso roto**: cualquier usuario autenticado leía y comentaba tickets ajenos (`/tickets/2`). | `/tickets/<id>`, `/comments` | A01 · CWE-639 | Alta | Verificación de dueño (`owned_ticket_or_404`); responde 404 y registra `authz_denied`. | `test_vuln03_*` |
| VULN-04 | **CSRF**: POST de login, logout y comentarios sin token. | todos los formularios | A01 · CWE-352 | Media | Token por sesión comparado con `hmac.compare_digest` en `before_request`; cookie `SameSite=Lax`. | `test_vuln04_*` |
| VULN-05 | **Cabeceras de seguridad ausentes** (CSP, X-Frame-Options, nosniff, Referrer-Policy) y mensajes de error por defecto. | respuestas HTTP | A05 · CWE-693/1021 | Media | `after_request` con CSP, XFO, nosniff, Referrer/Permissions-Policy, COOP/CORP, `no-store`; errores genéricos. | `test_vuln05_*` |
| VULN-06 | **Secreto de sesión conocido** (`clave-insegura-solo-laboratorio`) en código y compose; cookie sin flags; sin expiración. | `app.py`, `compose.yaml` | A02/A05 · CWE-798 | Alta | `SECRET_KEY` solo por entorno (aleatorio si falta); compose exige `.env`; cookie HttpOnly/SameSite/(Secure opcional); sesión 30 min. | `test_vuln06_*` |
| VULN-07 | **Sin protección contra fuerza bruta** (12 intentos → todos 200) y enumeración por tiempo de respuesta. | `/login` | A07 · CWE-307 | Media | Bloqueo 5 fallos/5 min por IP+usuario (429), hash simulado para usuario inexistente. | `test_vuln07_*` |
| VULN-08 | **Dependencias con 10 avisos únicos de seguridad (17 hallazgos en pip-audit)** (Flask 2.2.5, Werkzeug 2.2.3). | `requirements.txt` | A06 · CWE-1104 | Alta | Flask 3.1.3, Werkzeug 3.1.9 (ver §6). | pip-audit |
| VULN-09 | **Contenedor inseguro**: ejecuta como root, servidor de desarrollo Flask escuchando en `0.0.0.0`, sin healthcheck. | `Dockerfile`, `app.py` | A05 · CWE-250 | Media | Usuario `appuser` (UID 10001), gunicorn, healthcheck, FS de solo lectura, `cap_drop: ALL`, `no-new-privileges`. | revisión |
| VULN-10 | **Sin trazabilidad de eventos de seguridad** (no había logs ni métricas). | toda la app | A09 · CWE-778 | Media | Logs JSON (`login_failed`, `authz_denied`, `csrf_failed`, …) + contadores Prometheus. | `test_errores_*` |

Resultado comparado (`docs/evidencia/exploit_antes.txt` vs `exploit_despues.txt`): las 9 comprobaciones pasan de **VULNERABLE** a **mitigado**.

### Riesgos aceptados / pendientes
- Usuarios `ana/ana123` y `bruno/bruno123` se mantienen **solo** como datos de prueba del laboratorio (contraseñas débiles). En producción se eliminarían y se aplicaría política de contraseñas.
- La app funciona con HTTP en localhost. En producción debe ir tras TLS y activarse `SESSION_COOKIE_SECURE=1`.
- El limitador de login y las métricas viven en memoria; por eso se usa 1 worker de gunicorn. Con varias réplicas se requeriría Redis.
- `/metrics` no tiene autenticación: está publicado solo en `127.0.0.1` y en la red interna de Docker; en producción restringirlo por red.
- `style-src 'unsafe-inline'` en la CSP por el `<style>` embebido; mejora futura: mover a archivo estático.

## 3. Pipeline CI/CD (IL 3.1 / 3.2)
`Jenkinsfile` (declarativo). Cada etapa produce evidencia en `reports/` archivada como artefacto:

| Etapa | Qué hace | Evidencia |
|-------|----------|-----------|
| Checkout | Obtiene el commit y registra autor/hash | `reports/commit.txt` |
| Construcción | venv + `requirements-dev.txt` | log |
| Pruebas | `pytest` (12 pruebas, incluye regresión de seguridad) | `pytest.xml` (JUnit) |
| SAST | `bandit -r app.py -ll` | `bandit.json` |
| SCA | `pip-audit --strict` (falla si hay CVE) | `pip-audit.json` |
| Imagen | `docker build` | tag `securedev-tickets:<build>` |
| Despliegue | Contenedor efímero en red aislada + espera de `/health` | log |
| DAST | OWASP ZAP baseline contra la app desplegada | `zap-report.html/.json/.md` |
| Gate ZAP | Falla el build si hay alertas de riesgo Alto | log |

Levantar Jenkins: `docker compose -f compose.yaml -f ci/compose.ci.yaml up -d --build` → http://localhost:8080 → job *Pipeline from SCM* apuntando al repositorio.

## 4. Pruebas automatizadas de seguridad con OWASP ZAP (IL 3.2)
- Herramienta: `ghcr.io/zaproxy/zaproxy:stable` → `zap-baseline.py` (escaneo pasivo/spider) contra `http://securedev-app-N:8000` dentro de una red Docker temporal.
- Reglas en `zap/zap-baseline.conf`: ausencia de CSP, anti-clickjacking y nosniff → **FAIL**.
- Acciones de mitigación esperadas y ya aplicadas: esas tres reglas corresponden a VULN-05; `Cache-Control: no-store` evita la alerta de contenido cacheable.
- Limitación: el baseline no se autentica, por lo que cubre `/login`, `/health` y `/metrics`. SQLi, XSS, IDOR y CSRF autenticados se cubren con las pruebas de `tests/` y `exploit.py`. Extensión posible: `zap-full-scan` con contexto autenticado.
- **Resultados ZAP:** pegar aquí el resumen de `reports/zap-report.md` tras la primera ejecución (ver §9).

## 5. Monitorización con Grafana (IL 3.2)
Arquitectura: app (`/metrics` + logs JSON) → Prometheus (scrape 10 s) → Grafana (datasource y dashboard provisionados).
Dashboard **SecureDev – Seguridad en producción** (http://localhost:3000, usuario `admin`, clave de `.env`): eventos de seguridad por minuto, fallos de login, accesos denegados (IDOR), respuestas HTTP por código y estado de la app.
Alertas Prometheus (`monitoring/alerts.yml`): `PosibleFuerzaBruta` (>10 fallos/5 min), `AccesoNoAutorizado` (>3 denegaciones/5 min), `CSRFFallidos`, `AppCaida`.

**Simulación de incidentes (reproducible):** ejecutar `docs/evidencia/exploit.py` o intentar manualmente 6 logins fallidos y abrir `/tickets/2` con `ana`.
Eventos registrados en la corrida de verificación (`exploit_despues.txt`):

| Incidente simulado | Evento | Respuesta del sistema | Acción de respuesta recomendada |
|--------------------|--------|-----------------------|-------------------------------|
| 12 intentos de login contra `ana` | 5× `login_failed`, luego `login_rate_limited` (HTTP 429) | Bloqueo temporal automático | Revisar IP origen; bloquear en WAF/firewall si persiste |
| `ana` solicita ticket 2 de `bruno` | `authz_denied` (HTTP 404) | Acceso denegado | Investigar cuenta; rotar credenciales si es comprometida |
| POST sin token CSRF | `csrf_failed` (HTTP 400) | Petición rechazada | Revisar referer/origen de la petición |

## 6. Gestión de dependencias (IL 3.3)
- **Dependabot** (`.github/dependabot.yml`): ecosistemas `pip` y `docker` semanales, `github-actions` mensual, etiquetas `dependencies`/`security`.
- **Verificación de cada actualización** (`.github/workflows/dependency-gate.yml` y etapas SCA/pruebas de Jenkins): `pip-audit --strict` + `pytest` deben pasar antes de aceptar un PR.
- Actualización realizada (antes → después, `pip-audit`):

| Paquete | Antes | Después | CVE/avisos cerrados |
|---------|-------|---------|---------------------|
| Flask | 2.2.5 | 3.1.3 | PYSEC-2026-2151 |
| Werkzeug | 2.2.3 | 3.1.9 | 9 avisos únicos (PYSEC-2023-221, PYSEC-2026-1860 … 4312) |
| gunicorn | – | 27.0.1 | nueva (servidor WSGI de producción) |
| prometheus-client | – | 0.26.0 | nueva (métricas) |

Resultado: **17 hallazgos reportados por pip-audit (10 avisos únicos) → 0** (`pipaudit_antes.txt` / `pipaudit_despues.txt`). Las 12 pruebas pasan con las versiones nuevas, por lo que la actualización no rompió funcionalidad ni introdujo nuevos hallazgos (Bandit: 2 medios → 0).
Política: parches de seguridad se aceptan en ≤7 días; versiones mayores requieren pruebas verdes y revisión.

## 7. Trazabilidad en el SDLC (IL 3.4)

| Fase SDLC | Actividad / control | Herramienta | Evidencia | IL |
|-----------|---------------------|-------------|-----------|----|
| Requisitos | Requisitos de seguridad (§2: acceso, entrada, sesión, registro) | OWASP Top 10 | este informe | 3.1 |
| Diseño | Modelo de amenazas por hallazgo (VULN-01…10) | revisión manual | matriz §2 | 3.1 |
| Codificación | Correcciones con referencia `VULN-xx` en comentarios | Git | `app.py`, plantillas | 3.1 |
| Verificación | Pruebas unitarias + regresión de seguridad | pytest | `pytest_despues.txt`, `pytest.xml` | 3.2 |
| Análisis estático | SAST | Bandit | `bandit_antes/despues.txt` | 3.1 |
| Dependencias | SCA + Dependabot | pip-audit | `pipaudit_*.txt` | 3.3 |
| Build/Entrega | Imagen mínima, usuario no root | Docker | `Dockerfile` | 3.2 |
| Pruebas dinámicas | DAST | OWASP ZAP | `zap-report.*` | 3.2 |
| Operación | Logs + métricas + alertas | Prometheus/Grafana | dashboard, `alerts.yml` | 3.2 |
| Auditoría | Artefactos archivados por build (`archiveArtifacts`, fingerprint) | Jenkins | `reports/` | 3.4 |

### Matriz hallazgo → corrección → prueba → monitoreo
| Hallazgo | Commit/archivo | Prueba automatizada | Señal de monitoreo |
|----------|----------------|---------------------|--------------------|
| VULN-01 | `app.py` `/search` | `test_vuln01_*`, `test_busqueda_*` | – (bloqueado en origen) |
| VULN-02 | `ticket.html` | `test_vuln02_*` | CSP |
| VULN-03 | `owned_ticket_or_404` | `test_vuln03_*` | `authz_denied` |
| VULN-04 | `protect_against_csrf` | `test_vuln04_*` | `csrf_failed` |
| VULN-05 | `security_headers` | `test_vuln05_*` | ZAP (FAIL si faltan) |
| VULN-06 | config de sesión | `test_vuln06_*` | – |
| VULN-07 | limitador de login | `test_vuln07_*` | `login_failed`, `login_rate_limited` |
| VULN-08 | `requirements.txt` | pip-audit en CI | Dependabot |
| VULN-09 | `Dockerfile`, `compose.yaml` | revisión | `AppCaida` |
| VULN-10 | `log_event` | `test_errores_*` | dashboard completo |

## 8. Cómo reproducir
```bash
cp .env.example .env            # editar SECRET_KEY y GRAFANA_ADMIN_PASSWORD
pip install -r requirements-dev.txt
pytest -q && bandit -r app.py -ll && pip-audit -r requirements.txt --strict   # local
docker compose -f compose.yaml -f ci/compose.ci.yaml up -d --build           # app + Jenkins + Prometheus + Grafana
```
Nota para Jenkins en Docker: el job usa el socket del host; si el workspace de Jenkins está en un volumen, los `-v $PWD/reports` de la etapa ZAP deben apuntar a una ruta visible por el daemon (p. ej. montar el workspace en la misma ruta en host y contenedor).

## 9. Checklist de ejecución en laboratorio (completar con capturas)
- [ ] Jenkins: build verde con las 9 etapas (captura de *Stage View*).
- [ ] ZAP: `zap-report.html` archivado; sin alertas de riesgo Alto.
- [ ] Grafana: dashboard con eventos tras simular los 3 incidentes de §5.
- [ ] Repositorio en GitHub con Dependabot habilitado (primer PR automático).
- [ ] Incluir el nombre del estudiante y el enlace al repositorio en la portada.
