# SecureDev Tickets – versión corregida (OCY1102 EV3)

Aplicación base con las vulnerabilidades corregidas, pipeline Jenkins, ZAP, monitorización Grafana y Dependabot.
**Lea primero `docs/INFORME_SEGURIDAD.md`** (hallazgos, correcciones, trazabilidad y checklist).

```powershell
copy .env.example .env      # defina SECRET_KEY y GRAFANA_ADMIN_PASSWORD
docker compose up -d --build                                   # solo la app  -> http://localhost:8000
docker compose -f compose.yaml -f ci/compose.ci.yaml up -d --build   # + Jenkins :8080, Prometheus :9090, Grafana :3000
```
Usuarios de prueba (solo laboratorio): `ana / ana123`, `bruno / bruno123`.
Pruebas locales: `pip install -r requirements-dev.txt && pytest -q`.
`docker compose down -v` reinicia los datos.
