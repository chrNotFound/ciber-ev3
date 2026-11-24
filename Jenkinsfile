// Pipeline DevSecOps - SecureDev Tickets (OCY1102 EV3)
// Etapas: Checkout -> Construcción -> Pruebas -> SAST/Dependencias -> Imagen -> Despliegue -> ZAP -> Gate
pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds(); timeout(time: 30, unit: 'MINUTES') }
  environment {
    IMAGE = "securedev-tickets:${env.BUILD_NUMBER}"
    NET   = "securedev-ci-${env.BUILD_NUMBER}"
    APP   = "securedev-app-${env.BUILD_NUMBER}"
  }
  stages {
    stage('Checkout') {
      steps { checkout scm; sh 'mkdir -p reports && git log -1 --pretty="%H %an %s" | tee reports/commit.txt || true' }
    }
    stage('Construcción') {
      steps {
        sh '''python3 -m venv .venv
              . .venv/bin/activate
              pip install -q -r requirements-dev.txt'''
      }
    }
    stage('Pruebas unitarias y de seguridad') {
      steps { sh '. .venv/bin/activate && pytest -q --junitxml=reports/pytest.xml' }
      post { always { junit allowEmptyResults: true, testResults: 'reports/pytest.xml' } }
    }
    stage('Revisión de seguridad estática (SAST)') {
      steps { sh '. .venv/bin/activate && bandit -r app.py -ll -f json -o reports/bandit.json && bandit -r app.py -ll' }
    }
    stage('Dependencias vulnerables (SCA)') {
      steps { sh '. .venv/bin/activate && pip-audit -r requirements.txt --strict -f json -o reports/pip-audit.json && pip-audit -r requirements.txt --strict' }
    }
    stage('Construir imagen') {
      steps { sh 'docker build -t $IMAGE .' }
    }
    stage('Despliegue (entorno de pruebas)') {
      steps {
        sh '''docker network create $NET
              docker run -d --name $APP --network $NET -e SECRET_KEY=$(head -c32 /dev/urandom | od -An -tx1 | tr -d " \\n") $IMAGE
              for i in $(seq 1 20); do docker exec $APP python -c "import urllib.request as u;u.urlopen('http://127.0.0.1:8000/health')" && break; sleep 2; done'''
      }
    }
    stage('OWASP ZAP baseline (DAST)') {
      steps {
        sh '''chmod 777 reports
              docker run --rm --network $NET -v "$PWD/reports:/zap/wrk:rw" -v "$PWD/zap:/zap/conf:ro" \
                ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://$APP:8000 \
                -c /zap/conf/zap-baseline.conf -r zap-report.html -J zap-report.json -w zap-report.md -I || true'''
      }
    }
    stage('Gate de seguridad ZAP') {
      steps {
        sh '''python3 - <<PY
import json, sys
alerts = [a for s in json.load(open("reports/zap-report.json"))["site"] for a in s["alerts"]]
high = [a["name"] for a in alerts if int(a["riskcode"]) >= 3]
print("Alertas ZAP:", [(a["name"], a["riskdesc"]) for a in alerts])
sys.exit(1 if high else 0)
PY'''
      }
    }
  }
  post {
    always {
      sh 'docker rm -f $APP >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true'
      publishHTML(target: [reportDir: 'reports', reportFiles: 'zap-report.html', reportName: 'ZAP Baseline', allowMissing: true, keepAll: true])
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
    }
    success { echo 'Pipeline OK: sin hallazgos críticos; evidencia archivada para auditoría.' }
    failure { echo 'Pipeline falló: revisar reports/ (bandit, pip-audit, ZAP).' }
  }
}
