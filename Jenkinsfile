pipeline {
    agent any

    environment {
        TRIVY_CACHE = "/tmp/trivy-cache"
        REPORT_DIR  = "${WORKSPACE}/trivy-reports"
        API_PORT    = "8081"
    }

    stages {

        stage('Cleanup') {
            steps {
                echo "Nettoyage..."
                sh 'docker-compose down --remove-orphans || true'
                sh 'docker rmi smartphones-ml-app || true'
                sh 'docker stop smartphones-api || true'
                sh 'docker rm   smartphones-api || true'
                sh '''
                    CONTAINER=$(docker ps -q --filter "publish=${API_PORT}")
                    if [ -n "$CONTAINER" ]; then
                        echo "Port ${API_PORT} occupé par $CONTAINER — nettoyage..."
                        docker stop $CONTAINER || true
                        docker rm   $CONTAINER || true
                    fi
                '''
            }
        }

        stage('Build Image') {
            steps {
                echo "Build Docker..."
                sh 'docker-compose build app'
            }
        }

        stage('Security Scan (Trivy)') {
            steps {
                echo "Scan sécurité..."
                sh '''
                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${TRIVY_CACHE}

                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v ${TRIVY_CACHE}:/root/.cache/trivy \
                        -v ${REPORT_DIR}:/reports \
                        aquasec/trivy:0.69.3 image \
                        --exit-code 0 \
                        --severity CRITICAL,HIGH,MEDIUM,LOW \
                        --scanners vuln \
                        --format json \
                        --output /reports/trivy-raw.json \
                        smartphones-ml-app

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_critical.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_high.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_medium.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_low.csv

                    echo "=== Résumé du scan Trivy ==="
                    echo "CRITICAL : $(tail -n +2 ${REPORT_DIR}/resultat_critical.csv | wc -l)"
                    echo "HIGH     : $(tail -n +2 ${REPORT_DIR}/resultat_high.csv | wc -l)"
                    echo "MEDIUM   : $(tail -n +2 ${REPORT_DIR}/resultat_medium.csv | wc -l)"
                    echo "LOW      : $(tail -n +2 ${REPORT_DIR}/resultat_low.csv | wc -l)"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: '''trivy-reports/resultat.csv,
                                                  trivy-reports/resultat_critical.csv,
                                                  trivy-reports/resultat_high.csv,
                                                  trivy-reports/resultat_medium.csv,
                                                  trivy-reports/resultat_low.csv''',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('Start MLflow') {
            steps {
                echo "Démarrage MLflow..."
                sh 'docker-compose up -d mlflow'
                echo "Attente MLflow healthy..."
                sh '''
                    for i in $(seq 1 24); do
                        STATUS=$(docker inspect --format='{{.State.Health.Status}}' mlflow_server || echo "starting")
                        if [ "$STATUS" = "healthy" ]; then
                            echo "MLflow prêt !"
                            exit 0
                        fi
                        echo "Etat: $STATUS | tentative $i/24..."
                        sleep 5
                    done
                    echo "MLflow non disponible"
                    docker logs mlflow_server
                    exit 1
                '''
            }
        }

        stage('Model Training') {
            steps {
                echo "Training..."
                sh 'docker-compose run --rm train'
            }
        }

        stage('Validate Metrics') {
            steps {
                echo "Validation des métriques..."
                sh 'docker-compose run --rm app python /app/validate_metrics.py'
            }
        }

        stage('Promote Model') {
            steps {
                echo "Promotion du modèle en Production..."
                sh 'docker-compose run --rm app python /app/promote_model.py'
            }
        }

        stage('Model Prediction') {
            steps {
                echo "Prediction..."
                sh 'docker-compose run --rm predict'
            }
        }

        stage('Deploy API') {
            steps {
                echo "Déploiement de l'API sur le port ${API_PORT}..."
                sh '''
                    docker stop smartphones-api || true
                    docker rm   smartphones-api || true

                    # Récupérer le nom du réseau dynamiquement
                    NETWORK=$(docker inspect mlflow_server \
                        --format='{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}')
                    echo "Réseau détecté : ${NETWORK}"

                    docker run -d \
                        --name smartphones-api \
                        --network ${NETWORK} \
                        -p ${API_PORT}:8080 \
                        -e MLFLOW_TRACKING_URI=http://mlflow:5000 \
                        -e MLFLOW_SERVER_DISABLE_SECURITY_MIDDLEWARE=true \
                        -v $(pwd)/mlruns:/mlflow/mlruns \
                        -v $(pwd)/workspace:/app/workspace \
                        smartphones-ml-app \
                        mlflow models serve \
                            -m "models:/smartphones_price_model@Production" \
                            --host 0.0.0.0 \
                            --port 8080 \
                            --no-conda

                    echo "Attente de l API..."
                    for i in $(seq 1 20); do
                        if docker exec smartphones-api curl -sf http://localhost:8080/health 2>/dev/null; then
                            echo "API prête ✅"
                            exit 0
                        fi
                        echo "Tentative $i/20..."
                        sleep 5
                    done
                    echo "API non disponible après 100 secondes"
                    docker logs smartphones-api
                    exit 1
                '''
            }
        }
    }

    post {
        always {
            sh 'docker-compose down --remove-orphans || true'
        }
        success {
            echo "Pipeline OK ✅ — API disponible sur http://localhost:${API_PORT}/invocations"
        }
        failure {
            echo "Pipeline FAILED ❌"
            sh 'docker stop smartphones-api || true'
            sh 'docker rm   smartphones-api || true'
        }
    }
}
```

---

## Ce qui change

`API_PORT = "8081"` est défini dans le bloc `environment` — un seul endroit à modifier si tu veux changer le port à l'avenir. Le mapping Docker est `-p 8081:8080` — le conteneur écoute en interne sur `8080`, mais est accessible depuis l'extérieur sur `8081`.
```
Jenkins    → port 8080  (inchangé)
MLflow     → port 5000  (inchangé)
API Predict → port 8081  (nouveau)
