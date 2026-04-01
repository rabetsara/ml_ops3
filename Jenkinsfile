pipeline {
    agent any

    environment {
        TRIVY_CACHE = "/tmp/trivy-cache"
        REPORT_DIR  = "${WORKSPACE}/trivy-reports"
    }

    stages {

        stage('Cleanup') {
            steps {
                echo "Nettoyage..."
                sh 'docker-compose down --remove-orphans || true'
                sh 'docker rmi smartphones-ml-app || true'
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

                    # Scan → JSON
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

                    # CSV global
                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat.csv

                    # CSV CRITICAL
                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_critical.csv

                    # CSV HIGH
                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_high.csv

                    # CSV MEDIUM
                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_medium.csv

                    # CSV LOW
                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' /reports/trivy-raw.json > ${REPORT_DIR}/resultat_low.csv

                    # Résumé console
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
    }

    post {
        always {
            sh 'docker-compose down --remove-orphans || true'
        }
        success {
            echo "Pipeline OK ✅"
        }
        failure {
            echo "Pipeline FAILED ❌"
        }
    }
}
