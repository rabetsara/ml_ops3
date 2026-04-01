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

                    docker run --rm \
                        -v /var/run/docker.sock:/var/run/docker.sock \
                        -v ${TRIVY_CACHE}:/root/.cache/trivy \
                        -v ${REPORT_DIR}:/reports \
                        aquasec/trivy:0.69.3 image \
                        --exit-code 0 \
                        --severity HIGH,CRITICAL \
                        --scanners vuln \
                        --format json \
                        --output /reports/trivy-raw.json \
                        smartphones-ml-app

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq \
                        -r '
                          ["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],
                          (.Results[]?.Vulnerabilities[]? |
                          [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))])
                          | @csv
                        ' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat.csv

                    head -20 ${REPORT_DIR}/resultat.csv
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/resultat.csv',
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

        // ✅ NOUVEAU : Quality Gate — échoue si MAE ou R² hors seuil
        stage('Validate Metrics') {
            steps {
                echo "Validation des métriques..."
                sh 'docker-compose run --rm app python /app/validate_metrics.py'
            }
        }

        // ✅ NOUVEAU : Promotion du modèle validé en Production
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