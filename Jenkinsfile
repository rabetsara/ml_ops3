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
                    CONTAINER=$(docker ps -q --filter "publish=8081")
                    if [ -n "$CONTAINER" ]; then
                        echo "Port 8081 occupe par $CONTAINER nettoyage..."
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
                echo "Scan securite..."
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
                        imega/jq -r '["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],(.Results[]?.Vulnerabilities[]? | [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))]) | @csv' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],(.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))]) | @csv' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat_critical.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],(.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))]) | @csv' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat_high.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],(.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") | [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))]) | @csv' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat_medium.csv

                    docker run --rm \
                        -v ${REPORT_DIR}:/reports \
                        imega/jq -r '["PackageName","VulnerabilityID","Severity","InstalledVersion","FixedVersion","Title"],(.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") | [.PkgName, .VulnerabilityID, .Severity, .InstalledVersion, (.FixedVersion // ""), (.Title // "" | gsub(","; " "))]) | @csv' \
                        /reports/trivy-raw.json > ${REPORT_DIR}/resultat_low.csv

                    echo "=== Resume du scan Trivy ==="
                    echo "CRITICAL : $(tail -n +2 ${REPORT_DIR}/resultat_critical.csv | wc -l)"
                    echo "HIGH     : $(tail -n +2 ${REPORT_DIR}/resultat_high.csv | wc -l)"
                    echo "MEDIUM   : $(tail -n +2 ${REPORT_DIR}/resultat_medium.csv | wc -l)"
                    echo "LOW      : $(tail -n +2 ${REPORT_DIR}/resultat_low.csv | wc -l)"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/resultat.csv, trivy-reports/resultat_critical.csv, trivy-reports/resultat_high.csv, trivy-reports/resultat_medium.csv, trivy-reports/resultat_low.csv',
                                     allowEmptyArchive: true
                }
            }
        }

        stage('Start MLflow') {
            steps {
                echo "Demarrage MLflow..."
                sh 'docker-compose up -d mlflow'
                echo "Attente MLflow healthy..."
                sh '''
                    for i in $(seq 1 24); do
                        STATUS=$(docker inspect --format="{{.State.Health.Status}}" mlflow_server || echo "starting")
                        if [ "$STATUS" = "healthy" ]; then
                            echo "MLflow pret !"
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
                echo "Validation des metriques..."
                sh 'docker-compose run --rm app python /app/validate_metrics.py'
            }
        }

        stage('Promote Model') {
            steps {
                echo "Promotion du modele en Production..."
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
                echo "Deploiement de l API sur le port ${API_PORT}..."
                sh '''
                    docker stop smartphones-api || true
                    docker rm   smartphones-api || true

                    NETWORK=$(docker inspect mlflow_server --format="{{range \$k, \$v := .NetworkSettings.Networks}}{{\$k}}{{end}}")
                    echo "Reseau detecte : ${NETWORK}"

                    docker run -d \
                        --name smartphones-api \
                        --network ${NETWORK} \
                        -p 8081:8080 \
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
                            echo "API prete"
                            exit 0
                        fi
                        echo "Tentative $i/20..."
                        sleep 5
                    done
                    echo "API non disponible apres 100 secondes"
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
            echo "Pipeline OK - API disponible sur http://localhost:8081/invocations"
        }
        failure {
            echo "Pipeline FAILED"
            sh 'docker stop smartphones-api || true'
            sh 'docker rm   smartphones-api || true'
        }
    }
}
