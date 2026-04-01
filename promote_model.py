import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"

import mlflow

mlflow.set_tracking_uri("http://mlflow:5000")

client = mlflow.tracking.MlflowClient()

model_name = "smartphones_price_model"

# MLflow 3.x : search_model_versions remplace get_latest_versions
versions = client.search_model_versions(f"name='{model_name}'")

if not versions:
    raise Exception("Aucune version trouvée pour le modèle !")

# Prendre la version la plus récente
latest = sorted(versions, key=lambda v: int(v.version), reverse=True)[0]
version_number = latest.version

print(f"Version trouvée : {version_number} — statut : {latest.current_stage}")

# MLflow 3.x : utiliser les alias à la place des stages
try:
    client.set_registered_model_alias(
        name=model_name,
        alias="Production",
        version=version_number
    )
    print(f"Modèle v{version_number} promu via alias 'Production' ✅")
except Exception as e:
    # Fallback MLflow 2.x
    client.transition_model_version_stage(
        name=model_name,
        version=version_number,
        stage="Production",
        archive_existing_versions=True
    )
    print(f"Modèle v{version_number} promu en Production (stage) ✅")
