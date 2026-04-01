import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"

import mlflow

mlflow.set_tracking_uri("http://mlflow:5000")

client = mlflow.tracking.MlflowClient()

# MLflow 3.x : récupérer l'ID via le nom d'abord
experiment = client.get_experiment_by_name("smartphones-price-prediction")
if experiment is None:
    raise Exception("Expérience 'smartphones-price-prediction' introuvable !")

runs = client.search_runs(
    experiment_ids=[experiment.experiment_id],
    order_by=["start_time DESC"],
    max_results=1
)

if not runs:
    raise Exception("Aucun run MLflow trouvé !")

mae = runs[0].data.metrics["mae"]
r2  = runs[0].data.metrics["r2"]

assert mae < 110,  f"MAE trop élevée : {mae:.2f} (seuil : 110)"
assert r2  > 0.75, f"R² trop bas : {r2:.4f} (seuil : 0.75)"

print(f"Validation OK — MAE={mae:.2f}, R2={r2:.4f}")
