import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"

import pandas as pd
import mlflow
import mlflow.xgboost
from xgboost import XGBRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_absolute_error, r2_score

mlflow.set_tracking_uri("http://mlflow:5000")
mlflow.set_experiment("smartphones-price-prediction")

# Preprocessing
df = pd.read_csv("/app/data/smartphones.csv")
df["RAM"] = df["RAM"].fillna(df["RAM"].median())
df = df.dropna(subset=["Storage"])
df = df[df["Brand"] != "Nothing"]
df = df.drop(columns=["Smartphone"])
df["Free"] = df["Free"].map({"Yes": 1, "No": 0})
df = pd.get_dummies(df, columns=["Brand", "Model", "Color"], drop_first=True)
X = df.drop(columns=["Final Price"])
y = df["Final Price"]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Sauvegarder les colonnes dans le workspace partagé
pd.Series(X.columns.tolist()).to_csv("feature_columns.csv", index=False)

params = {
    "n_estimators": 500,
    "learning_rate": 0.05,
    "max_depth": 6,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "gamma": 0.1,
    "reg_alpha": 0.1,
    "reg_lambda": 1,
    "random_state": 42
}

with mlflow.start_run():
    model = XGBRegressor(**params)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    r2  = r2_score(y_test, y_pred)
    mlflow.log_params(params)
    mlflow.log_metric("mae", mae)
    mlflow.log_metric("r2",  r2)
    mlflow.xgboost.log_model(
        model,
        artifact_path="model",
        registered_model_name="smartphones_price_model"
    )
    mlflow.log_artifact("feature_columns.csv")
    print(f"Run terminé.")
    print(f"  MAE = {mae:.2f}")
    print(f"  R²  = {r2:.4f}")
    print(f"  run_id = {mlflow.active_run().info.run_id}")
