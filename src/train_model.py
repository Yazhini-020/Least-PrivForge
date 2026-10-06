"""
train_model.py — Train and save the XGBoost risk scoring model
AI IAM Least-Privilege Enforcer

Reads labeled examples from dataset/policies.json, trains an XGBoost
regressor, and saves it to models/xgboost_model.pkl, which
risk_scorer.py loads at runtime.

Usage:
    python -m src.train_model
"""

import pickle
import os
import json
import logging
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
import xgboost as xgb

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

MODEL_PATH = "models/xgboost_model.pkl"
DATASET_PATH = "dataset/policies.json"


def load_training_data():
    from src.ml_features import extract_features, features_to_vector

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Training dataset not found at {DATASET_PATH}. "
            f"Create it before running train_model.py."
        )

    with open(DATASET_PATH, "r") as f:
        examples = json.load(f)

    if not examples:
        raise ValueError(
            f"{DATASET_PATH} is empty. Add labeled examples "
            f"(finding + usage + risk_score) before training."
        )

    X, y = [], []
    for example in examples:
        features = extract_features(example["finding"], example.get("usage", {}))
        X.append(features_to_vector(features))
        y.append(example["risk_score"])

    return np.array(X), np.array(y)


def train():
    log.info("Loading training data from %s...", DATASET_PATH)
    X, y = load_training_data()

    log.info("Dataset size: %d examples, %d features", X.shape[0], X.shape[1])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    log.info("Training XGBoost regressor...")
    model = xgb.XGBRegressor(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        objective="reg:squarederror",
        random_state=42
    )
    model.fit(X_train, y_train)

    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    log.info("R^2 on train set: %.3f", train_score)
    log.info("R^2 on test set:  %.3f", test_score)

    cv_scores = cross_val_score(model, X, y, cv=5, scoring="r2")
    log.info("5-fold CV R^2: %.3f (+/- %.3f)", cv_scores.mean(), cv_scores.std())

    from src.ml_features import FEATURE_NAMES
    importances = model.feature_importances_
    log.info("Feature importances:")
    for name, imp in sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1]):
        log.info("  %-28s %.3f", name, imp)

    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    log.info("Model saved to %s (%d bytes)", MODEL_PATH, os.path.getsize(MODEL_PATH))


if __name__ == "__main__":
    train()