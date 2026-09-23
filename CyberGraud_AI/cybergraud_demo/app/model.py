from __future__ import annotations

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

FEATURES = [
    "request_rate", "failed_logins", "payload_anomaly", "unique_ips", "packet_rate", "suspicious_headers"
]
LABELS = ["normal", "sql_injection", "xss", "brute_force", "ddos"]
rng = np.random.default_rng(42)


def build_dataset(seed=42):
    r = np.random.default_rng(seed)
    X, y = [], []
    specs = {
        "normal": ([25,2,.10,5,30,1], [8,2,.08,2,10,1]),
        "sql_injection": ([55,5,.88,10,80,6], [15,3,.08,4,25,2]),
        "xss": ([48,4,.78,8,65,8], [13,3,.12,3,20,2]),
        "brute_force": ([70,75,.25,4,45,4], [18,18,.12,2,15,2]),
        "ddos": ([220,4,.35,35,360,3], [45,3,.15,10,70,2]),
    }
    for label, (mean, std) in specs.items():
        data = r.normal(mean, std, (350, len(FEATURES)))
        X.append(data); y.extend([label] * len(data))
    return np.vstack(X), np.array(y)


X, y = build_dataset()
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2, random_state=42, stratify=y)
scaler = StandardScaler().fit(X_train)
model = RandomForestClassifier(n_estimators=220, random_state=42, class_weight="balanced_subsample")
model.fit(scaler.transform(X_train), y_train)
MODEL_ACCURACY = float(accuracy_score(y_test, model.predict(scaler.transform(X_test))))


def simulate_features(attack: str) -> dict[str, float]:
    presets = {
        "normal": [24,1,.08,5,28,1],
        "sql_injection": [58,5,.91,10,82,7],
        "xss": [50,4,.80,8,68,9],
        "brute_force": [74,82,.24,4,48,5],
        "ddos": [235,5,.36,38,375,3],
    }
    base = np.array(presets.get(attack.lower(), presets["normal"]), dtype=float)
    jitter = np.array([3,2,.03,1,5,1])
    values = base + rng.normal(0, jitter)
    values[0] = max(1, values[0]); values[1] = max(0, values[1]); values[2] = np.clip(values[2],0,1)
    values[3] = max(1, values[3]); values[4] = max(1, values[4]); values[5] = max(0, values[5])
    return dict(zip(FEATURES, values.round(3).tolist()))


def predict(features: dict[str, float]) -> dict:
    row = np.array([[float(features[f]) for f in FEATURES]])
    probs = model.predict_proba(scaler.transform(row))[0]
    idx = int(np.argmax(probs))
    attack = model.classes_[idx]
    confidence = float(probs[idx])
    normal_idx = list(model.classes_).index("normal")
    malicious_prob = float(1 - probs[normal_idx])
    risk = "High" if malicious_prob >= .78 else "Medium" if malicious_prob >= .45 else "Low"

    # Transparent XAI: model feature importance multiplied by deviation from the learned normal baseline.
    normal = np.array([24,1,.08,5,28,1], dtype=float)
    scale = np.array([30,50,1,30,300,8], dtype=float)
    deviation = np.abs(row[0] - normal) / scale
    influence = model.feature_importances_ * deviation
    if influence.max() > 0:
        influence = influence / influence.max()
    order = np.argsort(influence)[::-1]
    explanation = [{
        "feature": FEATURES[i].replace("_", " ").title(),
        "value": round(float(row[0,i]), 3),
        "influence": round(float(influence[i]), 3),
        "direction": "increased risk" if row[0,i] > normal[i] else "decreased risk / baseline"
    } for i in order[:4]]

    return {
        "prediction": "Malicious" if attack != "normal" else "Normal",
        "attack_type": attack.replace("_", " ").title(),
        "confidence": round(confidence*100, 2),
        "malicious_probability": round(malicious_prob*100, 2),
        "risk": risk,
        "explanation": explanation,
    }


def retrain(seed=42):
    global model, scaler, MODEL_ACCURACY
    X2, y2 = build_dataset(seed)
    xa, xb, ya, yb = train_test_split(X2, y2, test_size=.2, random_state=seed, stratify=y2)
    scaler = StandardScaler().fit(xa)
    model = RandomForestClassifier(n_estimators=240, random_state=seed, class_weight="balanced_subsample")
    model.fit(scaler.transform(xa), ya)
    MODEL_ACCURACY = float(accuracy_score(yb, model.predict(scaler.transform(xb))))
    return {"algorithm":"Random Forest", "samples":len(y2), "accuracy":round(MODEL_ACCURACY,4)}
