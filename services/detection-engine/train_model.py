import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# Feature vector: [severity, events_last_5min_from_ip, distinct_ports_touched, asset_criticality_ordinal]
# Simulate benign traffic to train baseline
np.random.seed(42)
benign = np.column_stack([
    np.random.randint(1, 4, 500),      # low severity
    np.random.randint(1, 5, 500),      # low event frequency
    np.random.randint(1, 3, 500),      # few ports
    np.random.randint(0, 2, 500),      # low/medium criticality
])

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(benign)
joblib.dump(model, "isolation_forest.pkl")
print("Model trained and saved")