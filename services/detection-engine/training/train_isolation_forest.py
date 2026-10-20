import pandas as pd
import numpy as np
import glob
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
    'Packet Length Mean',
    'Average Packet Size'
]

csv_files = glob.glob('cicids2017/MachineLearningCVE/*.csv', recursive=True)
print(f"Found {len(csv_files)} CSV files")

benign_chunks = []

for f in csv_files:
    print(f"Processing {f}...")

    # Peek at columns first, strip spaces, figure out which needed cols exist in this file
    header = pd.read_csv(f, nrows=0)
    header.columns = header.columns.str.strip()
    cols_needed = [c for c in FEATURES + ['Label'] if c in header.columns]

    # Only load needed columns, and use a memory-efficient dtype where possible
    df = pd.read_csv(f, usecols=lambda c: c.strip() in cols_needed, low_memory=False)
    df.columns = df.columns.str.strip()

    # Filter to BENIGN immediately, before accumulating
    df_benign = df[df['Label'] == 'BENIGN']

    # Keep only the feature columns actually present, drop Label now
    available_features = [c for c in FEATURES if c in df_benign.columns]
    df_benign = df_benign[available_features].copy()

    # Downcast to float32 to roughly halve memory vs default float64
    for col in df_benign.columns:
        df_benign[col] = pd.to_numeric(df_benign[col], errors='coerce').astype('float32')

    benign_chunks.append(df_benign)
    del df, df_benign   # free memory before next file

    print(f"  -> {len(benign_chunks[-1])} BENIGN rows kept")

benign = pd.concat(benign_chunks, ignore_index=True)
del benign_chunks
print(f"Total BENIGN rows: {len(benign)}")

FEATURES = [f for f in FEATURES if f in benign.columns]
print(f"Using {len(FEATURES)} features: {FEATURES}")

X = benign[FEATURES]

# --- Handle missing/infinite values ---
X = X.replace([np.inf, -np.inf], np.nan)
X = X.dropna()
print(f"Rows after dropping NaN/Inf: {len(X)}")

# --- Optional: subsample if still too large for your RAM ---
if len(X) > 300_000:
    X = X.sample(n=300_000, random_state=42)
    print(f"Subsampled to {len(X)} rows for training")

# --- Standardize ---
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# --- Train Isolation Forest ---
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)
model.fit(X_scaled)

# --- Save model, scaler, and feature list together ---
joblib.dump({
    'model': model,
    'scaler': scaler,
    'features': FEATURES
}, '../isolation_forest.pkl')

print("Saved isolation_forest.pkl")

preds = model.predict(X_scaled)
anomaly_rate = (preds == -1).mean()
print(f"Anomaly rate on training (benign) data: {anomaly_rate:.2%}")