import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

def select_top_features(X, y, num_features=20, n_estimators=100):
    model = RandomForestClassifier(n_estimators=1, random_state=42, warm_start=True, n_jobs=-1)

    print(f"\nTraining Random Forest with {n_estimators} trees:")
    for i in tqdm(range(1, n_estimators + 1)):
        model.n_estimators = i
        model.fit(X, y)

    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]

    top_indices = indices[:num_features]
    top_features = X.columns[top_indices]

    print(f"\nTop {num_features} Features by Importance:\n")
    for rank, idx in enumerate(top_indices):
        print(f"{rank+1}. {X.columns[idx]} ({importances[idx]:.5f})")

    return X[top_features]


def load_and_validate_data(features_path, labels_path):
    # Load features
    X = pd.read_csv(features_path, header=None)
    print(f"✔️ Successfully loaded {X.shape[0]} feature samples.")

    # Load labels while skipping the first row
    labels_df = pd.read_csv(labels_path)

    # Drop empty rows (in case of trailing newline)
    labels_df.dropna(how='all', inplace=True)

    print(f"✔️ Successfully loaded {labels_df.shape[0]} labels.")

    # Align number of rows between features and labels
    if labels_df.shape[0] > X.shape[0]:
        print(f"⚠️ Labels have extra rows ({labels_df.shape[0]}). Trimming to match features.")
        labels_df = labels_df.iloc[:X.shape[0]]
    elif labels_df.shape[0] < X.shape[0]:
        print(f"⚠️ Features have extra rows ({X.shape[0]}). Trimming to match labels.")
        X = X.iloc[:labels_df.shape[0]]

    # Extract labels from first column
    y = labels_df.iloc[:, 1].values

    # Convert to binary if labels are numeric
    if np.issubdtype(y.dtype, np.floating) or np.issubdtype(y.dtype, np.integer):
        y = (y != 0).astype(int)

    print(f"Final shapes — X: {X.shape}, y: {y.shape}")
    return X, y


#Set your paths here
features_path = '/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_dataset.csv'
labels_path = '/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_labels.csv'

#Load and validate data
X, y = load_and_validate_data(features_path, labels_path)

# Scale the data
scaler = StandardScaler()
X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)

# Select top features with progress bar
X_top = select_top_features(X_scaled, y, num_features=20, n_estimators=100)

print(np.unique(y))

print(np.isnan(X_scaled).sum())


