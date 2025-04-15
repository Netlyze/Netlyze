import numpy as np
import time
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
from tqdm import tqdm  # For progress bars

def serialize_tree(tree):
    if not isinstance(tree, tuple):
        return {"leaf": tree}
    split_idx, split_val, left, right = tree
    return {
        "split_idx": split_idx,
        "split_val": split_val,
        "left": serialize_tree(left),
        "right": serialize_tree(right)
    }

def save_model(model, path):
    forest = {
        "rf_trees": [serialize_tree(tree.tree) for tree in model.rf_trees],
        "gb_trees": [serialize_tree(tree.tree) for tree in model.gb_trees],
        "learning_rate": model.learning_rate
    }
    with open(path, "w") as f:
        json.dump(forest, f)

# Decision Tree implementation
class DecisionTree:
    def __init__(self, max_depth=3):
        self.max_depth = max_depth
        self.tree = None

    def fit(self, X, y):
        self.tree = self._build_tree(X, y, depth=0)

    def predict(self, X):
        return np.array([self._predict_input(x, self.tree) for x in X])

    def _gini(self, y):
        if y.ndim > 1 and y.shape[1] > 1:
            y = np.argmax(y, axis=1)
        classes, counts = np.unique(y, return_counts=True)
        probs = counts / counts.sum()
        return 1 - np.sum(probs ** 2)
    def _best_split(self, X, y, num_thresholds=20):
        start_time = time.time()
        m, n = X.shape
        if m <= 1:
            return None, None

        parent_gini = self._gini(y)
        best_gain = 0
        best_feature = None
        best_threshold = None

        for feature_index in range(n):
            X_column = X[:, feature_index]
            thresholds = np.unique(X_column)
            if len(thresholds) > num_thresholds:
                thresholds = np.percentile(X_column, np.linspace(0, 100, num_thresholds))

            for threshold in thresholds:
                left_mask = X_column <= threshold
                right_mask = ~left_mask

                if np.sum(left_mask) == 0 or np.sum(right_mask) == 0:
                    continue

                y_left, y_right = y[left_mask], y[right_mask]
                gini_left = self._gini(y_left)
                gini_right = self._gini(y_right)

                weighted_gini = (len(y_left) / m) * gini_left + (len(y_right) / m) * gini_right
                gain = parent_gini - weighted_gini

                if gain > best_gain:
                    best_gain = gain
                    best_feature = feature_index
                    best_threshold = threshold
        #print(f"Best split computed in {time.time() - start_time:.2f} sec")
        return best_feature, best_threshold

    def _build_tree(self, X, y, depth):
        if depth >= self.max_depth or len(set(y)) == 1:
            return np.mean(y)

        split_idx, split_val = self._best_split(X, y)
        if split_idx is None:
            return np.mean(y)

        left_mask = X[:, split_idx] < split_val
        right_mask = ~left_mask

        left_subtree = self._build_tree(X[left_mask], y[left_mask], depth + 1)
        right_subtree = self._build_tree(X[right_mask], y[right_mask], depth + 1)

        return (split_idx, split_val, left_subtree, right_subtree)

    def _predict_input(self, x, tree):
        if not isinstance(tree, tuple):
            return tree
        feature, threshold, left, right = tree
        if x[feature] < threshold:
            return self._predict_input(x, left)
        else:
            return self._predict_input(x, right)


# HybridEnsemble model with progress bars, epochs, and MSE tracking
class HybridEnsemble:
    def __init__(self, n_rf=5, n_gb=5, learning_rate=0.1, max_depth=3):
        self.n_rf = n_rf
        self.n_gb = n_gb
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.rf_trees = []
        self.gb_trees = []

    def fit(self, X, y, epochs=5, X_val=None, y_val=None):
        m = X.shape[0]

        for epoch in range(epochs):
            print(f"\nEpoch {epoch+1}/{epochs}")

            # Random Forest Phase
            print("  Training Random Forest Trees:")
            for _ in tqdm(range(self.n_rf)):
                indices = np.random.choice(m, m, replace=True)
                X_sample, y_sample = X[indices], y[indices]
                tree = DecisionTree(max_depth=self.max_depth)
                tree.fit(X_sample, y_sample)
                self.rf_trees.append(tree)

            pred = self._rf_predict(X)

            # Gradient Boosting Phase
            print("  Training Gradient Boosting Trees:")
            for _ in tqdm(range(self.n_gb)):
                residuals = y - pred
                tree = DecisionTree(max_depth=self.max_depth)
                tree.fit(X, residuals)
                self.gb_trees.append(tree)
                pred += self.learning_rate * tree.predict(X)

            # Epoch-end MSE Logging
            if X_val is not None and y_val is not None:
                val_pred = self.predict(X_val)
                val_mse = mean_squared_error(y_val, val_pred)
                print(f"  Validation MSE after epoch {epoch+1}: {val_mse:.4f}")

    def predict(self, X):
        pred = self._rf_predict(X)
        for tree in self.gb_trees:
            pred += self.learning_rate * tree.predict(X)
        return pred

    def _rf_predict(self, X):
        preds = np.array([tree.predict(X) for tree in self.rf_trees])
        return np.mean(preds, axis=0)


# MSE metric function
def mean_squared_error(y_true, y_pred):
    return np.mean((y_true - y_pred) ** 2)


# === Data Preparation ===

# Load features and labels
features_act = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/Active_Wiretap/Active_Wiretap_dataset.csv', header=None)
labels_act = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/Active_Wiretap/Active_Wiretap_labels.csv')
features_mitm = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_dataset.csv', header=None)
labels_mitm = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_labels.csv')

print("features_act shape:", features_act.shape)
print("labels_act shape:", labels_act.shape)
assert len(features_act) == len(labels_act)
print("features_mitm shape:", features_mitm.shape)
print("labels_mitm shape:", labels_mitm.shape)
assert len(features_mitm) == len(labels_mitm)

# Selected feature indices
selected_features_indices_act = [79,78,64,12,63,51,9,77,24,58,75,27,76,111,14,62,44,74,13,29]
selected_features_indices_mitm = [79,78,108,27,77,58,12,63,64,76,75,59,61,56,62,13,28,60,109,14]

# Select features
X_act_selected = features_act.iloc[:, selected_features_indices_act]
X_mitm_selected = features_mitm.iloc[:, selected_features_indices_mitm]

# Labels
y_act = labels_act.iloc[:, 1].values
y_mitm = labels_mitm.iloc[:, 1].values

# Combine datasets
X_selected = pd.concat([X_act_selected, X_mitm_selected], axis=0).values
y = np.concatenate([y_act, y_mitm])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2, random_state=42)

# Scaling
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train the model
model = HybridEnsemble(n_rf=40, n_gb=40, learning_rate=0.01, max_depth=3)
model.fit(X_train_scaled, y_train, epochs=6, X_val=X_test_scaled, y_val=y_test)

# Final test MSE
y_pred = model.predict(X_test_scaled)
mse = mean_squared_error(y_test, y_pred)
print("\nFinal Test Set MSE:", mse)

save_model(model, "/Users/r1shabh/dev/kitsune_dataset/__pickle_model/hybrid_ensemble_model.json")

with open("/Users/r1shabh/dev/kitsune_dataset/__pickle_model/hybrid_ensemble_model.pkl", "wb") as f:
    pickle.dump(model, f)

y_pred_labels = (y_pred >= 0.5).astype(int)
y_test_labels = y_test.astype(int)

accuracy = accuracy_score(y_test_labels, y_pred_labels)
print(f"✅ Model Accuracy on Test Set: {accuracy * 100:.2f}%")
