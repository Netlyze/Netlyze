import numpy as np
import time
import pickle
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, confusion_matrix, roc_auc_score,
                             roc_curve, precision_recall_curve)
from tqdm import tqdm


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

def mean_squared_error(y_true, y_pred):
    return np.mean((y_true - y_pred) ** 2)

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

# === Load Test Data ===

# Reload datasets (same paths used during training)
features_act = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/Active_Wiretap/Active_Wiretap_dataset.csv', header=None)
labels_act = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/Active_Wiretap/Active_Wiretap_labels.csv')
features_mitm = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_dataset.csv', header=None)
labels_mitm = pd.read_csv('/Users/r1shabh/dev/kitsune_dataset/ARP_MitM/ARP_MitM_labels.csv')

# Select the same features
selected_features_indices_act = [79,78,64,12,63,51,9,77,24,58,75,27,76,111,14,62,44,74,13,29]
selected_features_indices_mitm = [79,78,108,27,77,58,12,63,64,76,75,59,61,56,62,13,28,60,109,14]

X_act_selected = features_act.iloc[:, selected_features_indices_act]
X_mitm_selected = features_mitm.iloc[:, selected_features_indices_mitm]

y_act = labels_act.iloc[:, 1].values
y_mitm = labels_mitm.iloc[:, 1].values

X_selected = pd.concat([X_act_selected, X_mitm_selected], axis=0).values
y = np.concatenate([y_act, y_mitm])

# Train/test split & scaling must be consistent
X_train, X_test, y_train, y_test = train_test_split(X_selected, y, test_size=0.2, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# === Load Model from Pickle ===
with open("/Users/r1shabh/dev/kitsune_dataset/__pickle_model/hybrid_ensemble_model.pkl", "rb") as f:
    model = pickle.load(f)


# Predict
y_prob = model.predict(X_test_scaled)
y_pred = (y_prob >= 0.5).astype(int)

# Evaluate
print("Accuracy:", accuracy_score(y_test.astype(int), y_pred))
print("Precision:", precision_score(y_test.astype(int), y_pred))
print("Recall:", recall_score(y_test.astype(int), y_pred))
print("F1 Score:", f1_score(y_test.astype(int), y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test.astype(int), y_pred))

# === Predict and Evaluate ===
'''y_pred = model.predict(X_test_scaled)
y_pred_labels = (y_pred >= 0.5).astype(int)
accuracy = accuracy_score(y_test.astype(int), y_pred_labels)

print(f"✅ Loaded Model Accuracy on Test Set: {accuracy * 100:.2f}%")'''

# === Visualisations ===

# Confusion Matrix Heatmap
conf_matrix = confusion_matrix(y_test.astype(int), y_pred)
plt.figure(figsize=(6, 4))
sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues", cbar=False)
plt.title("Confusion Matrix")
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.tight_layout()
plt.show()

# ROC Curve
fpr, tpr, _ = roc_curve(y_test.astype(int), y_prob)
auc_score = roc_auc_score(y_test.astype(int), y_prob)

plt.figure()
plt.plot(fpr, tpr, color='darkorange', label=f'ROC curve (AUC = {auc_score:.4f})')
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc='lower right')
plt.grid(True)
plt.tight_layout()
plt.show()

# Precision-Recall Curve
precision_vals, recall_vals, _ = precision_recall_curve(y_test.astype(int), y_prob)

plt.figure()
plt.plot(recall_vals, precision_vals, color='purple')
plt.xlabel('Recall')
plt.ylabel('Precision')
plt.title('Precision-Recall Curve')
plt.grid(True)
plt.tight_layout()
plt.show()

# Prediction Probability Distribution
plt.figure()
plt.hist(y_prob, bins=50, color='skyblue')
plt.title("Distribution of Prediction Probabilities")
plt.xlabel("Predicted Probability")
plt.ylabel("Number of Samples")
plt.grid(True)
plt.tight_layout()
plt.show()

