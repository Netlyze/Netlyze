import numpy as np
from collections import Counter


class DecisionTree:
    def __init__(self, max_depth=10, min_samples_split=2):
        self.max_depth = max_depth
        self.min_samples_split = min_samples_split
        self.tree = None

    def fit(self, X, y):
        self.tree = self._grow_tree(X, y, depth=0)

    def predict(self, X):
        return np.array([self._traverse_tree(x, self.tree) for x in X])

    def _grow_tree(self, X, y, depth):
        if len(set(y)) == 1 or depth >= self.max_depth or len(y) < self.min_samples_split:
            return Counter(y).most_common(1)[0][0]

        feature, threshold = self._best_split(X, y)
        if feature is None:
            return Counter(y).most_common(1)[0][0]

        left_idx, right_idx = X[:, feature] < threshold, X[:, feature] >= threshold
        left_subtree = self._grow_tree(X[left_idx], y[left_idx], depth + 1)
        right_subtree = self._grow_tree(X[right_idx], y[right_idx], depth + 1)
        return (feature, threshold, left_subtree, right_subtree)

    def _best_split(self, X, y):
        best_mse, best_feature, best_threshold = float("inf"), None, None
        for feature in range(X.shape[1]):
            thresholds = np.unique(X[:, feature])
            for threshold in thresholds:
                left_idx, right_idx = X[:, feature] < threshold, X[:, feature] >= threshold
                if sum(left_idx) == 0 or sum(right_idx) == 0:
                    continue
                mse = self._mse(y[left_idx]) * sum(left_idx) + self._mse(y[right_idx]) * sum(right_idx)
                if mse < best_mse:
                    best_mse, best_feature, best_threshold = mse, feature, threshold
        return best_feature, best_threshold

    def _mse(self, y):
        return np.mean((y - np.mean(y)) ** 2) if len(y) > 0 else float("inf")

    def _traverse_tree(self, x, node):
        if not isinstance(node, tuple):
            return node
        feature, threshold, left, right = node
        return self._traverse_tree(x, left if x[feature] < threshold else right)


class RandomForest:
    def __init__(self, n_trees=10, max_depth=10, min_samples_split=2):
        self.n_trees = n_trees
        self.trees = [DecisionTree(max_depth, min_samples_split) for _ in range(n_trees)]

    def fit(self, X, y):
        for tree in self.trees:
            idxs = np.random.choice(len(X), len(X), replace=True)
            tree.fit(X[idxs], y[idxs])

    def predict(self, X):
        return np.mean([tree.predict(X) for tree in self.trees], axis=0)


def mean_squared_error(y_true, y_pred):
    return np.mean((y_true - y_pred) ** 2)


class GradientBoosting:
    def __init__(self, n_estimators=100, learning_rate=0.1, max_depth=3):
        self.n_estimators = n_estimators
        self.learning_rate = learning_rate
        self.max_depth = max_depth
        self.trees = []

    def fit(self, X, y):
        pred = np.full(y.shape, np.mean(y))
        for _ in range(self.n_estimators):
            residuals = y - pred
            tree = DecisionTree(max_depth=self.max_depth)
            tree.fit(X, residuals)
            self.trees.append(tree)
            pred += self.learning_rate * tree.predict(X)

    def predict(self, X):
        pred = np.full((X.shape[0],), np.mean(y))
        for tree in self.trees:
            pred += self.learning_rate * tree.predict(X)
        return pred


class KNN:
    def __init__(self, k=5):
        self.k = k

    def fit(self, X, y):
        self.X_train = X
        self.y_train = y

    def predict(self, X):
        predictions = [self._predict_single(x) for x in X]
        return np.array(predictions)

    def _predict_single(self, x):
        distances = np.sqrt(np.sum((self.X_train - x) ** 2, axis=1))
        k_indices = np.argsort(distances)[:self.k]
        return np.mean(self.y_train[k_indices])

