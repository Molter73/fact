"""Anomaly detectors. Higher scores mean more anomalous."""

from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.svm import OneClassSVM


class KnnDistance:
    """Mean distance to the k nearest benign rows.

    Unlike an RBF kernel this keeps ranking information far from the training
    data instead of saturating, which makes scores usable for triage."""

    def __init__(self, k=3):
        self.k = k

    def fit(self, x):
        self._nn = NearestNeighbors(n_neighbors=self.k).fit(x)
        return self

    def score_samples(self, x):
        return -self._nn.kneighbors(x)[0].mean(axis=1)


ESTIMATORS = {
    "knn": lambda: KnnDistance(k=3),
    "knn5": lambda: KnnDistance(k=5),
    "knn10": lambda: KnnDistance(k=10),
    "ocsvm": lambda: OneClassSVM(kernel="rbf", gamma=0.1, nu=0.05),
    "ocsvm-wide": lambda: OneClassSVM(kernel="rbf", gamma="scale", nu=0.05),
    "iforest": lambda: IsolationForest(n_estimators=300, random_state=0),
    "iforest-small": lambda: IsolationForest(
        n_estimators=500, max_samples=256, max_features=0.5, random_state=0
    ),
    "lof": lambda: LocalOutlierFactor(n_neighbors=20, novelty=True),
    "elliptic": lambda: EllipticEnvelope(support_fraction=0.9, random_state=0),
}

DEFAULT_MODELS = "knn,ocsvm,iforest,lof"
