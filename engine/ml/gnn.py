"""
Graph neural network for kill-chain edge prediction (O3, optional).

Question: given the stages an intrusion set has already been seen using,
how likely is it to also use stage B after stage A (an edge of the
propagation graph)?

The learned-probability model in engine/graph/path_prediction.py answers
this with one fixed number per edge. This model conditions on the actor's
other observed stages:

    node features : [stage used, is source A, is target B]   (B's own
                    "used" bit is hidden, so the label is never an input)
    layer 1       : H1 = relu(A_hat X W1)    message passing over the
    layer 2       : H2 = A_hat H1 W2         propagation graph
    edge score    : sigmoid(w . (H2[A] * H2[B]) + c)

A_hat is the symmetric-normalised adjacency with self loops. It is a
two-layer graph convolution (Kipf & Welling) written in numpy with
hand-derived gradients and Adam, so it adds no dependency (no torch).
"""

import numpy as np

from engine.intelligence.propagation_engine import PROPAGATION_RULES


class StageGNN:

    def __init__(self, hidden=8, epochs=60, lr=0.02, l2=1e-3, seed=42):

        self.hidden = hidden
        self.epochs = epochs
        self.lr = lr
        self.l2 = l2
        self.seed = seed

        self.stages = sorted(
            set(PROPAGATION_RULES)
            | {b for succ in PROPAGATION_RULES.values() for b in succ}
        )

        self.index = {s: i for i, s in enumerate(self.stages)}

        n = len(self.stages)

        adjacency = np.eye(n)

        for a, successors in PROPAGATION_RULES.items():
            for b in successors:
                adjacency[self.index[a], self.index[b]] = 1
                adjacency[self.index[b], self.index[a]] = 1

        inv = 1 / np.sqrt(adjacency.sum(axis=1))

        self.a_hat = adjacency * inv[:, None] * inv[None, :]

    # ---------------------------------------------------------------- data

    def _features(self, stages, a, b):

        x = np.zeros((len(self.stages), 3))

        for stage in stages:
            if stage in self.index:
                x[self.index[stage], 0] = 1

        x[self.index[b], 0] = 0
        x[self.index[a], 1] = 1
        x[self.index[b], 2] = 1

        return self.a_hat @ x

    def _samples(self, groups):
        """(P, a, b, y) for every edge whose source the group used."""

        out = []

        for stages in groups:
            for a, successors in PROPAGATION_RULES.items():

                if a not in stages:
                    continue

                for b in successors:
                    out.append((
                        self._features(stages, a, b),
                        self.index[a], self.index[b], float(b in stages)
                    ))

        return out

    # ------------------------------------------------------------- network

    def _forward(self, p, a, b):

        z1 = p @ self.params["W1"]
        h1 = np.maximum(z1, 0)
        q = self.a_hat @ h1
        h2 = q @ self.params["W2"]

        s = float((h2[a] * h2[b]) @ self.params["w"] + self.params["c"])

        return 1 / (1 + np.exp(-np.clip(s, -30, 30))), (z1, q, h2)

    def fit(self, groups):

        rng = np.random.default_rng(self.seed)

        h = self.hidden

        self.params = {
            "W1": rng.normal(0, 0.5, (3, h)),
            "W2": rng.normal(0, 0.5, (h, h)),
            "w": rng.normal(0, 0.5, h),
            "c": np.zeros(()),
        }

        samples = self._samples(groups)

        if not samples:
            return self

        adam = {k: [np.zeros_like(v), np.zeros_like(v)] for k, v in self.params.items()}
        step = 0

        for _ in range(self.epochs):

            for i in rng.permutation(len(samples)):

                p, a, b, y = samples[i]

                prob, (z1, q, h2) = self._forward(p, a, b)

                ds = prob - y

                grads = {"c": np.asarray(ds)}
                grads["w"] = ds * h2[a] * h2[b]

                dh2 = np.zeros_like(h2)
                dh2[a] += ds * self.params["w"] * h2[b]
                dh2[b] += ds * self.params["w"] * h2[a]

                grads["W2"] = q.T @ dh2
                dh1 = self.a_hat.T @ (dh2 @ self.params["W2"].T)
                dz1 = dh1 * (z1 > 0)
                grads["W1"] = p.T @ dz1

                step += 1

                for name, g in grads.items():

                    g = g + self.l2 * self.params[name]
                    m, v = adam[name]

                    m[...] = 0.9 * m + 0.1 * g
                    v[...] = 0.999 * v + 0.001 * g * g

                    self.params[name] = self.params[name] - self.lr * (
                        m / (1 - 0.9 ** step)
                    ) / (np.sqrt(v / (1 - 0.999 ** step)) + 1e-8)

        return self

    def predict(self, stages, a, b):
        """Probability the actor that used `stages` also used b after a."""

        return self._forward(self._features(stages, a, b), self.index[a], self.index[b])[0]
