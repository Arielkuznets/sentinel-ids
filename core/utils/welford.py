class Welford:
    """Online mean and variance via Welford's algorithm.

    Accumulates values one at a time in O(1) memory – n, the running mean, and
    M2 (the running sum of squared deviations) – without storing the samples,
    and stays numerically stable where the naive sum-of-squares form suffers
    catastrophic cancellation on large values with small spread.
    """

    def __init__(self):
        self.n    = 0
        self.mean = 0.0
        self._m2  = 0.0

    def update(self, x: float) -> None:
        self.n   += 1
        delta     = x - self.mean
        self.mean += delta / self.n
        self._m2  += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self._m2 / (self.n - 1)

    @property
    def std(self) -> float:
        return self.variance ** 0.5

    def state(self) -> tuple[int, float, float]:
        return (self.n, self.mean, self._m2)

    @classmethod
    def from_state(cls, n: int, mean: float, m2: float) -> "Welford":
        w = cls()
        w.n    = n
        w.mean = mean
        w._m2  = m2
        return w
