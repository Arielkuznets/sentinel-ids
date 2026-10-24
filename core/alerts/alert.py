from dataclasses import dataclass, field
from typing import Any


@dataclass
class Alert:
    """Represents a single detection event produced by any detector.

    score is stamped later, by the alert loop: it needs the repeat count, which
    only exists once the Deduplicator has seen the alert. A detector emits 0.
    """
    type:      str
    severity:  str
    src_ip:    str | None
    timestamp: float
    details:   dict[str, Any] = field(default_factory=dict)
    score:     int            = 0
