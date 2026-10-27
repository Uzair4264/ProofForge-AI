"""Abstract severity framework interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class SeverityResult:
    vector: str
    score: float
    rating: str


class SeverityFramework(ABC):
    id: str = "base"

    @abstractmethod
    def score(self, vector: str) -> SeverityResult:
        """Parse a vector string and return score + qualitative rating."""
