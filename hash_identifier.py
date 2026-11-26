"""
Author: 

Simple hash function identifier.
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class HashCandidate:
    algorithm:  str
    confidence: Confidence
    reason:     str

