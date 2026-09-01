"""Pluggable cloud-side Detector contract, factory, and built-in detectors."""

from .contracts import (
    AnalysisContext,
    Detector,
    DetectorInputs,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from .factory import DetectorFactory
from .rule_correlation import RuleCorrelationDetector
from .shortest_path import ShortestPathDetector

DetectorFactory.register(
    {
        RuleCorrelationDetector.name: RuleCorrelationDetector,
        ShortestPathDetector.name: ShortestPathDetector,
    }
)

__all__ = [
    "AnalysisContext",
    "Detector",
    "DetectorFactory",
    "DetectorInputs",
    "DetectionResult",
    "RequiredInput",
    "RuleCorrelationDetector",
    "ShortestPathDetector",
    "StateRequirements",
]
