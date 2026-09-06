"""Pluggable cloud-side Detector contract, registry, and built-in detectors."""

from .contracts import (
    AnalysisContext,
    cross_lineage_enabled,
    Detector,
    DetectorInputs,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from .registry import DetectorRegistry
from .rule_correlation import RuleCorrelationDetector
from .shortest_path import ShortestPathDetector
from .nodlink.detector import NodlinkDetector

DetectorRegistry.register(
    {
        RuleCorrelationDetector.name: RuleCorrelationDetector,
        ShortestPathDetector.name: ShortestPathDetector,
        NodlinkDetector.name: NodlinkDetector,
    }
)

__all__ = [
    "AnalysisContext",
    "Detector",
    "DetectorRegistry",
    "DetectorInputs",
    "DetectionResult",
    "RequiredInput",
    "RuleCorrelationDetector",
    "ShortestPathDetector",
    "NodlinkDetector",
    "StateRequirements",
]
