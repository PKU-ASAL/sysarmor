"""Pluggable cloud-side Detector contract, registry, and built-in detectors."""

from .contracts import (
    AnalysisContext,
    cross_lineage_enabled,
    Detector,
    DetectorInputs,
    DetectionFinding,
    DetectionResult,
    RequiredInput,
    StateRequirements,
)
from .registry import DetectorRegistry
from .rule_correlation import RuleCorrelationDetector
from .nodlink.detector import NodlinkDetector

DetectorRegistry.register(
    {
        RuleCorrelationDetector.name: RuleCorrelationDetector,
        NodlinkDetector.name: NodlinkDetector,
    }
)

__all__ = [
    "AnalysisContext",
    "Detector",
    "DetectorRegistry",
    "DetectorInputs",
    "DetectionFinding",
    "DetectionResult",
    "RequiredInput",
    "RuleCorrelationDetector",
    "NodlinkDetector",
    "StateRequirements",
]
