"""MITRE ATT&CK Hierarchy Parser for LLM Consumption.

This package extracts the MITRE ATT&CK kill chain hierarchy from STIX 2.1 format
and renders it as structured Markdown optimized for LLM/RAG consumption.
"""

from attack_hierarchy.markdown_generator import MarkdownGenerator
from attack_hierarchy.models import SubTechnique, Tactic, Technique
from attack_hierarchy.stix_parser import STIXParser

__version__ = "0.1.0"
__all__ = [
    "Tactic",
    "Technique",
    "SubTechnique",
    "STIXParser",
    "MarkdownGenerator",
]
