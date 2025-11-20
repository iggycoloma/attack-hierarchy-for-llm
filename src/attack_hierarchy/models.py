"""Domain models for MITRE ATT&CK hierarchy.

These dataclasses represent the core entities in the MITRE ATT&CK framework:
tactics, techniques, and sub-techniques, with their hierarchical relationships.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Tactic:
    """Represents a MITRE ATT&CK tactic.

    Tactics represent the "why" of an attack - the adversary's tactical goal.
    Examples: Initial Access, Persistence, Privilege Escalation.

    Attributes:
        id: External MITRE ID (e.g., "TA0001")
        name: Human-readable name (e.g., "Initial Access")
        description: Detailed description of the tactic
        stix_id: Full STIX identifier (e.g., "x-mitre-tactic--...")
        kill_chain_phase: Phase name used in kill chain references
    """

    id: str
    name: str
    description: str
    stix_id: str
    kill_chain_phase: str


@dataclass
class Technique:
    """Represents a MITRE ATT&CK technique.

    Techniques represent "how" an adversary achieves a tactical goal.
    A technique may belong to multiple tactics.

    Attributes:
        id: External MITRE ID (e.g., "T1595")
        name: Human-readable name (e.g., "Active Scanning")
        description: Detailed description of the technique
        stix_id: Full STIX identifier (e.g., "attack-pattern--...")
        tactic_ids: List of tactic IDs this technique belongs to
        kill_chain_phases: List of kill chain phase names
        platforms: List of platforms this technique applies to (e.g., Windows, Linux, macOS)
        detection: Detection guidance and recommendations
        mitigations: List of mitigation IDs and names
        used_by_groups: List of threat group IDs and names that use this technique
        used_by_software: List of malware/tool IDs and names that implement this technique
        external_references: List of external references (URLs, citations)
    """

    id: str
    name: str
    description: str
    stix_id: str
    tactic_ids: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    detection: str = ""
    mitigations: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    used_by_groups: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    used_by_software: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    external_references: List[dict] = field(default_factory=list)  # List of reference dicts


@dataclass
class SubTechnique:
    """Represents a MITRE ATT&CK sub-technique.

    Sub-techniques are specific implementations or variations of a parent technique.
    They follow the ID pattern: T####.### (e.g., T1595.001)

    Attributes:
        id: External MITRE ID (e.g., "T1595.001")
        name: Human-readable name (e.g., "Scanning IP Blocks")
        description: Detailed description of the sub-technique
        stix_id: Full STIX identifier
        parent_technique_id: The parent technique ID (e.g., "T1595")
        platforms: List of platforms this sub-technique applies to
        detection: Detection guidance and recommendations
        mitigations: List of mitigation IDs and names
        used_by_groups: List of threat group IDs and names that use this sub-technique
        used_by_software: List of malware/tool IDs and names that implement this sub-technique
        external_references: List of external references (URLs, citations)
    """

    id: str
    name: str
    description: str
    stix_id: str
    parent_technique_id: str
    platforms: List[str] = field(default_factory=list)
    detection: str = ""
    mitigations: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    used_by_groups: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    used_by_software: List[tuple[str, str]] = field(default_factory=list)  # [(id, name), ...]
    external_references: List[dict] = field(default_factory=list)  # List of reference dicts
