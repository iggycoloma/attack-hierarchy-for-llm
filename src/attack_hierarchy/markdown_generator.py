"""Markdown generator for MITRE ATT&CK hierarchy.

This module formats the parsed ATT&CK hierarchy into structured Markdown
optimized for LLM consumption, with clear hierarchical relationships and
explicit IDs for reference.
"""

import logging
from pathlib import Path
from typing import Dict, List

from attack_hierarchy.models import SubTechnique, Tactic, Technique

logger = logging.getLogger(__name__)


class MarkdownGenerator:
    """Generates structured Markdown from ATT&CK hierarchy.

    The output format is optimized for LLM/RAG consumption:
    - Clear hierarchical structure with proper heading levels
    - Explicit IDs included for reference (e.g., [TA0001], [T1595])
    - Descriptions included at each level for context richness
    - Tactics ordered by kill chain
    - Techniques and sub-techniques sorted alphabetically
    """

    # Standard kill chain order for MITRE ATT&CK Enterprise
    # This ensures tactics appear in the expected sequence
    KILL_CHAIN_ORDER = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]

    def __init__(
        self,
        tactics: Dict[str, Tactic],
        techniques: Dict[str, Technique],
        subtechniques: Dict[str, SubTechnique],
    ) -> None:
        """Initialize the generator with parsed ATT&CK data.

        Args:
            tactics: Dictionary of tactics keyed by ID
            techniques: Dictionary of techniques keyed by ID
            subtechniques: Dictionary of sub-techniques keyed by ID
        """
        self.tactics = tactics
        self.techniques = techniques
        self.subtechniques = subtechniques

        # Build reverse lookup indexes for O(1) access
        self._tactic_to_techniques: Dict[str, List[Technique]] = {}
        self._technique_to_subtechniques: Dict[str, List[SubTechnique]] = {}
        self._build_indexes()

    def _build_indexes(self) -> None:
        """Build reverse lookup indexes for O(1) access with pre-sorted results."""
        # Index techniques by tactic
        for technique in self.techniques.values():
            for tactic_id in technique.tactic_ids:
                if tactic_id not in self._tactic_to_techniques:
                    self._tactic_to_techniques[tactic_id] = []
                self._tactic_to_techniques[tactic_id].append(technique)

        # Sort all technique lists once (alphabetically by name)
        for _, techniques in self._tactic_to_techniques.items():
            techniques.sort(key=lambda t: t.name)

        # Index subtechniques by parent technique
        for subtechnique in self.subtechniques.values():
            parent_id = subtechnique.parent_technique_id
            if parent_id not in self._technique_to_subtechniques:
                self._technique_to_subtechniques[parent_id] = []
            self._technique_to_subtechniques[parent_id].append(subtechnique)

        # Sort all subtechnique lists once (alphabetically by name)
        for _, subtechniques in self._technique_to_subtechniques.items():
            subtechniques.sort(key=lambda st: st.name)

    def generate(self, output_path: Path | str) -> None:
        """Generate Markdown file with the ATT&CK hierarchy.

        Args:
            output_path: Path where the markdown file will be written
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info(f"Generating Markdown to {output_path}")

        content = self._build_markdown()

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

        logger.info(f"Markdown generated successfully: {output_path}")

    def _build_markdown(self) -> str:
        """Build the complete Markdown content.

        Returns:
            Complete Markdown string
        """
        lines: List[str] = []

        # Document header
        lines.append("# MITRE ATT&CK Enterprise Framework")
        lines.append("")
        lines.append(
            "This document contains the MITRE ATT&CK kill chain hierarchy: "
            "tactics, techniques, and sub-techniques."
        )
        lines.append("")
        lines.append(
            f"**Statistics:** {len(self.tactics)} tactics, "
            f"{len(self.techniques)} techniques, "
            f"{len(self.subtechniques)} sub-techniques"
        )
        lines.append("")
        lines.append("---")
        lines.append("")

        sorted_tactics = self._sort_tactics()

        for tactic in sorted_tactics:
            self._add_tactic_section(lines, tactic)

        return "\n".join(lines)

    def _sort_tactics(self) -> List[Tactic]:
        """Sort tactics by kill chain order.

        Returns:
            List of tactics in kill chain order
        """
        phase_to_tactic: Dict[str, Tactic] = {}
        for tactic in self.tactics.values():
            phase_to_tactic[tactic.kill_chain_phase] = tactic

        # Sort by kill chain order, then alphabetically for any unknowns
        sorted_tactics: List[Tactic] = []

        for phase in self.KILL_CHAIN_ORDER:
            if phase in phase_to_tactic:
                sorted_tactics.append(phase_to_tactic[phase])

        # Add any tactics not in the standard order (alphabetically)
        remaining = [
            t for t in self.tactics.values() if t.kill_chain_phase not in self.KILL_CHAIN_ORDER
        ]
        sorted_tactics.extend(sorted(remaining, key=lambda t: t.name))

        return sorted_tactics

    def _add_tactic_section(self, lines: List[str], tactic: Tactic) -> None:
        """Add a tactic section with its techniques and sub-techniques.

        Args:
            lines: List of lines to append to
            tactic: Tactic to add
        """
        # Tactic header (## level)
        lines.append(f"## [{tactic.id}] {tactic.name}")
        lines.append("")
        lines.append(tactic.description)
        lines.append("")

        # Find all techniques for this tactic (pre-sorted)
        tactic_techniques = self._get_techniques_for_tactic(tactic.id)

        if not tactic_techniques:
            logger.warning(f"No techniques found for tactic {tactic.id}")
            return

        for technique in tactic_techniques:
            self._add_technique_section(lines, technique)

    def _add_technique_section(self, lines: List[str], technique: Technique) -> None:
        """Add a technique section with its sub-techniques.

        Args:
            lines: List of lines to append to
            technique: Technique to add
        """
        # Technique header (### level)
        lines.append(f"### [{technique.id}] {technique.name}")
        lines.append("")
        lines.append(technique.description)
        lines.append("")

        self._add_metadata_sections(lines, technique)

        # Find all sub-techniques for this technique (pre-sorted)
        technique_subtechniques = self._get_subtechniques_for_technique(technique.id)

        if technique_subtechniques:
            for subtechnique in technique_subtechniques:
                self._add_subtechnique_section(lines, subtechnique)

    def _add_subtechnique_section(self, lines: List[str], subtechnique: SubTechnique) -> None:
        """Add a sub-technique section.

        Args:
            lines: List of lines to append to
            subtechnique: Sub-technique to add
        """
        # Sub-technique header (#### level)
        lines.append(f"#### [{subtechnique.id}] {subtechnique.name}")
        lines.append("")
        lines.append(subtechnique.description)
        lines.append("")

        self._add_metadata_sections(lines, subtechnique)

    def _get_techniques_for_tactic(self, tactic_id: str) -> List[Technique]:
        """Get all techniques that belong to a tactic - O(1) lookup.

        Args:
            tactic_id: Tactic ID (e.g., "TA0001")

        Returns:
            List of techniques for this tactic (pre-sorted alphabetically)
        """
        return self._tactic_to_techniques.get(tactic_id, [])

    def _get_subtechniques_for_technique(self, technique_id: str) -> List[SubTechnique]:
        """Get all sub-techniques that belong to a technique - O(1) lookup.

        Args:
            technique_id: Technique ID (e.g., "T1595")

        Returns:
            List of sub-techniques for this technique (pre-sorted alphabetically)
        """
        return self._technique_to_subtechniques.get(technique_id, [])

    def _add_metadata_sections(self, lines: List[str], obj: Technique | SubTechnique) -> None:
        """Add metadata sections for a technique or sub-technique.

        Args:
            lines: List of lines to append to
            obj: Technique or SubTechnique object
        """
        # Platforms
        if obj.platforms:
            lines.append("**Platforms:** " + ", ".join(obj.platforms))
            lines.append("")

        # Detection
        if obj.detection:
            lines.append("**Detection:**")
            lines.append("")
            lines.append(obj.detection)
            lines.append("")

        # Mitigations
        if obj.mitigations:
            lines.append("**Mitigations:**")
            lines.append("")
            for mitigation_id, mitigation_name in obj.mitigations:
                lines.append(f"- [{mitigation_id}] {mitigation_name}")
            lines.append("")

        # Usage by Groups
        if obj.used_by_groups:
            self._add_usage_list(lines, obj.used_by_groups, "threat group(s)")

        # Usage by Software
        if obj.used_by_software:
            self._add_usage_list(lines, obj.used_by_software, "software/malware")

        # External References
        if obj.external_references:
            self._add_external_references(lines, obj.external_references)

    def _add_usage_list(
        self, lines: List[str], items: List[tuple[str, str]], item_type: str
    ) -> None:
        """Add a usage list section (groups or software).

        Args:
            lines: List of lines to append to
            items: List of (id, name) tuples
            item_type: Type description (e.g., "threat group(s)", "software/malware")
        """
        count = len(items)
        lines.append(f"**Used by {count} {item_type}:**")
        lines.append("")
        # Show all items for complete relational data (optimized for LLM/RAG consumption)
        for item_id, item_name in items:
            lines.append(f"- [{item_id}] {item_name}")
        lines.append("")

    def _add_external_references(self, lines: List[str], references: List[Dict[str, str]]) -> None:
        """Add external references section.

        Args:
            lines: List of lines to append to
            references: List of reference dictionaries
        """
        lines.append("**External References:**")
        lines.append("")
        for ref in references:
            source = ref.get("source_name", "")
            url = ref.get("url", "")
            description = ref.get("description", "")

            if url:
                ref_text = f"[{source}]({url})"
                if description:
                    ref_text += f": {description}"
                lines.append(f"- {ref_text}")
            elif source:
                lines.append(f"- {source}")
        lines.append("")
