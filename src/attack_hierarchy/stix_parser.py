"""STIX 2.1 parser for MITRE ATT&CK Enterprise dataset using mitreattack-python.

This module handles parsing of the STIX 2.1 JSON format used by MITRE ATT&CK,
extracting tactics, techniques, and sub-techniques with their hierarchical
relationships and additional metadata.
"""

import logging
from pathlib import Path
from typing import Dict, Tuple

from mitreattack.stix20 import MitreAttackData

from attack_hierarchy.models import SubTechnique, Tactic, Technique

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class STIXParser:
    """Parser for MITRE ATT&CK STIX 2.1 data using mitreattack-python.

    This parser extracts the kill chain hierarchy from the STIX bundle,
    building relationships between tactics, techniques, and sub-techniques,
    along with mitigations, detection strategies, data sources, and usage information.
    """

    # Maximum input file size: 100MB (MITRE ATT&CK files are typically ~30MB)
    MAX_INPUT_SIZE = 100 * 1024 * 1024

    def __init__(self, filepath: Path | str) -> None:
        """Initialize the parser with a STIX JSON file.

        Args:
            filepath: Path to the STIX JSON file (e.g., tests/fixtures/enterprise-attack.json)
        """
        self.filepath = Path(filepath)
        self.attack_data: MitreAttackData | None = None
        self.tactics: Dict[str, Tactic] = {}
        self.techniques: Dict[str, Technique] = {}
        self.subtechniques: Dict[str, SubTechnique] = {}
        self._phase_to_tactic_cache: Dict[str, str] = {}

    def load(self) -> None:
        """Load and parse the STIX JSON file.

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file is too large (>100MB)
        """
        logger.info(f"Loading STIX data from {self.filepath}")

        if not self.filepath.exists():
            raise FileNotFoundError(f"STIX file not found: {self.filepath}")

        # Validate file size to prevent DoS via memory exhaustion
        file_size = self.filepath.stat().st_size
        if file_size > self.MAX_INPUT_SIZE:
            raise ValueError(
                f"Input file too large: {file_size / (1024 * 1024):.1f}MB "
                f"(max {self.MAX_INPUT_SIZE / (1024 * 1024):.0f}MB)"
            )

        logger.info(f"File size: {file_size / (1024 * 1024):.1f}MB")
        self.attack_data = MitreAttackData(str(self.filepath))
        logger.info("Loaded STIX data using mitreattack-python")

    def parse(self) -> Tuple[Dict[str, Tactic], Dict[str, Technique], Dict[str, SubTechnique]]:
        """Parse STIX objects and extract the ATT&CK hierarchy.

        Returns:
            Tuple of (tactics dict, techniques dict, subtechniques dict)
            keyed by their external MITRE IDs (e.g., "TA0001", "T1595")
        """
        if not self.attack_data:
            self.load()

        assert self.attack_data is not None  # For type checker

        logger.info("Parsing STIX objects...")

        self._parse_tactics()
        self._parse_techniques()
        self._parse_subtechniques()

        logger.info(
            f"Parsed {len(self.tactics)} tactics, "
            f"{len(self.techniques)} techniques, "
            f"{len(self.subtechniques)} sub-techniques"
        )

        return self.tactics, self.techniques, self.subtechniques

    def _parse_tactics(self) -> None:
        """Parse all tactics from the STIX data."""
        assert self.attack_data is not None

        for tactic_stix in self.attack_data.get_tactics(remove_revoked_deprecated=True):
            tactic_id = self._get_attack_id(tactic_stix)
            if not tactic_id:
                continue

            tactic = Tactic(
                id=tactic_id,
                name=tactic_stix.get("name", ""),
                description=tactic_stix.get("description", ""),
                stix_id=tactic_stix.get("id", ""),
                kill_chain_phase=tactic_stix.get("x_mitre_shortname", ""),
            )

            self.tactics[tactic_id] = tactic
            # Build phase-to-tactic cache for O(1) lookups
            self._phase_to_tactic_cache[tactic.kill_chain_phase] = tactic_id
            logger.debug(f"Parsed tactic: {tactic_id} - {tactic.name}")

    def _parse_techniques(self) -> None:
        """Parse all techniques (excluding sub-techniques) from the STIX data."""
        assert self.attack_data is not None

        for tech_stix in self.attack_data.get_techniques(
            remove_revoked_deprecated=True, include_subtechniques=False
        ):
            technique_id = self._get_attack_id(tech_stix)
            if not technique_id:
                continue

            tactic_ids = []
            kill_chain_phases = []
            for phase in tech_stix.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name", "")
                    kill_chain_phases.append(phase_name)
                    tactic_id = self._find_tactic_by_phase(phase_name)
                    if tactic_id:
                        tactic_ids.append(tactic_id)

            technique = Technique(
                id=technique_id,
                name=tech_stix.get("name", ""),
                description=tech_stix.get("description", ""),
                stix_id=tech_stix.get("id", ""),
                tactic_ids=tactic_ids,
                kill_chain_phases=kill_chain_phases,
                platforms=tech_stix.get("x_mitre_platforms", []),
                detection=tech_stix.get("x_mitre_detection", ""),
                mitigations=self._get_mitigations(tech_stix),
                used_by_groups=self._get_used_by_groups(tech_stix),
                used_by_software=self._get_used_by_software(tech_stix),
                external_references=self._get_external_references(tech_stix),
            )

            self.techniques[technique_id] = technique
            logger.debug(f"Parsed technique: {technique_id} - {technique.name}")

    def _parse_subtechniques(self) -> None:
        """Parse all sub-techniques from the STIX data."""
        assert self.attack_data is not None

        for subtech_stix in self.attack_data.get_subtechniques(remove_revoked_deprecated=True):
            subtechnique_id = self._get_attack_id(subtech_stix)
            if not subtechnique_id or "." not in subtechnique_id:
                continue

            parent_technique_id = subtechnique_id.split(".", maxsplit=1)[0]

            subtechnique = SubTechnique(
                id=subtechnique_id,
                name=subtech_stix.get("name", ""),
                description=subtech_stix.get("description", ""),
                stix_id=subtech_stix.get("id", ""),
                parent_technique_id=parent_technique_id,
                platforms=subtech_stix.get("x_mitre_platforms", []),
                detection=subtech_stix.get("x_mitre_detection", ""),
                mitigations=self._get_mitigations(subtech_stix),
                used_by_groups=self._get_used_by_groups(subtech_stix),
                used_by_software=self._get_used_by_software(subtech_stix),
                external_references=self._get_external_references(subtech_stix),
            )

            self.subtechniques[subtechnique_id] = subtechnique
            logger.debug(f"Parsed sub-technique: {subtechnique_id} - {subtechnique.name}")

    def _get_attack_id(self, stix_obj: dict) -> str:
        """Extract the MITRE ATT&CK ID from a STIX object.

        Args:
            stix_obj: STIX object dictionary

        Returns:
            ATT&CK ID (e.g., "TA0001", "T1595") or empty string if not found
        """
        for ref in stix_obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return str(ref.get("external_id", ""))
        return ""

    def _find_tactic_by_phase(self, phase_name: str) -> str:
        """Find tactic ID by kill chain phase name - O(1) lookup.

        Args:
            phase_name: Kill chain phase name (e.g., "initial-access")

        Returns:
            Tactic ID (e.g., "TA0001") or empty string if not found
        """
        return self._phase_to_tactic_cache.get(phase_name, "")

    def _get_mitigations(self, stix_obj: dict) -> list[tuple[str, str]]:
        """Get mitigations for a technique or sub-technique.

        Args:
            stix_obj: STIX technique/sub-technique object

        Returns:
            List of (mitigation_id, mitigation_name) tuples
        """
        assert self.attack_data is not None

        mitigations = []
        try:
            mitigation_stix_objs = self.attack_data.get_mitigations_mitigating_technique(
                stix_obj["id"]
            )
            for mitigation_wrapper in mitigation_stix_objs:
                # Unwrap the object if it's wrapped in a dict with "object" key
                mitigation = mitigation_wrapper.get("object", mitigation_wrapper)
                mitigation_id = self._get_attack_id(mitigation)
                mitigation_name = mitigation.get("name", "")
                if mitigation_id and mitigation_name:
                    mitigations.append((mitigation_id, mitigation_name))
        except Exception as e:
            logger.debug(f"Could not get mitigations for {stix_obj.get('id')}: {e}")

        return mitigations

    def _get_used_by_groups(self, stix_obj: dict) -> list[tuple[str, str]]:
        """Get threat groups using a technique or sub-technique.

        Args:
            stix_obj: STIX technique/sub-technique object

        Returns:
            List of (group_id, group_name) tuples
        """
        assert self.attack_data is not None

        groups = []
        try:
            group_stix_objs = self.attack_data.get_groups_using_technique(stix_obj["id"])
            for group_wrapper in group_stix_objs:
                # Unwrap the object if it's wrapped in a dict with "object" key
                group = group_wrapper.get("object", group_wrapper)
                group_id = self._get_attack_id(group)
                group_name = group.get("name", "")
                if group_id and group_name:
                    groups.append((group_id, group_name))
        except Exception as e:
            logger.debug(f"Could not get groups for {stix_obj.get('id')}: {e}")

        return groups

    def _get_used_by_software(self, stix_obj: dict) -> list[tuple[str, str]]:
        """Get software (malware/tools) using a technique or sub-technique.

        Args:
            stix_obj: STIX technique/sub-technique object

        Returns:
            List of (software_id, software_name) tuples
        """
        assert self.attack_data is not None

        software = []
        try:
            software_stix_objs = self.attack_data.get_software_using_technique(stix_obj["id"])
            for sw_wrapper in software_stix_objs:
                # Unwrap the object if it's wrapped in a dict with "object" key
                sw = sw_wrapper.get("object", sw_wrapper)
                sw_id = self._get_attack_id(sw)
                sw_name = sw.get("name", "")
                if sw_id and sw_name:
                    software.append((sw_id, sw_name))
        except Exception as e:
            logger.debug(f"Could not get software for {stix_obj.get('id')}: {e}")

        return software

    def _get_external_references(self, stix_obj: dict) -> list[dict]:
        """Get external references for a technique or sub-technique.

        Args:
            stix_obj: STIX technique/sub-technique object

        Returns:
            List of external reference dictionaries
        """
        external_refs = []
        for ref in stix_obj.get("external_references", []):
            # Skip the main ATT&CK reference as it's redundant
            if ref.get("source_name") == "mitre-attack":
                continue
            external_refs.append(ref)

        return external_refs
