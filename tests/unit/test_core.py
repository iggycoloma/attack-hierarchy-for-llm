"""Unit tests for STIX parser core functionality using mocks."""

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from attack_hierarchy.stix_parser import STIXParser


class TestSTIXParser:
    """Tests for STIXParser class using mocked data."""

    def test_parser_initialization(self) -> None:
        """Test parser can be initialized with a file path."""
        test_path = Path("/test/path/attack.json")
        parser = STIXParser(test_path)
        assert parser.filepath == test_path
        assert parser.attack_data is None

    def test_parser_load_missing_file(self) -> None:
        """Test parser raises error for missing file."""
        parser = STIXParser("/nonexistent/file.json")

        with pytest.raises(FileNotFoundError):
            parser.load()

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_load(self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock) -> None:
        """Test parser can load STIX data using mitreattack-python."""
        # Mock file stat to return valid file size (30MB)
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        mock_attack_data = Mock()
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        parser.load()

        assert parser.attack_data is not None
        mock_mitre_attack.assert_called_once_with("/test/attack.json")

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_parse_tactics(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parsing tactics from mocked STIX data."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        # Create mock tactic STIX object
        mock_tactic_stix = {
            "id": "x-mitre-tactic--test-id",
            "name": "Initial Access",
            "description": "The adversary is trying to get into your network.",
            "x_mitre_shortname": "initial-access",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "TA0001",
                }
            ],
        }

        # Setup mock MitreAttackData
        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = [mock_tactic_stix]
        mock_attack_data.get_techniques.return_value = []
        mock_attack_data.get_subtechniques.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        tactics, techniques, subtechniques = parser.parse()

        # Verify tactic was parsed correctly
        assert len(tactics) == 1
        assert "TA0001" in tactics
        assert tactics["TA0001"].name == "Initial Access"
        assert tactics["TA0001"].kill_chain_phase == "initial-access"
        assert len(techniques) == 0
        assert len(subtechniques) == 0

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_parse_techniques(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parsing techniques from mocked STIX data."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        # Create mock tactic
        mock_tactic_stix = {
            "id": "x-mitre-tactic--test-id",
            "name": "Reconnaissance",
            "description": "Test tactic",
            "x_mitre_shortname": "reconnaissance",
            "external_references": [{"source_name": "mitre-attack", "external_id": "TA0043"}],
        }

        # Create mock technique STIX object
        mock_technique_stix = {
            "id": "attack-pattern--test-id",
            "name": "Active Scanning",
            "description": "Adversaries may execute active reconnaissance scans.",
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "reconnaissance",
                }
            ],
            "x_mitre_platforms": ["PRE"],
            "x_mitre_detection": "Monitor for scanning activity.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1595",
                }
            ],
        }

        # Setup mock MitreAttackData
        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = [mock_tactic_stix]
        mock_attack_data.get_techniques.return_value = [mock_technique_stix]
        mock_attack_data.get_subtechniques.return_value = []

        # Mock the metadata extraction methods
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []

        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        _, techniques, _ = parser.parse()

        # Verify technique was parsed correctly
        assert len(techniques) == 1
        assert "T1595" in techniques
        assert techniques["T1595"].name == "Active Scanning"
        assert techniques["T1595"].tactic_ids == ["TA0043"]
        assert techniques["T1595"].platforms == ["PRE"]
        assert techniques["T1595"].detection == "Monitor for scanning activity."

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_parse_subtechniques(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parsing sub-techniques from mocked STIX data."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        # Create mock sub-technique STIX object
        mock_subtechnique_stix = {
            "id": "attack-pattern--sub-test-id",
            "name": "Scanning IP Blocks",
            "description": "Adversaries may scan victim IP blocks.",
            "x_mitre_platforms": ["PRE"],
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1595.001",
                }
            ],
        }

        # Setup mock MitreAttackData
        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = []
        mock_attack_data.get_subtechniques.return_value = [mock_subtechnique_stix]

        # Mock the metadata extraction methods
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []

        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        _, _, subtechniques = parser.parse()

        # Verify sub-technique was parsed correctly
        assert len(subtechniques) == 1
        assert "T1595.001" in subtechniques
        assert subtechniques["T1595.001"].name == "Scanning IP Blocks"
        assert subtechniques["T1595.001"].parent_technique_id == "T1595"
        assert "." in subtechniques["T1595.001"].id

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_extracts_platforms(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test that parser extracts platform information."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        mock_technique_stix = {
            "id": "attack-pattern--test",
            "name": "Test Technique",
            "description": "Test",
            "x_mitre_platforms": ["Windows", "Linux", "macOS"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique_stix]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        _, techniques, _ = parser.parse()

        assert len(techniques) == 1
        assert techniques["T1234"].platforms == ["Windows", "Linux", "macOS"]

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_extracts_mitigations(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test that parser extracts mitigation relationships."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        mock_technique_stix = {
            "id": "attack-pattern--test",
            "name": "Test Technique",
            "description": "Test",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
        }

        # Mock mitigation object with wrapper structure
        mock_mitigation = {
            "object": {
                "id": "course-of-action--test",
                "name": "User Account Management",
                "external_references": [{"source_name": "mitre-attack", "external_id": "M1018"}],
            }
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique_stix]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = [mock_mitigation]
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        _, techniques, _ = parser.parse()

        assert len(techniques) == 1
        assert len(techniques["T1234"].mitigations) == 1
        assert techniques["T1234"].mitigations[0] == ("M1018", "User Account Management")

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_extracts_usage_info(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test that parser extracts group and software usage information."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 30 * 1024 * 1024

        mock_technique_stix = {
            "id": "attack-pattern--test",
            "name": "Test Technique",
            "description": "Test",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
        }

        # Mock group object with wrapper structure
        mock_group = {
            "object": {
                "id": "intrusion-set--test",
                "name": "APT29",
                "external_references": [{"source_name": "mitre-attack", "external_id": "G0016"}],
            }
        }

        # Mock software object with wrapper structure
        mock_software = {
            "object": {
                "id": "malware--test",
                "name": "Mimikatz",
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0002"}],
            }
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique_stix]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = [mock_group]
        mock_attack_data.get_software_using_technique.return_value = [mock_software]
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/attack.json")
        _, techniques, _ = parser.parse()

        assert len(techniques) == 1
        assert len(techniques["T1234"].used_by_groups) == 1
        assert techniques["T1234"].used_by_groups[0] == ("G0016", "APT29")
        assert len(techniques["T1234"].used_by_software) == 1
        assert techniques["T1234"].used_by_software[0] == ("S0002", "Mimikatz")


class TestSTIXParserEdgeCases:
    """Edge case tests for STIXParser class."""

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_empty_stix_bundle(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles empty STIX bundle gracefully."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = []
        mock_attack_data.get_subtechniques.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/empty.json")
        tactics, techniques, subtechniques = parser.parse()

        assert len(tactics) == 0
        assert len(techniques) == 0
        assert len(subtechniques) == 0

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_malformed_technique_id(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser skips techniques with invalid IDs."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Technique without external_references
        mock_technique_no_refs = {
            "id": "attack-pattern--test1",
            "name": "No References",
            "description": "Test",
        }

        # Technique with non-mitre-attack reference
        mock_technique_wrong_source = {
            "id": "attack-pattern--test2",
            "name": "Wrong Source",
            "description": "Test",
            "external_references": [{"source_name": "other-source", "external_id": "OTHER-001"}],
        }

        # Technique with empty external_id
        mock_technique_empty_id = {
            "id": "attack-pattern--test3",
            "name": "Empty ID",
            "description": "Test",
            "external_references": [{"source_name": "mitre-attack", "external_id": ""}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [
            mock_technique_no_refs,
            mock_technique_wrong_source,
            mock_technique_empty_id,
        ]
        mock_attack_data.get_subtechniques.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/malformed.json")
        _, techniques, _ = parser.parse()

        # All techniques should be skipped due to missing/invalid IDs
        assert len(techniques) == 0

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_technique_without_tactic(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles orphaned techniques without kill chain phases."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Technique with no kill_chain_phases
        mock_technique = {
            "id": "attack-pattern--test",
            "name": "Orphaned Technique",
            "description": "Technique with no tactic association",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            # No kill_chain_phases field
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/orphaned.json")
        _, techniques, _ = parser.parse()

        # Technique should be parsed but with empty tactic_ids
        assert len(techniques) == 1
        assert "T9999" in techniques
        assert techniques["T9999"].tactic_ids == []
        assert techniques["T9999"].kill_chain_phases == []

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_unicode_in_names_and_descriptions(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles unicode characters correctly."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Technique with unicode characters
        mock_technique = {
            "id": "attack-pattern--unicode",
            "name": "Unicode Test 中文 العربية ñ",
            "description": "Description with unicode characters ü ñ ç",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T8888"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/unicode.json")
        _, techniques, _ = parser.parse()

        # Unicode should be preserved
        assert len(techniques) == 1
        assert "中文" in techniques["T8888"].name
        assert "unicode" in techniques["T8888"].description.lower()

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_extremely_long_descriptions(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles very long descriptions (10,000+ characters)."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Create a very long description (15,000 characters)
        long_description = "A" * 15000

        mock_technique = {
            "id": "attack-pattern--long",
            "name": "Long Description Technique",
            "description": long_description,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T7777"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/long.json")
        _, techniques, _ = parser.parse()

        # Long description should be preserved
        assert len(techniques) == 1
        assert len(techniques["T7777"].description) == 15000

    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_file_size_limit_exceeded(self, mock_exists: Mock, mock_stat: Mock) -> None:
        """Test parser rejects files exceeding MAX_INPUT_SIZE."""
        # Mock file stat to return size over limit (150MB > 100MB limit)
        mock_stat.return_value.st_size = 150 * 1024 * 1024

        parser = STIXParser("/test/huge.json")

        with pytest.raises(ValueError, match="Input file too large"):
            parser.load()

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_missing_required_fields(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles techniques missing name or description."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Technique missing name and description
        mock_technique = {
            "id": "attack-pattern--missing",
            # No name field
            # No description field
            "external_references": [{"source_name": "mitre-attack", "external_id": "T6666"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/missing.json")
        _, techniques, _ = parser.parse()

        # Should handle missing fields with empty strings
        assert len(techniques) == 1
        assert techniques["T6666"].name == ""
        assert techniques["T6666"].description == ""

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_subtechnique_without_parent(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles sub-techniques where parent doesn't exist."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Sub-technique with non-existent parent
        mock_subtechnique = {
            "id": "attack-pattern--orphan",
            "name": "Orphaned Sub-technique",
            "description": "Sub-technique with no parent",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999.001"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = []  # No parent T9999
        mock_attack_data.get_subtechniques.return_value = [mock_subtechnique]
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/orphan-sub.json")
        _, _, subtechniques = parser.parse()

        # Sub-technique should still be parsed
        assert len(subtechniques) == 1
        assert "T9999.001" in subtechniques
        assert subtechniques["T9999.001"].parent_technique_id == "T9999"

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_duplicate_technique_ids(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser handles duplicate technique IDs (last one wins)."""
        # Mock file stat to return valid file size
        mock_stat.return_value.st_size = 1024

        # Two techniques with same ID
        mock_technique1 = {
            "id": "attack-pattern--dup1",
            "name": "First Technique",
            "description": "First version",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T5555"}],
        }

        mock_technique2 = {
            "id": "attack-pattern--dup2",
            "name": "Second Technique",
            "description": "Second version",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T5555"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique1, mock_technique2]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/duplicate.json")
        _, techniques, _ = parser.parse()

        # Last technique wins
        assert len(techniques) == 1
        assert techniques["T5555"].name == "Second Technique"
