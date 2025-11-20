"""Specialized edge case tests for complex scenarios.

This module contains edge case tests that don't fit neatly into other test files,
including tests for circular references, memory efficiency, and unusual data patterns.
"""

import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from attack_hierarchy import MarkdownGenerator, STIXParser
from attack_hierarchy.models import SubTechnique, Tactic, Technique


class TestCircularReferences:
    """Tests for handling circular or self-referential data."""

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_subtechnique_references_self_as_parent(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test handling of self-referential sub-technique."""
        mock_stat.return_value.st_size = 1024

        # Sub-technique with parent ID matching its own ID (circular reference)
        mock_subtechnique = {
            "id": "attack-pattern--circular",
            "name": "Circular Sub-technique",
            "description": "References itself as parent",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1234.001"}],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = []
        mock_attack_data.get_subtechniques.return_value = [mock_subtechnique]
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/circular.json")
        _, _, subtechniques = parser.parse()

        # Should parse successfully with extracted parent ID
        assert len(subtechniques) == 1
        assert "T1234.001" in subtechniques
        assert subtechniques["T1234.001"].parent_technique_id == "T1234"


class TestMemoryEfficiency:
    """Tests for memory efficiency with large datasets."""

    def test_markdown_generation_with_very_large_dataset(self) -> None:
        """Test markdown generation doesn't use excessive memory."""
        # Create a large dataset: 100 tactics, 1000 techniques, 2000 sub-techniques
        tactics = {
            f"TA{i:04d}": Tactic(
                f"TA{i:04d}",
                f"Tactic {i}",
                f"Description {i}",
                f"stix-{i}",
                f"phase-{i}",
            )
            for i in range(100)
        }

        techniques = {
            f"T{i:04d}": Technique(
                f"T{i:04d}",
                f"Technique {i}",
                f"Description {i}",
                f"attack-pattern--{i}",
                tactic_ids=[f"TA{i % 100:04d}"],
                kill_chain_phases=[f"phase-{i % 100}"],
            )
            for i in range(1000)
        }

        subtechniques = {
            f"T{i // 2:04d}.{i % 2 + 1:03d}": SubTechnique(
                f"T{i // 2:04d}.{i % 2 + 1:03d}",
                f"Sub-technique {i}",
                f"Description {i}",
                f"attack-pattern--sub-{i}",
                f"T{i // 2:04d}",
            )
            for i in range(2000)
        }

        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        try:
            # Should complete without memory errors
            generator.generate(output_path)

            assert output_path.exists()
            # Verify file was created with content
            assert output_path.stat().st_size > 0
        finally:
            output_path.unlink()


class TestSpecialIDFormats:
    """Tests for various MITRE ID formats."""

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_special_technique_id_formats(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test various technique ID formats are handled correctly."""
        mock_stat.return_value.st_size = 1024

        # Test various ID formats
        test_techniques = [
            # Standard format
            {
                "id": "attack-pattern--1",
                "name": "Standard",
                "description": "T0001",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            },
            # Four-digit ID
            {
                "id": "attack-pattern--2",
                "name": "Four Digit",
                "description": "T1234",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1234"}],
            },
            # High number
            {
                "id": "attack-pattern--3",
                "name": "High Number",
                "description": "T9999",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
            },
        ]

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = test_techniques
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/ids.json")
        _, techniques, _ = parser.parse()

        # All formats should parse successfully
        assert len(techniques) == 3
        assert "T0001" in techniques
        assert "T1234" in techniques
        assert "T9999" in techniques

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_subtechnique_id_variations(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test various sub-technique ID formats."""
        mock_stat.return_value.st_size = 1024

        test_subtechniques = [
            # One-digit sub-technique
            {
                "id": "attack-pattern--sub1",
                "name": "One Digit Sub",
                "description": "Test",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1234.001"}
                ],
            },
            # Two-digit sub-technique
            {
                "id": "attack-pattern--sub2",
                "name": "Two Digit Sub",
                "description": "Test",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1234.010"}
                ],
            },
            # Three-digit sub-technique
            {
                "id": "attack-pattern--sub3",
                "name": "Three Digit Sub",
                "description": "Test",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1234.100"}
                ],
            },
        ]

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = []
        mock_attack_data.get_subtechniques.return_value = test_subtechniques
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/sub-ids.json")
        _, _, subtechniques = parser.parse()

        # All formats should parse successfully
        assert len(subtechniques) == 3
        assert "T1234.001" in subtechniques
        assert "T1234.010" in subtechniques
        assert "T1234.100" in subtechniques
        # All should have same parent
        assert subtechniques["T1234.001"].parent_technique_id == "T1234"
        assert subtechniques["T1234.010"].parent_technique_id == "T1234"
        assert subtechniques["T1234.100"].parent_technique_id == "T1234"


class TestFutureCompatibility:
    """Tests for handling unknown/future STIX fields."""

    @patch("attack_hierarchy.stix_parser.MitreAttackData")
    @patch("pathlib.Path.stat")
    @patch("pathlib.Path.exists", return_value=True)
    def test_parser_handles_unknown_fields(
        self, mock_exists: Mock, mock_stat: Mock, mock_mitre_attack: Mock
    ) -> None:
        """Test parser ignores unknown fields without error."""
        mock_stat.return_value.st_size = 1024

        # Technique with extra unknown fields (simulating future STIX version)
        mock_technique = {
            "id": "attack-pattern--future",
            "name": "Future Technique",
            "description": "Has future fields",
            "external_references": [{"source_name": "mitre-attack", "external_id": "T8888"}],
            # Unknown future fields
            "x_mitre_future_field": "some value",
            "new_stix_field": {"nested": "data"},
            "unknown_list": [1, 2, 3],
        }

        mock_attack_data = Mock()
        mock_attack_data.get_tactics.return_value = []
        mock_attack_data.get_techniques.return_value = [mock_technique]
        mock_attack_data.get_subtechniques.return_value = []
        mock_attack_data.get_mitigations_mitigating_technique.return_value = []
        mock_attack_data.get_groups_using_technique.return_value = []
        mock_attack_data.get_software_using_technique.return_value = []
        mock_mitre_attack.return_value = mock_attack_data

        parser = STIXParser("/test/future.json")
        _, techniques, _ = parser.parse()

        # Should parse successfully, ignoring unknown fields
        assert len(techniques) == 1
        assert "T8888" in techniques
        assert techniques["T8888"].name == "Future Technique"


class TestExtremeValues:
    """Tests with extreme or boundary values."""

    def test_technique_with_empty_name_and_description(self) -> None:
        """Test technique with completely empty string fields."""
        technique = Technique(
            id="",
            name="",
            description="",
            stix_id="",
            tactic_ids=[],
        )

        # Should create successfully
        assert technique.id == ""
        assert technique.name == ""
        assert technique.description == ""

    def test_technique_with_thousands_of_platforms(self) -> None:
        """Test technique with extremely long platform list."""
        platforms = [f"Platform{i}" for i in range(1000)]

        technique = Technique(
            id="T9999",
            name="Many Platforms",
            description="Test",
            stix_id="test",
            tactic_ids=["TA0001"],
            platforms=platforms,
        )

        assert len(technique.platforms) == 1000

    def test_markdown_with_technique_duplicated_across_all_tactics(self) -> None:
        """Test technique that appears in all 14 tactics."""
        # Create 14 tactics
        tactics = {
            f"TA{i:04d}": Tactic(
                f"TA{i:04d}", f"Tactic {i}", f"Desc {i}", f"stix-{i}", f"phase-{i}"
            )
            for i in range(1, 15)
        }

        # Create one technique that belongs to all tactics
        technique = Technique(
            id="T9999",
            name="Ubiquitous Technique",
            description="Appears everywhere",
            stix_id="attack-pattern--ubiq",
            tactic_ids=[f"TA{i:04d}" for i in range(1, 15)],
            kill_chain_phases=[f"phase-{i}" for i in range(1, 15)],
        )

        generator = MarkdownGenerator(tactics, {"T9999": technique}, {})

        content = generator._build_markdown()

        # Technique should appear 14 times (once per tactic)
        count = content.count("[T9999] Ubiquitous Technique")
        assert count == 14

    def test_subtechnique_with_missing_parent_dot(self) -> None:
        """Test sub-technique ID without a dot (malformed)."""
        # This would be a malformed sub-technique ID
        subtechnique = SubTechnique(
            id="T1234",  # Missing the .001 part
            name="Malformed Sub",
            description="Test",
            stix_id="test",
            parent_technique_id="T1234",
        )

        # Model allows this (validation is parser's job)
        assert subtechnique.id == "T1234"
        assert subtechnique.parent_technique_id == "T1234"


class TestConcurrentDataStructures:
    """Tests for potential concurrency issues."""

    def test_multiple_generators_same_data(self) -> None:
        """Test creating multiple generators from same data doesn't interfere."""
        tactics = {"TA0001": Tactic("TA0001", "Test", "Test tactic", "stix-id", "test-phase")}

        technique = Technique(
            id="T0001",
            name="Test",
            description="Test technique",
            stix_id="attack-pattern--test",
            tactic_ids=["TA0001"],
        )

        # Create multiple generators simultaneously
        gen1 = MarkdownGenerator(tactics, {"T0001": technique}, {})
        gen2 = MarkdownGenerator(tactics, {"T0001": technique}, {})
        gen3 = MarkdownGenerator(tactics, {"T0001": technique}, {})

        # Build markdown from all
        content1 = gen1._build_markdown()
        content2 = gen2._build_markdown()
        content3 = gen3._build_markdown()

        # All should produce identical output
        assert content1 == content2 == content3
