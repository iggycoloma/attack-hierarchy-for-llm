"""Integration tests for end-to-end workflows."""

import tempfile
from pathlib import Path

import pytest

from attack_hierarchy import MarkdownGenerator, STIXParser
from attack_hierarchy.models import Tactic


@pytest.fixture(scope="session")
def parsed_enterprise_data(enterprise_attack_file):
    """Parse enterprise-attack.json once and share across all integration tests."""
    parser = STIXParser(enterprise_attack_file)
    tactics, techniques, subtechniques = parser.parse()

    return tactics, techniques, subtechniques


class TestEndToEndWorkflow:
    """Test complete end-to-end workflows with real data."""

    def test_complete_parse_and_generate_workflow(self, parsed_enterprise_data) -> None:
        """Test complete workflow from STIX file to Markdown output."""
        tactics, techniques, subtechniques = parsed_enterprise_data

        # Verify parsing results
        assert len(tactics) > 0
        assert len(techniques) > 100  # Should have many techniques
        assert len(subtechniques) > 100  # Should have many sub-techniques

        # Step 2: Generate Markdown
        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        generator.generate(output_path)

        # Step 3: Verify Markdown output
        assert output_path.exists()

        content = output_path.read_text(encoding="utf-8")

        # Verify structure
        assert "# MITRE ATT&CK Enterprise Framework" in content
        assert " tactics" in content
        assert " techniques" in content
        assert " sub-techniques" in content

        # Verify heading levels exist
        assert "\n## [TA" in content  # Tactics
        assert "\n### [T" in content  # Techniques
        assert "\n#### [T" in content  # Sub-techniques

        # Verify enhanced metadata sections exist
        assert "**Platforms:**" in content
        # Note: Detection and Data Sources may not always be present in STIX data
        # but other metadata like Mitigations and Groups should be
        assert "**Mitigations:**" in content or "**Used by" in content

        # Clean up
        output_path.unlink()

    def test_generated_markdown_has_all_metadata(self, parsed_enterprise_data) -> None:
        """Test that generated markdown includes all metadata sections."""
        tactics, techniques, subtechniques = parsed_enterprise_data

        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        generator.generate(output_path)

        content = output_path.read_text(encoding="utf-8")

        # Check for various metadata sections that should exist
        assert "**Platforms:**" in content
        # Note: Data Sources are not available in enterprise-attack.json STIX format
        # (no relationships link data components to techniques)
        assert "**Mitigations:**" in content or "**Detection:**" in content

        # Check for usage information
        assert "**Used by" in content  # Groups or software

        # Clean up
        output_path.unlink()

    def test_markdown_tactics_in_kill_chain_order(self, parsed_enterprise_data) -> None:
        """Test that tactics appear in kill chain order."""
        tactics, techniques, subtechniques = parsed_enterprise_data

        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        generator.generate(output_path)

        content = output_path.read_text(encoding="utf-8")

        # Check that Reconnaissance comes before Initial Access
        if "Reconnaissance" in content and "Initial Access" in content:
            recon_pos = content.find("## [TA0043] Reconnaissance")
            initial_pos = content.find("## [TA0001] Initial Access")

            if recon_pos > 0 and initial_pos > 0:
                assert recon_pos < initial_pos

        # Clean up
        output_path.unlink()

    def test_workflow_with_output_directory_creation(self, parsed_enterprise_data) -> None:
        """Test that generator creates output directory if it doesn't exist."""
        tactics, techniques, subtechniques = parsed_enterprise_data

        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        # Use a path with a non-existent directory
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "dir" / "output.md"

            generator.generate(output_path)

            # Should create the directory and file
            assert output_path.exists()
            assert output_path.parent.exists()


class TestRealWorldScenarios:
    """Test with real-world scenarios using actual data."""

    def test_multi_tactic_technique_appears_multiple_times(self, parsed_enterprise_data) -> None:
        """Test that techniques belonging to multiple tactics appear under each."""
        tactics, techniques, subtechniques = parsed_enterprise_data

        # Find a technique with multiple tactics
        multi_tactic_techniques = [t for t in techniques.values() if len(t.tactic_ids) > 1]

        if not multi_tactic_techniques:
            pytest.skip("No multi-tactic techniques found")

        # Generate markdown
        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        generator.generate(output_path)

        content = output_path.read_text(encoding="utf-8")

        # Check that at least one multi-tactic technique appears multiple times
        sample_technique = multi_tactic_techniques[0]
        pattern = f"### [{sample_technique.id}] {sample_technique.name}"

        # Should appear once for each tactic it belongs to
        count = content.count(pattern)
        assert count == len(sample_technique.tactic_ids)

        # Clean up
        output_path.unlink()

    def test_enhanced_metadata_is_populated(self, parsed_enterprise_data) -> None:
        """Test that enhanced metadata fields are actually populated with data."""
        _, techniques, _ = parsed_enterprise_data

        # Find techniques with various metadata
        has_platforms = sum(1 for t in techniques.values() if t.platforms)
        has_mitigations = sum(1 for t in techniques.values() if t.mitigations)
        has_groups = sum(1 for t in techniques.values() if t.used_by_groups)
        has_software = sum(1 for t in techniques.values() if t.used_by_software)

        # Most techniques should have at least some metadata
        assert has_platforms > len(techniques) * 0.5  # Most have platforms
        assert has_mitigations > 0  # Some have mitigations
        assert has_groups > 0  # Some used by groups
        assert has_software > 0  # Some used by software


class TestIntegrationEdgeCases:
    """Integration edge case tests."""

    def test_workflow_with_corrupted_json(self) -> None:
        """Test workflow handles corrupted JSON gracefully."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{invalid json syntax")
            corrupt_file = Path(f.name)

        try:
            parser = STIXParser(corrupt_file)
            # mitreattack-python should raise an error when loading invalid JSON
            with pytest.raises(Exception):  # Could be JSONDecodeError or other
                parser.load()
        finally:
            corrupt_file.unlink()

    def test_workflow_with_minimal_valid_data(self) -> None:
        """Test workflow with smallest valid STIX bundle."""
        minimal_bundle = {
            "type": "bundle",
            "id": "bundle--minimal",
            "objects": [],  # No objects at all
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json

            json.dump(minimal_bundle, f)
            f.flush()
            minimal_file = Path(f.name)

        try:
            parser = STIXParser(minimal_file)
            tactics, techniques, subtechniques = parser.parse()

            # Should parse successfully with empty results
            assert len(tactics) == 0
            assert len(techniques) == 0
            assert len(subtechniques) == 0

            # Should be able to generate markdown from empty data
            generator = MarkdownGenerator(tactics, techniques, subtechniques)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as out_f:
                output_path = Path(out_f.name)

            generator.generate(output_path)

            # Output should exist and have header
            assert output_path.exists()
            content = output_path.read_text(encoding="utf-8")
            assert "# MITRE ATT&CK Enterprise Framework" in content
            assert "0 tactics" in content

            output_path.unlink()
        finally:
            minimal_file.unlink()

    def test_workflow_with_single_tactic_only(self) -> None:
        """Test workflow with only a single tactic and no techniques."""
        single_tactic_bundle = {
            "type": "bundle",
            "id": "bundle--12345678-1234-4000-9000-123456789012",
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "id": "x-mitre-tactic--12345678-abcd-4000-9000-123456789abc",
                    "name": "Test Tactic",
                    "description": "A single test tactic",
                    "x_mitre_shortname": "test-tactic",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "TA9999"}
                    ],
                }
            ],
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json

            json.dump(single_tactic_bundle, f)
            f.flush()
            single_file = Path(f.name)

        try:
            parser = STIXParser(single_file)
            tactics, techniques, subtechniques = parser.parse()

            # Should have one tactic, no techniques
            assert len(tactics) == 1
            assert len(techniques) == 0
            assert len(subtechniques) == 0
            assert "TA9999" in tactics

            # Generate markdown
            generator = MarkdownGenerator(tactics, techniques, subtechniques)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as out_f:
                output_path = Path(out_f.name)

            generator.generate(output_path)

            content = output_path.read_text(encoding="utf-8")
            assert "[TA9999] Test Tactic" in content
            assert "A single test tactic" in content

            output_path.unlink()
        finally:
            single_file.unlink()

    def test_workflow_with_unicode_data(self) -> None:
        """Test end-to-end workflow with unicode data."""
        from attack_hierarchy.models import Technique

        # Create models with unicode directly (avoiding STIX parsing complexity)
        tactics = {
            "TA8888": Tactic(
                "TA8888",
                "Unicode Tactic",
                "Tactic with 中文 characters",
                "x-mitre-tactic--unicode",
                "unicode-tactic",
            )
        }

        techniques = {
            "T8888": Technique(
                "T8888",
                "Unicode Technique",
                "Technique with العربية and ñ",
                "attack-pattern--unicode",
                ["TA8888"],
                ["unicode-tactic"],
            )
        }

        # Generate markdown with unicode
        generator = MarkdownGenerator(tactics, techniques, {})

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".md", delete=False, encoding="utf-8"
        ) as out_f:
            output_path = Path(out_f.name)

        try:
            generator.generate(output_path)

            # Read and verify unicode in output
            content = output_path.read_text(encoding="utf-8")
            assert "中文" in content
            assert "العربية" in content
            assert "ñ" in content
        finally:
            output_path.unlink()

    def test_output_directory_creation(self) -> None:
        """Test that deeply nested output directories are created."""
        tactics = {"TA0001": Tactic("TA0001", "Test", "Test tactic", "stix-id", "test-phase")}

        generator = MarkdownGenerator(tactics, {}, {})

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a deeply nested path
            output_path = Path(tmpdir) / "level1" / "level2" / "level3" / "output.md"

            # Should create all parent directories
            generator.generate(output_path)

            assert output_path.exists()
            assert output_path.parent.exists()
            assert output_path.parent.parent.exists()

    def test_workflow_preserves_special_markdown_chars(self) -> None:
        """Test that markdown special characters are preserved correctly."""
        from attack_hierarchy.models import Technique

        # Create models with special chars directly (avoiding STIX parsing complexity)
        tactics = {
            "TA7777": Tactic(
                "TA7777",
                "Tactic with [brackets]",
                "Description with **bold** and *italic*",
                "x-mitre-tactic--special",
                "special-tactic",
            )
        }

        techniques = {
            "T7777": Technique(
                "T7777",
                "Technique with `code`",
                "Description with > quotes and # hashes",
                "attack-pattern--special",
                ["TA7777"],
                ["special-tactic"],
            )
        }

        # Generate markdown
        generator = MarkdownGenerator(tactics, techniques, {})

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as out_f:
            output_path = Path(out_f.name)

        try:
            generator.generate(output_path)

            # Verify special chars are preserved
            content = output_path.read_text(encoding="utf-8")
            assert "[brackets]" in content
            assert "**bold**" in content
            assert "`code`" in content
            assert ">" in content
            assert "#" in content
        finally:
            output_path.unlink()
