"""Unit tests for markdown generator."""

import tempfile
from pathlib import Path

import pytest

from attack_hierarchy.markdown_generator import MarkdownGenerator
from attack_hierarchy.models import SubTechnique, Tactic, Technique


class TestMarkdownGenerator:
    """Tests for MarkdownGenerator class."""

    @pytest.fixture
    def sample_tactic(self) -> Tactic:
        """Create a sample tactic for testing."""
        return Tactic(
            id="TA0001",
            name="Initial Access",
            description="The adversary is trying to get into your network.",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

    @pytest.fixture
    def sample_technique(self) -> Technique:
        """Create a sample technique for testing."""
        return Technique(
            id="T1595",
            name="Active Scanning",
            description="Adversaries may execute active reconnaissance scans.",
            stix_id="attack-pattern--test",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            platforms=["PRE"],
            detection="Monitor for unusual scanning activity.",
            mitigations=[("M1056", "Pre-compromise Mitigation")],
            used_by_groups=[("G0001", "Test Group")],
            used_by_software=[("S0001", "Test Software")],
            external_references=[{"source_name": "test", "url": "https://example.com"}],
        )

    @pytest.fixture
    def sample_subtechnique(self) -> SubTechnique:
        """Create a sample sub-technique for testing."""
        return SubTechnique(
            id="T1595.001",
            name="Scanning IP Blocks",
            description="Adversaries may scan victim IP blocks.",
            stix_id="attack-pattern--sub-test",
            parent_technique_id="T1595",
            platforms=["PRE"],
            detection="Monitor for IP scanning patterns.",
            mitigations=[],
            used_by_groups=[],
            used_by_software=[],
            external_references=[],
        )

    def test_generator_initialization(
        self,
        sample_tactic: Tactic,
        sample_technique: Technique,
        sample_subtechnique: SubTechnique,
    ) -> None:
        """Test generator can be initialized with data."""
        generator = MarkdownGenerator(
            tactics={"TA0001": sample_tactic},
            techniques={"T1595": sample_technique},
            subtechniques={"T1595.001": sample_subtechnique},
        )

        assert len(generator.tactics) == 1
        assert len(generator.techniques) == 1
        assert len(generator.subtechniques) == 1

    def test_generator_generate_file(
        self,
        sample_tactic: Tactic,
        sample_technique: Technique,
        sample_subtechnique: SubTechnique,
    ) -> None:
        """Test generating markdown file."""
        generator = MarkdownGenerator(
            tactics={"TA0001": sample_tactic},
            techniques={"T1595": sample_technique},
            subtechniques={"T1595.001": sample_subtechnique},
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            output_path = Path(f.name)

        generator.generate(output_path)

        assert output_path.exists()

        # Read and verify content
        content = output_path.read_text(encoding="utf-8")

        # Check for expected markdown structure
        assert "# MITRE ATT&CK Enterprise Framework" in content
        assert "## [TA0001] Initial Access" in content
        assert "### [T1595] Active Scanning" in content
        assert "#### [T1595.001] Scanning IP Blocks" in content

        # Clean up
        output_path.unlink()

    def test_markdown_hierarchy_structure(
        self,
        sample_tactic: Tactic,
        sample_technique: Technique,
        sample_subtechnique: SubTechnique,
    ) -> None:
        """Test that markdown has proper hierarchical structure."""
        generator = MarkdownGenerator(
            tactics={"TA0001": sample_tactic},
            techniques={"T1595": sample_technique},
            subtechniques={"T1595.001": sample_subtechnique},
        )

        content = generator._build_markdown()

        # Verify heading levels are in correct order
        lines = content.split("\n")

        h1_index = next(i for i, line in enumerate(lines) if line.startswith("# "))
        h2_index = next(i for i, line in enumerate(lines) if line.startswith("## [TA"))
        h3_index = next(i for i, line in enumerate(lines) if line.startswith("### [T"))
        h4_index = next(i for i, line in enumerate(lines) if line.startswith("#### [T"))

        # Check hierarchy: H1 < H2 < H3 < H4
        assert h1_index < h2_index < h3_index < h4_index

    def test_techniques_for_tactic(
        self, sample_tactic: Tactic, sample_technique: Technique
    ) -> None:
        """Test getting techniques for a specific tactic."""
        generator = MarkdownGenerator(
            tactics={"TA0001": sample_tactic},
            techniques={"T1595": sample_technique},
            subtechniques={},
        )

        techniques = generator._get_techniques_for_tactic("TA0001")
        assert len(techniques) == 1
        assert techniques[0].id == "T1595"

    def test_subtechniques_for_technique(
        self, sample_technique: Technique, sample_subtechnique: SubTechnique
    ) -> None:
        """Test getting sub-techniques for a specific technique."""
        generator = MarkdownGenerator(
            tactics={},
            techniques={"T1595": sample_technique},
            subtechniques={"T1595.001": sample_subtechnique},
        )

        subtechniques = generator._get_subtechniques_for_technique("T1595")
        assert len(subtechniques) == 1
        assert subtechniques[0].id == "T1595.001"

    def test_tactic_sorting(self) -> None:
        """Test that tactics are sorted by kill chain order."""
        tactics = {
            "TA0001": Tactic(
                "TA0001",
                "Initial Access",
                "desc",
                "stix-1",
                "initial-access",
            ),
            "TA0002": Tactic("TA0002", "Execution", "desc", "stix-2", "execution"),
            "TA0043": Tactic(
                "TA0043",
                "Reconnaissance",
                "desc",
                "stix-43",
                "reconnaissance",
            ),
        }

        generator = MarkdownGenerator(tactics=tactics, techniques={}, subtechniques={})
        sorted_tactics = generator._sort_tactics()

        # Reconnaissance should come first in kill chain
        assert sorted_tactics[0].id == "TA0043"
        assert sorted_tactics[1].id == "TA0001"
        assert sorted_tactics[2].id == "TA0002"

    def test_empty_data(self) -> None:
        """Test generator handles empty data gracefully."""
        generator = MarkdownGenerator(tactics={}, techniques={}, subtechniques={})

        content = generator._build_markdown()

        # Should still have header
        assert "# MITRE ATT&CK Enterprise Framework" in content
        assert "0 tactics" in content

    def test_metadata_sections_in_output(
        self,
        sample_tactic: Tactic,
        sample_technique: Technique,
    ) -> None:
        """Test that metadata sections appear in generated markdown."""
        generator = MarkdownGenerator(
            tactics={"TA0001": sample_tactic},
            techniques={"T1595": sample_technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Check for metadata sections
        assert "**Platforms:**" in content
        assert "PRE" in content
        assert "**Detection:**" in content
        assert "Monitor for unusual scanning activity" in content
        assert "**Mitigations:**" in content
        assert "[M1056]" in content
        assert "**Used by 1 threat group(s):**" in content
        assert "[G0001] Test Group" in content
        assert "**Used by 1 software/malware:**" in content
        assert "[S0001] Test Software" in content
        assert "**External References:**" in content


class TestMarkdownGeneratorEdgeCases:
    """Edge case tests for MarkdownGenerator class."""

    def test_empty_tactics_dict(self) -> None:
        """Test generator handles empty tactics dictionary."""
        generator = MarkdownGenerator(tactics={}, techniques={}, subtechniques={})

        content = generator._build_markdown()

        # Should still have header
        assert "# MITRE ATT&CK Enterprise Framework" in content
        assert "0 tactics" in content
        assert "0 techniques" in content
        assert "0 sub-techniques" in content

    def test_tactic_with_no_techniques(self) -> None:
        """Test tactic exists but has no associated techniques."""
        tactic = Tactic(
            id="TA0999",
            name="Empty Tactic",
            description="A tactic with no techniques",
            stix_id="x-mitre-tactic--empty",
            kill_chain_phase="empty-phase",
        )

        generator = MarkdownGenerator(
            tactics={"TA0999": tactic},
            techniques={},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Tactic should appear but with no techniques
        assert "## [TA0999] Empty Tactic" in content
        assert "A tactic with no techniques" in content
        # No technique headers should follow
        assert "###" not in content

    def test_unicode_in_markdown_output(self) -> None:
        """Test unicode characters render correctly in markdown."""
        tactic = Tactic(
            id="TA0888",
            name="Unicode Tactic",
            description="Tactic with unicode 中文 العربية",
            stix_id="x-mitre-tactic--unicode",
            kill_chain_phase="unicode-phase",
        )

        technique = Technique(
            id="T8888",
            name="Unicode Technique",
            description="Technique with unicode ñ ü ç",
            stix_id="attack-pattern--unicode",
            tactic_ids=["TA0888"],
            kill_chain_phases=["unicode-phase"],
        )

        generator = MarkdownGenerator(
            tactics={"TA0888": tactic},
            techniques={"T8888": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Unicode should be preserved
        assert "中文" in content
        assert "العربية" in content
        assert "ñ" in content

    def test_very_long_usage_lists(self) -> None:
        """Test techniques with 100+ groups show all groups."""
        # Create 100 groups
        groups = [(f"G{i:04d}", f"Group {i}") for i in range(100)]

        technique = Technique(
            id="T9999",
            name="Popular Technique",
            description="Used by many groups",
            stix_id="attack-pattern--popular",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            used_by_groups=groups,
        )

        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

        generator = MarkdownGenerator(
            tactics={"TA0001": tactic},
            techniques={"T9999": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Should show all 100 groups
        assert "[G0000] Group 0" in content
        assert "[G0009] Group 9" in content
        assert "[G0010] Group 10" in content
        assert "[G0099] Group 99" in content
        # Should NOT show truncation message
        assert "...and 90 more" not in content

    def test_techniques_with_100_plus_software(self) -> None:
        """Test techniques with 100+ software show all software."""
        # Create 150 software
        software = [(f"S{i:04d}", f"Software {i}") for i in range(150)]

        technique = Technique(
            id="T8888",
            name="Common Technique",
            description="Implemented by lots of software",
            stix_id="attack-pattern--common",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            used_by_software=software,
        )

        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

        generator = MarkdownGenerator(
            tactics={"TA0001": tactic},
            techniques={"T8888": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Should show all 150 software
        assert "[S0000] Software 0" in content
        assert "[S0009] Software 9" in content
        assert "[S0010] Software 10" in content
        assert "[S0149] Software 149" in content
        # Should NOT show truncation message
        assert "...and 140 more" not in content

    def test_external_refs_without_urls(self) -> None:
        """Test external references with only source name (no URL)."""
        technique = Technique(
            id="T7777",
            name="Technique with References",
            description="Test",
            stix_id="attack-pattern--refs",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            external_references=[
                {"source_name": "Source Only"},
                {"source_name": "Source with URL", "url": "https://example.com"},
                {"source_name": "Source with Description", "description": "Some details"},
            ],
        )

        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

        generator = MarkdownGenerator(
            tactics={"TA0001": tactic},
            techniques={"T7777": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Source names should appear (description is not rendered by current implementation)
        assert "Source Only" in content
        assert "https://example.com" in content
        assert "Source with Description" in content

    def test_markdown_special_chars_in_names(self) -> None:
        """Test markdown special characters don't break formatting."""
        tactic = Tactic(
            id="TA0777",
            name="Tactic with [brackets] and *asterisks*",
            description="Description with `backticks` and #hashes#",
            stix_id="x-mitre-tactic--special",
            kill_chain_phase="special-phase",
        )

        technique = Technique(
            id="T7777",
            name="Technique with **bold** and _underscores_",
            description="Description with [links](url) and > quotes",
            stix_id="attack-pattern--special",
            tactic_ids=["TA0777"],
            kill_chain_phases=["special-phase"],
        )

        generator = MarkdownGenerator(
            tactics={"TA0777": tactic},
            techniques={"T7777": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Special chars should be preserved as-is (markdown will handle them)
        assert "[brackets]" in content
        assert "*asterisks*" in content
        assert "`backticks`" in content
        assert "**bold**" in content
        assert "_underscores_" in content

    def test_technique_with_empty_metadata(self) -> None:
        """Test technique with all metadata fields empty."""
        technique = Technique(
            id="T6666",
            name="Minimal Technique",
            description="Only basic info",
            stix_id="attack-pattern--minimal",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            platforms=[],  # Empty
            detection="",  # Empty
            mitigations=[],  # Empty
            used_by_groups=[],  # Empty
            used_by_software=[],  # Empty
            external_references=[],  # Empty
        )

        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

        generator = MarkdownGenerator(
            tactics={"TA0001": tactic},
            techniques={"T6666": technique},
            subtechniques={},
        )

        content = generator._build_markdown()

        # Basic content should appear
        assert "[T6666] Minimal Technique" in content
        assert "Only basic info" in content
        # Metadata sections should NOT appear
        assert "**Platforms:**" not in content
        assert "**Detection:**" not in content
        assert "**Mitigations:**" not in content
        assert "**Used by" not in content
        assert "**External References:**" not in content

    def test_subtechnique_with_long_platform_list(self) -> None:
        """Test subtechnique with many platforms."""
        subtechnique = SubTechnique(
            id="T1234.001",
            name="Multi-Platform Sub-technique",
            description="Works on many platforms",
            stix_id="attack-pattern--multi",
            parent_technique_id="T1234",
            platforms=[
                "Windows",
                "Linux",
                "macOS",
                "iOS",
                "Android",
                "Cloud",
                "Container",
                "Network",
            ],
        )

        technique = Technique(
            id="T1234",
            name="Parent Technique",
            description="Parent",
            stix_id="attack-pattern--parent",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
        )

        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="initial-access",
        )

        generator = MarkdownGenerator(
            tactics={"TA0001": tactic},
            techniques={"T1234": technique},
            subtechniques={"T1234.001": subtechnique},
        )

        content = generator._build_markdown()

        # All platforms should be listed (comma-separated)
        assert "Windows, Linux, macOS, iOS, Android, Cloud, Container, Network" in content
