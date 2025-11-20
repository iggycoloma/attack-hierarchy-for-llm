"""Unit tests for domain models."""

from attack_hierarchy.models import SubTechnique, Tactic, Technique


class TestTactic:
    """Tests for Tactic model."""

    def test_tactic_creation(self) -> None:
        """Test creating a Tactic instance."""
        tactic = Tactic(
            id="TA0001",
            name="Initial Access",
            description="The adversary is trying to get into your network.",
            stix_id="x-mitre-tactic--xyz",
            kill_chain_phase="initial-access",
        )

        assert tactic.id == "TA0001"
        assert tactic.name == "Initial Access"
        assert tactic.description == "The adversary is trying to get into your network."
        assert tactic.stix_id == "x-mitre-tactic--xyz"
        assert tactic.kill_chain_phase == "initial-access"


class TestTechnique:
    """Tests for Technique model."""

    def test_technique_creation(self) -> None:
        """Test creating a Technique instance."""
        technique = Technique(
            id="T1595",
            name="Active Scanning",
            description="Adversaries may execute active reconnaissance scans.",
            stix_id="attack-pattern--xyz",
            tactic_ids=["TA0043"],
            kill_chain_phases=["reconnaissance"],
        )

        assert technique.id == "T1595"
        assert technique.name == "Active Scanning"
        assert technique.tactic_ids == ["TA0043"]
        assert technique.kill_chain_phases == ["reconnaissance"]

    def test_technique_default_lists(self) -> None:
        """Test that technique lists default to empty."""
        technique = Technique(
            id="T1234",
            name="Test",
            description="Test description",
            stix_id="attack-pattern--test",
        )

        assert technique.tactic_ids == []
        assert technique.kill_chain_phases == []
        assert technique.platforms == []
        assert technique.detection == ""
        assert technique.mitigations == []
        assert technique.used_by_groups == []
        assert technique.used_by_software == []
        assert technique.external_references == []

    def test_technique_multiple_tactics(self) -> None:
        """Test technique belonging to multiple tactics."""
        technique = Technique(
            id="T1078",
            name="Valid Accounts",
            description="Adversaries may obtain credentials.",
            stix_id="attack-pattern--abc",
            tactic_ids=["TA0001", "TA0003", "TA0004", "TA0005"],
            kill_chain_phases=[
                "initial-access",
                "persistence",
                "privilege-escalation",
                "defense-evasion",
            ],
        )

        assert len(technique.tactic_ids) == 4
        assert "TA0001" in technique.tactic_ids

    def test_technique_with_metadata(self) -> None:
        """Test technique with enhanced metadata fields."""
        technique = Technique(
            id="T1078",
            name="Valid Accounts",
            description="Adversaries may obtain credentials.",
            stix_id="attack-pattern--abc",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
            platforms=["Windows", "Linux", "macOS"],
            detection="Monitor for unusual account activity.",
            mitigations=[("M1026", "Privileged Account Management")],
            used_by_groups=[("G0001", "APT29"), ("G0002", "APT28")],
            used_by_software=[("S0001", "Mimikatz")],
            external_references=[{"source_name": "test", "url": "https://example.com"}],
        )

        assert technique.platforms == ["Windows", "Linux", "macOS"]
        assert "Monitor" in technique.detection
        assert len(technique.mitigations) == 1
        assert technique.mitigations[0] == ("M1026", "Privileged Account Management")
        assert len(technique.used_by_groups) == 2
        assert len(technique.used_by_software) == 1


class TestSubTechnique:
    """Tests for SubTechnique model."""

    def test_subtechnique_creation(self) -> None:
        """Test creating a SubTechnique instance."""
        subtechnique = SubTechnique(
            id="T1595.001",
            name="Scanning IP Blocks",
            description="Adversaries may scan victim IP blocks.",
            stix_id="attack-pattern--sub",
            parent_technique_id="T1595",
        )

        assert subtechnique.id == "T1595.001"
        assert subtechnique.name == "Scanning IP Blocks"
        assert subtechnique.parent_technique_id == "T1595"

    def test_subtechnique_id_pattern(self) -> None:
        """Test sub-technique follows T####.### pattern."""
        subtechnique = SubTechnique(
            id="T1078.004",
            name="Cloud Accounts",
            description="Test",
            stix_id="attack-pattern--cloud",
            parent_technique_id="T1078",
        )

        assert "." in subtechnique.id
        assert subtechnique.id.startswith("T")
        assert subtechnique.parent_technique_id == subtechnique.id.split(".")[0]


class TestModelEdgeCases:
    """Edge case tests for domain models."""

    def test_tactic_with_empty_strings(self) -> None:
        """Test tactic with all empty string fields."""
        tactic = Tactic(
            id="",
            name="",
            description="",
            stix_id="",
            kill_chain_phase="",
        )

        assert tactic.id == ""
        assert tactic.name == ""
        assert tactic.description == ""
        assert tactic.stix_id == ""
        assert tactic.kill_chain_phase == ""

    def test_technique_with_special_chars(self) -> None:
        """Test technique with special characters in fields."""
        technique = Technique(
            id="T1234",
            name="Technique with <script>alert('XSS')</script>",
            description="Description with \"quotes\" and 'apostrophes' and \n newlines",
            stix_id="attack-pattern--<special>",
            tactic_ids=["TA0001"],
            kill_chain_phases=["initial-access"],
        )

        # Special chars should be preserved as-is
        assert "<script>" in technique.name
        assert '"quotes"' in technique.description
        assert "\n" in technique.description

    def test_subtechnique_parent_id_extraction(self) -> None:
        """Test parent technique ID extraction from various sub-technique ID formats."""
        # Standard format
        sub1 = SubTechnique(
            id="T1234.001",
            name="Test",
            description="Test",
            stix_id="test",
            parent_technique_id="T1234",
        )
        assert sub1.parent_technique_id == "T1234"

        # Three-digit sub-technique
        sub2 = SubTechnique(
            id="T5678.123",
            name="Test",
            description="Test",
            stix_id="test",
            parent_technique_id="T5678",
        )
        assert sub2.parent_technique_id == "T5678"

        # Edge case: manual parent ID different from actual parent
        sub3 = SubTechnique(
            id="T9999.001",
            name="Test",
            description="Test",
            stix_id="test",
            parent_technique_id="T8888",  # Doesn't match!
        )
        # Model allows this mismatch (parser responsibility to enforce)
        assert sub3.parent_technique_id == "T8888"

    def test_technique_with_long_lists(self) -> None:
        """Test technique with very long metadata lists."""
        # Create very long lists
        tactic_ids = [f"TA{i:04d}" for i in range(100)]
        platforms = [f"Platform{i}" for i in range(50)]
        mitigations = [(f"M{i:04d}", f"Mitigation {i}") for i in range(200)]
        groups = [(f"G{i:04d}", f"Group {i}") for i in range(500)]
        software = [(f"S{i:04d}", f"Software {i}") for i in range(300)]

        technique = Technique(
            id="T9999",
            name="Technique with Long Lists",
            description="Test",
            stix_id="attack-pattern--long-lists",
            tactic_ids=tactic_ids,
            platforms=platforms,
            mitigations=mitigations,
            used_by_groups=groups,
            used_by_software=software,
        )

        # All lists should be preserved
        assert len(technique.tactic_ids) == 100
        assert len(technique.platforms) == 50
        assert len(technique.mitigations) == 200
        assert len(technique.used_by_groups) == 500
        assert len(technique.used_by_software) == 300

    def test_technique_with_unicode(self) -> None:
        """Test technique with unicode in all fields."""
        technique = Technique(
            id="T中文",
            name="Technique Unicode",
            description="Description with العربية and ñ characters",
            stix_id="attack-pattern--中文",
            tactic_ids=["TA العربية"],
            platforms=["Windows 中文", "Linux ñ"],
        )

        # Unicode should be preserved
        assert "中文" in technique.id
        assert "Unicode" in technique.name
        assert "العربية" in technique.description
        assert "ñ" in technique.platforms[1]

    def test_subtechnique_with_empty_lists(self) -> None:
        """Test subtechnique with all list fields empty."""
        subtechnique = SubTechnique(
            id="T1234.001",
            name="Minimal Sub-technique",
            description="Test",
            stix_id="test",
            parent_technique_id="T1234",
            platforms=[],
            detection="",
            mitigations=[],
            used_by_groups=[],
            used_by_software=[],
            external_references=[],
        )

        # All fields should be empty
        assert len(subtechnique.platforms) == 0
        assert subtechnique.detection == ""
        assert len(subtechnique.mitigations) == 0
        assert len(subtechnique.used_by_groups) == 0
        assert len(subtechnique.used_by_software) == 0
        assert len(subtechnique.external_references) == 0

    def test_model_with_very_long_strings(self) -> None:
        """Test models handle very long string fields."""
        # 50,000 character description
        long_desc = "A" * 50000

        technique = Technique(
            id="T8888",
            name="Technique with Long Description",
            description=long_desc,
            stix_id="attack-pattern--long",
            tactic_ids=["TA0001"],
        )

        assert len(technique.description) == 50000

    def test_tactic_with_unicode_kill_chain_phase(self) -> None:
        """Test tactic with unicode in kill chain phase."""
        tactic = Tactic(
            id="TA9999",
            name="Test Tactic",
            description="Test",
            stix_id="x-mitre-tactic--test",
            kill_chain_phase="phase-with-中文",
        )

        assert "中文" in tactic.kill_chain_phase

    def test_external_references_with_complex_data(self) -> None:
        """Test external references with various complex data structures."""
        refs = [
            {"source_name": "Test 1", "url": "https://example.com", "description": "Desc 1"},
            {"source_name": "Test 2"},  # No URL or description
            {"url": "https://example2.com"},  # No source_name
            {"description": "Just a description"},  # No source_name or URL
            {
                "source_name": "Complex",
                "url": "https://example3.com",
                "description": "Description with special chars: <>&\"'",
                "extra_field": "This is extra",
            },
        ]

        technique = Technique(
            id="T7777",
            name="Technique with Complex Refs",
            description="Test",
            stix_id="attack-pattern--refs",
            tactic_ids=["TA0001"],
            external_references=refs,
        )

        assert len(technique.external_references) == 5
        assert "extra_field" in technique.external_references[4]

    def test_mitigation_tuples_with_empty_strings(self) -> None:
        """Test mitigations with empty strings in tuples."""
        mitigations = [
            ("", ""),  # Both empty
            ("M1234", ""),  # Empty name
            ("", "Mitigation Name"),  # Empty ID
            ("M5678", "Normal Mitigation"),  # Normal
        ]

        technique = Technique(
            id="T6666",
            name="Test",
            description="Test",
            stix_id="test",
            tactic_ids=["TA0001"],
            mitigations=mitigations,
        )

        assert len(technique.mitigations) == 4
        assert technique.mitigations[0] == ("", "")
        assert technique.mitigations[1] == ("M1234", "")
        assert technique.mitigations[2] == ("", "Mitigation Name")
