"""Shared pytest fixtures for all tests.

This module provides common fixtures used across unit and integration tests.
"""

from pathlib import Path

import pytest


@pytest.fixture
def empty_stix_bundle():
    """Empty STIX bundle for edge case testing."""
    return {"type": "bundle", "id": "bundle--test-empty", "objects": []}


@pytest.fixture
def malformed_technique():
    """Technique with invalid ID (missing mitre-attack reference)."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--malformed",
        "name": "Malformed Technique",
        "description": "Technique with no valid ID",
        "external_references": [{"source_name": "other-source", "external_id": "INVALID_ID"}],
    }


@pytest.fixture
def unicode_technique():
    """Technique with unicode characters."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--unicode",
        "name": "Unicode Test 中文 العربية",
        "description": "Description with unicode ñ ü ç",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        "x_mitre_platforms": ["Windows 中文", "Linux ñ"],
    }


@pytest.fixture
def unicode_tactic():
    """Tactic with unicode characters."""
    return {
        "type": "x-mitre-tactic",
        "id": "x-mitre-tactic--unicode",
        "name": "Unicode Tactic",
        "description": "Tactic with 中文 and العربية",
        "x_mitre_shortname": "unicode-tactic",
        "external_references": [{"source_name": "mitre-attack", "external_id": "TA8888"}],
    }


@pytest.fixture
def technique_with_long_description():
    """Technique with very long description (10,000+ characters)."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--long",
        "name": "Long Description Technique",
        "description": "A" * 10000,  # 10,000 characters
        "external_references": [{"source_name": "mitre-attack", "external_id": "T7777"}],
    }


@pytest.fixture
def orphaned_technique():
    """Technique with no tactic associations (no kill_chain_phases)."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--orphaned",
        "name": "Orphaned Technique",
        "description": "Technique with no parent tactic",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T6666"}],
        # No kill_chain_phases field
    }


@pytest.fixture
def orphaned_subtechnique():
    """Sub-technique whose parent technique doesn't exist."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--orphan-sub",
        "name": "Orphaned Sub-technique",
        "description": "Sub-technique with no parent",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9999.001"}],
    }


@pytest.fixture
def minimal_valid_bundle():
    """Minimal valid STIX bundle with one tactic and one technique."""
    return {
        "type": "bundle",
        "id": "bundle--minimal",
        "objects": [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--minimal",
                "name": "Minimal Tactic",
                "description": "A minimal test tactic",
                "x_mitre_shortname": "minimal",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--minimal",
                "name": "Minimal Technique",
                "description": "A minimal test technique",
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "minimal"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
            },
        ],
    }


@pytest.fixture
def technique_with_special_chars():
    """Technique with markdown special characters."""
    return {
        "type": "attack-pattern",
        "id": "attack-pattern--special",
        "name": "Technique with [brackets] and **bold**",
        "description": "Description with `code` and > quotes and # hashes",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T5555"}],
    }


# File-based fixtures for test data


@pytest.fixture(scope="session")
def enterprise_attack_file() -> Path:
    """Get path to full enterprise-attack.json file (51MB).

    This fixture returns the path to the full MITRE ATT&CK Enterprise dataset.
    If the file is not found, the test will be skipped with a helpful message.

    The file must be downloaded separately via:
    - make download-fixtures
    - Or manually from MITRE's GitHub repository

    Returns:
        Path to enterprise-attack.json in tests/fixtures/

    Raises:
        pytest.skip: If the file is not found (with download instructions)
    """
    fixture_path = Path(__file__).parent / "fixtures" / "enterprise-attack.json"

    if not fixture_path.exists():
        pytest.skip(
            "enterprise-attack.json not found in tests/fixtures/. "
            "Download it with: make download-fixtures"
        )

    return fixture_path


@pytest.fixture
def minimal_attack_file() -> Path:
    """Get path to minimal STIX bundle fixture (~5KB).

    This fixture returns the path to a minimal committed fixture that is always
    available. It contains a valid STIX bundle with 1 tactic, 1 technique, and
    1 sub-technique for fast testing.

    Returns:
        Path to minimal-attack.json in tests/fixtures/
    """
    return Path(__file__).parent / "fixtures" / "minimal-attack.json"
