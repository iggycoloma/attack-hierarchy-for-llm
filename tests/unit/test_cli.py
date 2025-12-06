"""Unit tests for CLI module."""

import json
import logging
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from attack_hierarchy.cli import (
    JsonFormatter,
    RunMetrics,
    StructuredLogger,
    _generate_by_tactic,
    _generate_by_technique,
    extract_mitre_version,
    run,
    validate_output_path,
)
from attack_hierarchy.models import SubTechnique, Tactic, Technique


class TestValidateOutputPath:
    """Tests for output path validation."""

    def test_valid_path_within_cwd(self):
        """Test that paths within CWD are accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original_cwd = Path.cwd()
            try:
                import os

                os.chdir(tmpdir)
                path = Path("output/test.md")
                result = validate_output_path(path)
                assert result.is_absolute()
            finally:
                os.chdir(original_cwd)

    def test_rejects_path_traversal(self):
        """Test that path traversal attempts are rejected."""
        with pytest.raises(ValueError, match="must be within current directory"):
            validate_output_path(Path("/etc/passwd"))

    def test_rejects_root_directory(self):
        """Test that writing to root is rejected."""
        with pytest.raises(ValueError):
            validate_output_path(Path("/test.md"))


class TestStructuredLogger:
    """Tests for StructuredLogger class."""

    def test_text_format_logging(self, capsys):
        """Test text format logging."""
        logger = StructuredLogger("test_text", log_format="text")
        logger.info("Test message", key="value")

        # Text goes to stderr (propagate=False means we need to check stderr)
        captured = capsys.readouterr()
        assert "Test message" in captured.err

    def test_json_format_logging(self, capsys):
        """Test JSON format logging."""
        logger = StructuredLogger("test_json", log_format="json")
        logger.info("Test message", key="value")

        # JSON goes to stderr
        captured = capsys.readouterr()
        # The message should be in JSON format
        assert "Test message" in captured.err or "test_json" in captured.err

    def test_metrics_emission(self, capsys):
        """Test metrics are emitted correctly."""
        logger = StructuredLogger("test_metrics_emission", log_format="text")
        metrics = RunMetrics(
            tactics_count=14,
            techniques_count=200,
            success=True,
        )
        logger.metrics(metrics)

        # Metrics go to stderr (propagate=False means we need to check stderr)
        captured = capsys.readouterr()
        assert "Metrics" in captured.err or "tactics_count" in captured.err


class TestJsonFormatter:
    """Tests for JSON log formatter."""

    def test_format_basic_record(self):
        """Test basic log record formatting."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["level"] == "INFO"
        assert parsed["message"] == "Test message"
        assert "timestamp" in parsed

    def test_format_with_structured_data(self):
        """Test log record with structured data."""
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.structured_data = {"key": "value", "count": 42}

        result = formatter.format(record)
        parsed = json.loads(result)

        assert parsed["data"]["key"] == "value"
        assert parsed["data"]["count"] == 42


class TestRunMetrics:
    """Tests for RunMetrics dataclass."""

    def test_default_values(self):
        """Test default metric values."""
        metrics = RunMetrics()

        assert metrics.success is False
        assert metrics.tactics_count == 0
        assert metrics.error == ""

    def test_custom_values(self):
        """Test custom metric values."""
        metrics = RunMetrics(
            tactics_count=14,
            techniques_count=216,
            subtechniques_count=475,
            success=True,
            mitre_version="15.1",
        )

        assert metrics.tactics_count == 14
        assert metrics.mitre_version == "15.1"


class TestExtractMitreVersion:
    """Tests for MITRE version extraction."""

    def test_extracts_version_from_collection(self):
        """Test version extraction from x-mitre-collection object."""
        mock_data = Mock()
        mock_data.stix_content = {
            "objects": [
                {"type": "x-mitre-collection", "x_mitre_version": "15.1"},
            ]
        }

        result = extract_mitre_version(mock_data)
        assert result == "15.1"

    def test_returns_unknown_for_missing_version(self):
        """Test unknown returned when version is missing."""
        mock_data = Mock()
        mock_data.stix_content = {"objects": []}

        result = extract_mitre_version(mock_data)
        assert result == "unknown"

    def test_handles_exception_gracefully(self):
        """Test graceful handling of exceptions."""
        mock_data = Mock()
        mock_data.stix_content = None  # Will cause AttributeError

        result = extract_mitre_version(mock_data)
        assert result == "unknown"


class TestGenerateByTactic:
    """Tests for by-tactic generation."""

    def test_generates_files_per_tactic(self):
        """Test that one file is generated per tactic."""
        from attack_hierarchy import MarkdownGenerator

        tactics = {
            "TA0001": Tactic("TA0001", "Initial Access", "Test desc", "stix-1", "initial-access"),
            "TA0002": Tactic("TA0002", "Execution", "Test desc", "stix-2", "execution"),
        }
        techniques = {
            "T0001": Technique(
                "T0001", "Test Tech", "Desc", "stix-t1", ["TA0001"], ["initial-access"]
            ),
        }

        generator = MarkdownGenerator(tactics, techniques, {})
        logger = StructuredLogger("test", log_format="text")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            file_count, _total_bytes = _generate_by_tactic(generator, output_dir, logger)

            # Should have 2 tactic files + 1 index
            assert file_count == 3
            assert (output_dir / "TA0001-initial-access.md").exists()
            assert (output_dir / "TA0002-execution.md").exists()
            assert (output_dir / "index.md").exists()

    def test_includes_yaml_frontmatter(self):
        """Test that YAML frontmatter is included."""
        from attack_hierarchy import MarkdownGenerator

        tactics = {
            "TA0001": Tactic("TA0001", "Initial Access", "Test", "stix-1", "initial-access"),
        }

        generator = MarkdownGenerator(tactics, {}, {})
        logger = StructuredLogger("test", log_format="text")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            _generate_by_tactic(generator, output_dir, logger)

            content = (output_dir / "TA0001-initial-access.md").read_text()
            assert "---" in content
            assert "id: TA0001" in content
            assert "type: tactic" in content


class TestGenerateByTechnique:
    """Tests for by-technique generation."""

    def test_generates_files_per_technique(self):
        """Test that one file is generated per technique."""
        from attack_hierarchy import MarkdownGenerator

        tactics = {"TA0001": Tactic("TA0001", "Test", "Desc", "stix-1", "test")}
        techniques = {
            "T1001": Technique("T1001", "Tech 1", "Desc", "stix-t1", ["TA0001"], ["test"]),
            "T1002": Technique("T1002", "Tech 2", "Desc", "stix-t2", ["TA0001"], ["test"]),
        }

        generator = MarkdownGenerator(tactics, techniques, {})
        logger = StructuredLogger("test", log_format="text")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            file_count, _total_bytes = _generate_by_technique(generator, output_dir, logger)

            # Should have 2 technique files + 1 index
            assert file_count == 3
            assert (output_dir / "T1001.md").exists()
            assert (output_dir / "T1002.md").exists()
            assert (output_dir / "index.md").exists()

    def test_includes_subtechniques(self):
        """Test that subtechniques are included in technique files."""
        from attack_hierarchy import MarkdownGenerator

        tactics = {"TA0001": Tactic("TA0001", "Test", "Desc", "stix-1", "test")}
        techniques = {
            "T1001": Technique("T1001", "Tech 1", "Desc", "stix-t1", ["TA0001"], ["test"]),
        }
        subtechniques = {
            "T1001.001": SubTechnique("T1001.001", "SubTech 1", "Desc", "stix-st1", "T1001"),
        }

        generator = MarkdownGenerator(tactics, techniques, subtechniques)
        logger = StructuredLogger("test", log_format="text")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            _generate_by_technique(generator, output_dir, logger)

            content = (output_dir / "T1001.md").read_text()
            assert "T1001.001" in content
            assert "SubTech 1" in content


class TestRunFunction:
    """Tests for main run function."""

    def test_returns_error_for_missing_input(self):
        """Test error return for missing input file."""
        result = run(
            input_path=Path("/nonexistent/file.json"),
            output_path=Path("output.md"),
        )
        assert result == 1

    @patch("attack_hierarchy.cli.STIXParser")
    def test_successful_run_single_format(self, mock_parser_class):
        """Test successful run with single file format."""
        # Setup mocks
        mock_parser = Mock()
        mock_parser.parse.return_value = ({}, {}, {})
        mock_parser.attack_data = Mock()
        mock_parser.attack_data.stix_content = {"objects": []}
        mock_parser_class.return_value = mock_parser

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a fake input file
            input_file = Path(tmpdir) / "input.json"
            input_file.write_text("{}")

            output_file = Path(tmpdir) / "output.md"

            import os

            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = run(
                    input_path=input_file,
                    output_path=output_file,
                    output_format="single",
                )
            finally:
                os.chdir(original_cwd)

            assert result == 0
