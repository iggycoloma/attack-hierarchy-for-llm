"""CLI module for attack_hierarchy with structured logging and output format options.

This module provides production-grade CLI functionality including:
- Structured JSON logging for log aggregation
- Multiple output formats (single file, by-tactic, by-technique)
- Version tracking for MITRE ATT&CK data
- Metrics emission for observability
"""

import json
import logging
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from attack_hierarchy import MarkdownGenerator, STIXParser


@dataclass
class RunMetrics:
    """Metrics collected during a run for observability."""

    start_time: str = ""
    end_time: str = ""
    duration_seconds: float = 0.0
    input_file: str = ""
    input_size_bytes: int = 0
    output_format: str = ""
    output_files_count: int = 0
    output_total_bytes: int = 0
    tactics_count: int = 0
    techniques_count: int = 0
    subtechniques_count: int = 0
    mitre_version: str = ""
    success: bool = False
    error: str = ""


class StructuredLogger:
    """Logger that supports both text and JSON output formats."""

    def __init__(self, name: str, log_format: str = "text", level: int = logging.INFO) -> None:
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        self.logger.propagate = False  # Prevent duplicate logs from root logger
        self.log_format = log_format
        self._setup_handler()

    def _setup_handler(self) -> None:
        """Configure the appropriate handler based on format."""
        # Only configure if not already set up (prevents issues with multiple instantiations)
        if self.logger.handlers:
            return

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(self.logger.level)

        if self.log_format == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )

        self.logger.addHandler(handler)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message with optional structured data."""
        self._log(logging.INFO, message, kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message with optional structured data."""
        self._log(logging.WARNING, message, kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message with optional structured data."""
        self._log(logging.ERROR, message, kwargs)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message with optional structured data."""
        self._log(logging.DEBUG, message, kwargs)

    def _log(self, level: int, message: str, extra: dict[str, Any]) -> None:
        """Internal logging with structured data support."""
        if self.log_format == "json" and extra:
            self.logger.log(level, message, extra={"structured_data": extra})
        else:
            if extra:
                message = f"{message} | {extra}"
            self.logger.log(level, message)

    def metrics(self, metrics: RunMetrics) -> None:
        """Emit metrics as a structured log entry."""
        if self.log_format == "json":
            self.logger.info("run_metrics", extra={"structured_data": asdict(metrics)})
        else:
            self.logger.info(f"Metrics: {asdict(metrics)}")


class JsonFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add structured data if present
        if hasattr(record, "structured_data"):
            log_data["data"] = record.structured_data

        return json.dumps(log_data)


def validate_output_path(path: Path) -> Path:
    """Validate output path is safe and doesn't traverse outside working directory.

    Args:
        path: The output path to validate

    Returns:
        The resolved absolute path

    Raises:
        ValueError: If path is unsafe (traverses outside working directory or writes to root)
    """
    resolved = path.resolve()
    cwd = Path.cwd().resolve()

    try:
        resolved.relative_to(cwd)
    except ValueError as exc:
        raise ValueError(
            f"Output path must be within current directory.\n"
            f"  Attempted path: {path}\n"
            f"  Resolves to: {resolved}\n"
            f"  Current directory: {cwd}\n"
            f"  For security, writing outside the current directory is not allowed."
        ) from exc

    if resolved.parent == Path("/"):
        raise ValueError(
            f"Cannot write to root directory.\n"
            f"  Attempted path: {path}\n"
            f"  Resolves to: {resolved}"
        )

    return resolved


def extract_mitre_version(attack_data: Any) -> str:
    """Extract MITRE ATT&CK version from parsed data.

    Args:
        attack_data: The MitreAttackData instance

    Returns:
        Version string (e.g., "15.1") or "unknown"
    """
    try:
        # Try to get version from the STIX bundle
        if hasattr(attack_data, "stix_content"):
            for obj in attack_data.stix_content.get("objects", []):
                if obj.get("type") == "x-mitre-collection":
                    version = obj.get("x_mitre_version", "unknown")
                    return str(version) if version else "unknown"
        return "unknown"
    except Exception as e:
        logging.debug("Could not extract MITRE version: %s", e)
        return "unknown"


def run(  # pylint: disable=too-many-statements
    input_path: Path,
    output_path: Path,
    output_format: str = "single",
    log_format: str = "text",
    verbose: bool = False,
) -> int:
    """Main execution function for the CLI.

    Args:
        input_path: Path to the STIX JSON input file
        output_path: Path for output (file or directory depending on format)
        output_format: Output format (single, by-tactic, by-technique)
        log_format: Logging format (text, json)
        verbose: Enable debug logging

    Returns:
        Exit code (0 for success, 1 for error)
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = StructuredLogger("attack_hierarchy", log_format=log_format, level=level)

    metrics = RunMetrics(
        start_time=datetime.now(timezone.utc).isoformat(),
        input_file=str(input_path),
        output_format=output_format,
    )

    start_time = time.monotonic()

    try:
        logger.info("MITRE ATT&CK Hierarchy Generator starting", version="0.1.0")

        # Validate input
        if not input_path.exists():
            logger.error(
                "Input file not found",
                path=str(input_path),
                suggestion="Run: make download-fixtures",
            )
            metrics.error = f"Input file not found: {input_path}"
            return 1

        metrics.input_size_bytes = input_path.stat().st_size

        # Validate output path
        if output_format == "single":
            output_path = validate_output_path(output_path)
        else:
            # For split formats, output_path is a directory
            output_path = validate_output_path(output_path)
            output_path.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Configuration",
            input=str(input_path),
            output=str(output_path),
            format=output_format,
        )

        # Parse STIX data
        logger.info("Parsing STIX data")
        stix_parser = STIXParser(input_path)
        tactics, techniques, subtechniques = stix_parser.parse()

        metrics.tactics_count = len(tactics)
        metrics.techniques_count = len(techniques)
        metrics.subtechniques_count = len(subtechniques)
        metrics.mitre_version = extract_mitre_version(stix_parser.attack_data)

        logger.info(
            "Parsing complete",
            tactics=len(tactics),
            techniques=len(techniques),
            subtechniques=len(subtechniques),
            mitre_version=metrics.mitre_version,
        )

        # Generate output based on format
        generator = MarkdownGenerator(tactics, techniques, subtechniques)

        if output_format == "single":
            generator.generate(output_path)
            metrics.output_files_count = 1
            metrics.output_total_bytes = output_path.stat().st_size
        elif output_format == "by-tactic":
            metrics.output_files_count, metrics.output_total_bytes = _generate_by_tactic(
                generator, output_path, logger
            )
        elif output_format == "by-technique":
            metrics.output_files_count, metrics.output_total_bytes = _generate_by_technique(
                generator, output_path, logger
            )

        metrics.success = True
        metrics.end_time = datetime.now(timezone.utc).isoformat()
        metrics.duration_seconds = time.monotonic() - start_time

        logger.info(
            "Generation complete",
            files=metrics.output_files_count,
            total_bytes=metrics.output_total_bytes,
            duration_seconds=round(metrics.duration_seconds, 2),
        )

        return 0

    except FileNotFoundError as e:
        metrics.error = str(e)
        logger.error("File not found", error=str(e))
        return 1
    except ValueError as e:
        metrics.error = str(e)
        logger.error("Validation error", error=str(e))
        return 1
    except PermissionError as e:
        metrics.error = str(e)
        logger.error("Permission denied", error=str(e))
        return 1
    except MemoryError:
        metrics.error = "Insufficient memory"
        logger.error("Insufficient memory to process file")
        return 1
    except KeyboardInterrupt:
        metrics.error = "Cancelled by user"
        logger.info("Operation cancelled by user")
        return 130
    except Exception as e:
        metrics.error = str(e)
        logger.error(
            "Unexpected error",
            error=str(e),
            suggestion="Report at https://github.com/iggycoloma/attack-hierarchy-for-llm/issues",
        )
        if verbose:
            import traceback  # pylint: disable=import-outside-toplevel

            traceback.print_exc()
        return 1
    finally:
        metrics.end_time = datetime.now(timezone.utc).isoformat()
        metrics.duration_seconds = time.monotonic() - start_time
        logger.metrics(metrics)  # Always emit metrics for observability


def _generate_by_tactic(
    generator: MarkdownGenerator, output_dir: Path, logger: StructuredLogger
) -> tuple[int, int]:
    """Generate one markdown file per tactic.

    Args:
        generator: The MarkdownGenerator instance
        output_dir: Directory to write files to
        logger: Logger instance

    Returns:
        Tuple of (file count, total bytes)
    """
    file_count = 0
    total_bytes = 0

    sorted_tactics = generator.sort_tactics()

    for tactic in sorted_tactics:
        # Build content for this tactic only
        lines: list[str] = []
        lines.append("---")
        lines.append(f"id: {tactic.id}")
        lines.append("type: tactic")
        lines.append(f"name: {tactic.name}")
        lines.append(f"kill_chain_phase: {tactic.kill_chain_phase}")
        lines.append("---")
        lines.append("")
        lines.append(f"# [{tactic.id}] {tactic.name}")
        lines.append("")
        lines.append(tactic.description)
        lines.append("")

        # Add techniques for this tactic
        tactic_techniques = generator.get_techniques_for_tactic(tactic.id)
        for technique in tactic_techniques:
            lines.append(f"## [{technique.id}] {technique.name}")
            lines.append("")
            lines.append(technique.description)
            lines.append("")
            generator.add_metadata_sections(lines, technique)

            # Add sub-techniques
            subtechniques = generator.get_subtechniques_for_technique(technique.id)
            for subtech in subtechniques:
                lines.append(f"### [{subtech.id}] {subtech.name}")
                lines.append("")
                lines.append(subtech.description)
                lines.append("")
                generator.add_metadata_sections(lines, subtech)

        content = "\n".join(lines)
        filename = f"{tactic.id}-{tactic.kill_chain_phase}.md"
        file_path = output_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        file_count += 1
        total_bytes += file_path.stat().st_size
        logger.debug(f"Generated {filename}", bytes=file_path.stat().st_size)

    # Also generate an index file
    index_lines = ["# MITRE ATT&CK Tactics Index", ""]
    index_lines.append(f"**Total:** {len(sorted_tactics)} tactics")
    index_lines.append("")
    for tactic in sorted_tactics:
        filename = f"{tactic.id}-{tactic.kill_chain_phase}.md"
        index_lines.append(f"- [{tactic.id}] [{tactic.name}]({filename})")

    index_path = output_dir / "index.md"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines))

    file_count += 1
    total_bytes += index_path.stat().st_size

    return file_count, total_bytes


def _generate_by_technique(
    generator: MarkdownGenerator, output_dir: Path, logger: StructuredLogger
) -> tuple[int, int]:
    """Generate one markdown file per technique.

    Args:
        generator: The MarkdownGenerator instance
        output_dir: Directory to write files to
        logger: Logger instance

    Returns:
        Tuple of (file count, total bytes)
    """
    file_count = 0
    total_bytes = 0

    for technique in generator.techniques.values():
        lines: list[str] = []

        # YAML frontmatter
        lines.append("---")
        lines.append(f"id: {technique.id}")
        lines.append("type: technique")
        lines.append(f"name: {technique.name}")
        lines.append(f"tactics: [{', '.join(technique.tactic_ids)}]")
        if technique.platforms:
            lines.append(f"platforms: [{', '.join(technique.platforms)}]")
        lines.append("---")
        lines.append("")

        # Content
        lines.append(f"# [{technique.id}] {technique.name}")
        lines.append("")
        lines.append(technique.description)
        lines.append("")
        generator.add_metadata_sections(lines, technique)

        # Add sub-techniques
        subtechniques = generator.get_subtechniques_for_technique(technique.id)
        if subtechniques:
            lines.append("## Sub-Techniques")
            lines.append("")
            for subtech in subtechniques:
                lines.append(f"### [{subtech.id}] {subtech.name}")
                lines.append("")
                lines.append(subtech.description)
                lines.append("")
                generator.add_metadata_sections(lines, subtech)

        content = "\n".join(lines)
        filename = f"{technique.id}.md"
        file_path = output_dir / filename

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)

        file_count += 1
        total_bytes += file_path.stat().st_size

    # Generate index
    index_lines = ["# MITRE ATT&CK Techniques Index", ""]
    index_lines.append(f"**Total:** {len(generator.techniques)} techniques")
    index_lines.append("")

    for technique_id in sorted(generator.techniques.keys()):
        technique = generator.techniques[technique_id]
        filename = f"{technique.id}.md"
        index_lines.append(f"- [{technique.id}] [{technique.name}]({filename})")

    index_path = output_dir / "index.md"
    with open(index_path, "w", encoding="utf-8") as f:
        f.write("\n".join(index_lines))

    file_count += 1
    total_bytes += index_path.stat().st_size

    logger.debug(f"Generated {file_count} technique files")

    return file_count, total_bytes
