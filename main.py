"""Main script for generating MITRE ATT&CK hierarchy markdown.

This script orchestrates the parsing of the STIX 2.1 formatted MITRE ATT&CK
Enterprise dataset and generation of structured Markdown optimized for LLM consumption.
"""

import argparse
import logging
import sys
from pathlib import Path

from attack_hierarchy import MarkdownGenerator, STIXParser

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def validate_output_path(path: Path) -> Path:
    """Validate output path is safe and doesn't traverse outside working directory.

    Args:
        path: The output path to validate

    Returns:
        The resolved absolute path

    Raises:
        ValueError: If path is unsafe (traverses outside working directory or writes to root)
    """
    # Resolve to absolute path (this also normalizes the path)
    resolved = path.resolve()

    # Get current working directory
    cwd = Path.cwd().resolve()

    # Check if the resolved path is within or is the current working directory
    # This prevents writing to /etc/passwd, ../../etc/passwd, etc.
    try:
        resolved.relative_to(cwd)
    except ValueError:
        raise ValueError(
            f"Output path must be within current directory.\n"
            f"  Attempted path: {path}\n"
            f"  Resolves to: {resolved}\n"
            f"  Current directory: {cwd}\n"
            f"  For security, writing outside the current directory is not allowed."
        )

    # Additional safety: ensure parent directory is not root
    if resolved.parent == Path("/"):
        raise ValueError(
            f"Cannot write to root directory.\n"
            f"  Attempted path: {path}\n"
            f"  Resolves to: {resolved}"
        )

    return resolved


def main() -> int:
    """Main entry point for the script.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    parser = argparse.ArgumentParser(
        description="Parse MITRE ATT&CK STIX data and generate Markdown hierarchy"
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        default=Path("enterprise-attack.json"),
        help="Path to enterprise-attack.json STIX file (default: enterprise-attack.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("output/attack-hierarchy.md"),
        help="Path for output Markdown file (default: output/attack-hierarchy.md)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("=" * 70)
        logger.info("MITRE ATT&CK Hierarchy Generator")
        logger.info("=" * 70)

        # Validate input file exists
        if not args.input.exists():
            logger.error(f"ERROR: Input file not found: {args.input}")
            logger.error("")
            logger.error("To download the MITRE ATT&CK dataset:")
            logger.error("  make download-fixtures")
            logger.error("")
            logger.error("Or download manually:")
            logger.error(
                "  curl -o tests/fixtures/enterprise-attack.json "
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
                "enterprise-attack/enterprise-attack.json"
            )
            logger.error("")
            logger.error("Then run with:")
            logger.error("  python main.py --input tests/fixtures/enterprise-attack.json")
            logger.error("")
            logger.error("Or specify a different file with:")
            logger.error(f"  python {sys.argv[0]} --input /path/to/your/file.json")
            return 1

        # Validate output path is safe (prevents path traversal attacks)
        args.output = validate_output_path(args.output)

        # Parse STIX data
        logger.info(f"Input: {args.input}")
        logger.info(f"Output: {args.output}")
        logger.info("-" * 70)

        stix_parser = STIXParser(args.input)
        tactics, techniques, subtechniques = stix_parser.parse()

        logger.info("-" * 70)

        # Generate Markdown
        generator = MarkdownGenerator(tactics, techniques, subtechniques)
        generator.generate(args.output)

        logger.info("-" * 70)
        logger.info("Successfully generated MITRE ATT&CK hierarchy markdown")
        logger.info("=" * 70)

        return 0

    except FileNotFoundError as e:
        logger.error(f"ERROR: File not found: {e}")
        logger.error("")
        logger.error("Please check that the file path is correct and the file exists.")
        return 1
    except ValueError as e:
        logger.error(f"ERROR: Validation error: {e}")
        return 1
    except PermissionError as e:
        logger.error(f"ERROR: Permission denied: {e}")
        logger.error("")
        logger.error("Please check that you have permission to read/write the specified files.")
        return 1
    except MemoryError:
        logger.error("Insufficient memory to process the file.")
        logger.error("")
        logger.error("The STIX file may be too large for available memory.")
        logger.error("Try closing other applications or using a machine with more RAM.")
        return 1
    except KeyboardInterrupt:
        logger.info("")
        logger.info("Operation cancelled by user.")
        return 130  # Standard Unix exit code for SIGINT
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        logger.error("")
        logger.error("This may be a bug. Please report this issue with the error above at:")
        logger.error("  https://github.com/iggycoloma/attack-hierarchy-for-llm/issues")
        logger.error("")
        if args.verbose:
            logger.error("Full traceback:", exc_info=True)
        else:
            logger.error("Run with --verbose flag for detailed error information.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
