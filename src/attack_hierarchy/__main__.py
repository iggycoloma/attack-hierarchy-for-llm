"""Entry point for running attack_hierarchy as a module.

Enables: python -m attack_hierarchy [args]
"""

import argparse
import sys
from pathlib import Path

from attack_hierarchy.cli import run


def main() -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="attack_hierarchy",
        description="Parse MITRE ATT&CK STIX data and generate Markdown hierarchy",
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
        "--format",
        "-f",
        choices=["single", "by-tactic", "by-technique"],
        default="single",
        help="Output format: single file, split by tactic, or split by technique (default: single)",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json"],
        default="text",
        help="Log output format (default: text)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging",
    )

    args = parser.parse_args()

    return run(
        input_path=args.input,
        output_path=args.output,
        output_format=args.format,
        log_format=args.log_format,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    sys.exit(main())
