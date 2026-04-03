"""
src/main.py — Unified entry point for Mini SIEM Simulator.

Combines:
  - security-log-analyzer: authentication pattern analysis & threat detection
  - suspicious-ip-detector: geolocation, attack classification, threat scoring

Unified CLI with options:
  python -m src.main [--csv PATH] [--no-db] [--no-geo] [--help]
"""

import argparse
import sys
from pathlib import Path

from rich.console import Console

from src.config import DEFAULT_CSV_PATH, ENABLE_DATABASE_BY_DEFAULT, ENABLE_GEOLOCATION_BY_DEFAULT
from src.pipeline import UnifiedPipeline
from src.report.reporter import print_result, print_summary
from src.utils.logger import setup_logger

console = Console()
logger = setup_logger("main")

_BANNER = """
  ╔═══════════════════════════════════════════════════════════╗
  ║              MINI SIEM SIMULATOR v2.0                     ║
  ║    Unified Authentication & Threat Analysis Engine        ║
  ║                                                            ║
  ║  Combined: Auth Detection + Geolocation + Threat Scoring  ║
  ╚═══════════════════════════════════════════════════════════╝
"""


def _build_parser() -> argparse.ArgumentParser:
    """Build CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mini-siem-sim",
        description="Unified security log analyzer with threat detection & geolocation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "\nUsage Examples:\n"
            "  python -m src.main\n"
            "  python -m src.main --csv data/auth_logs.csv\n"
            "  python -m src.main --no-geo         # skip geolocation API calls\n"
            "  python -m src.main --no-db          # skip database persistence\n"
            "  python -m src.main --no-geo --no-db # fast local analysis only\n"
        ),
    )
    parser.add_argument(
        "--csv",
        metavar="ARQUIVO",
        type=Path,
        default=DEFAULT_CSV_PATH,
        help=f"Path to authentication logs CSV (default: {DEFAULT_CSV_PATH})",
    )
    parser.add_argument(
        "--no-db",
        action="store_true",
        help="Skip SQLite persistence (faster but no historical storage)",
    )
    parser.add_argument(
        "--no-geo",
        action="store_true",
        help="Skip geolocation queries (faster, local detection only)",
    )
    return parser


def main() -> None:
    """Main entry point."""
    console.print(_BANNER, style="bold cyan")

    # Parse arguments
    args = _build_parser().parse_args()

    # Configure pipeline
    use_database = ENABLE_DATABASE_BY_DEFAULT and not args.no_db
    use_geolocation = ENABLE_GEOLOCATION_BY_DEFAULT and not args.no_geo

    pipeline = UnifiedPipeline(
        use_geolocation=use_geolocation,
        use_database=use_database,
    )

    # Run pipeline
    try:
        auth_logs, results = pipeline.run(args.csv)
    except Exception as e:
        console.print(f"\n[red]✘ Pipeline failed: {e}[/red]\n")
        logger.exception("Pipeline error")
        sys.exit(1)

    # Display results
    if not results:
        console.print("[yellow]⚠ No threats detected.[/yellow]\n")
        return

    console.print(f"\n[bold cyan]━━━ ANALYSIS RESULTS ({len(results)} threats) ━━━[/bold cyan]\n")

    for result in results:
        print_result(result)

    print_summary(results)


if __name__ == "__main__":
    main()
