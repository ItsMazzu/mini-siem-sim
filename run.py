"""
Mini SIEM Simulator — Quick start entry point.

Run this to execute the full pipeline:
  python run.py                              # Default behavior
  python run.py --csv data/auth_logs.csv     # Custom CSV
  python run.py --no-geo                     # Skip geolocation
  python run.py --no-db                      # Skip database
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.main import main

if __name__ == "__main__":
    main()
