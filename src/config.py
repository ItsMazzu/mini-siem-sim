"""
src/config.py — Unified configuration for Mini SIEM Simulator.

Centralizes all thresholds, API settings, and detection parameters.
Changes here propagate system-wide automatically.

Combines settings from:
  - security-log-analyzer: auth detection, scoring, database
  - suspicious-ip-detector: geolocation, attack classification, threat levels
  - New pipeline: geolocation caching, unified workflow
"""

from pathlib import Path

# ═══════════════════════════════════════════════════════════════════════════════
# PATHS & DIRECTORIES
# ═══════════════════════════════════════════════════════════════════════════════

ROOT_DIR    = Path(__file__).parent.parent
DATA_DIR    = ROOT_DIR / "data"
CONFIG_DIR  = ROOT_DIR / "config"
DB_DIR      = ROOT_DIR / "database"
LOG_DIR     = DATA_DIR / "logs"

DEFAULT_CSV_PATH       = DATA_DIR / "auth_logs.csv"
MALICIOUS_IPS_PATH     = CONFIG_DIR / "malicious_ips.txt"
DB_PATH                = DB_DIR / "logs.db"
SIEM_EXPORT_PATH       = DATA_DIR / "siem_export.csv"

# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION: Auth-Based Threats
# ═══════════════════════════════════════════════════════════════════════════════

# Brute Force Detection — Time-window based
BRUTE_FORCE_WINDOW_SECONDS: int = 60      # Window for consecutive attempts
BRUTE_FORCE_THRESHOLD: int = 5            # Min failures in window to trigger

# Credential Stuffing Detection
CREDENTIAL_STUFFING_MIN_USERS: int = 3    # Min distinct users per IP

# Account Compromise Detection
ACCOUNT_COMPROMISE_MIN_FAILURES: int = 2  # Min failures before success

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT SCORING (0–100 points)
# ═══════════════════════════════════════════════════════════════════════════════

# Auth-based scoring weights
SCORE_BRUTE_FORCE:          int = 20
SCORE_CREDENTIAL_STUFFING:  int = 25
SCORE_ACCOUNT_COMPROMISE:   int = 30   # Confirmed intrusion
SCORE_MALICIOUS_IP:         int = 35
SCORE_ATTEMPTS = {
    "EXTREME": (50, 40),               # >= 50 attempts → +40 pts
    "HIGH":    (20, 25),               # >= 20 → +25 pts
    "MEDIUM":  (10, 15),               # >= 10 → +15 pts
    "LOW":     (5,  8),                # >= 5 → +8 pts
    "ANY":     (1,  3),                # >= 1 → +3 pts
}

# ─── Attack-based scoring (from SIEM Detector) ──────────────────────────────
ATTACK_SCORES = {
    "NORMAL":              0,
    "SUSPICIOUS":         10,
    "BRUTE_FORCE":        20,
    "PORT_SCAN":          20,
    "DICTIONARY_ATTACK":  25,
    "CREDENTIAL_STUFFING":30,
    "DOS_ATTEMPT":        35,
    "SQL_INJECTION":      40,
}

# ─── Volume-based scoring (combined logic) ──────────────────────────────────
SCORE_VOLUME_EXTREME = 40      # >= 500 attempts
SCORE_VOLUME_HIGH    = 30      # >= 100 attempts
SCORE_VOLUME_MEDIUM  = 20      # >= 50 attempts
SCORE_VOLUME_LOW     = 10      # >= 10 attempts

# ─── Threat factors (cumulative) ─────────────────────────────────────────────
SCORE_BLACKLIST_IP           = 25   # Known malicious IP
SCORE_SUCCESSFUL_INTRUSION   = 20   # Confirmed access gained
SCORE_MALICIOUS_PAYLOAD      = 15   # SQLi, RCE, etc.
SCORE_SUSPICIOUS_ISP         = 10   # VPN, Tor, proxy, etc.
SCORE_PORT_SCAN_VARIANT      = 5    # Multiple distinct ports
SCORE_USERNAME_VARIETY       = 5    # Multiple distinct usernames
SCORE_PRIVATE_IP_DISCOUNT    = -10  # Internal threat (reduce score)

# ═══════════════════════════════════════════════════════════════════════════════
# THREAT LEVELS & BOUNDARIES
# ═══════════════════════════════════════════════════════════════════════════════

THREAT_LEVEL_CRITICAL: int = 80    # Score >= 80
THREAT_LEVEL_HIGH:     int = 55    # Score >= 55 and < 80
THREAT_LEVEL_MEDIUM:   int = 30    # Score >= 30 and < 55
THREAT_LEVEL_LOW:      int = 0     # Score < 30

# ═══════════════════════════════════════════════════════════════════════════════
# GEOLOCATION & IP ANALYSIS (from SIEM Detector)
# ═══════════════════════════════════════════════════════════════════════════════

# Geolocation API settings (ip-api.com)
GEO_API_URL       = "http://ip-api.com/json/{ip}?fields={fields}"
GEO_API_FIELDS    = "status,message,country,regionName,city,isp,org,lat,lon,timezone,query"
GEO_API_TIMEOUT   = 6                  # seconds
GEO_API_RATE_LIMIT = 45                # requests/minute (free tier)

# Geolocation caching
GEO_CACHE_ENABLED          = True      # Cache results to avoid API spam
GEO_CACHE_EXPIRY_HOURS     = 24        # Re-fetch after 24 hours
GEO_CACHE_MAX_SIZE         = 10000     # Max cached entries before cleanup

# Known malicious IPs (from GeoLocator blacklist)
BLACKLIST_IPS = {
    "185.220.101.45", "185.220.101.47",           # Tor exit nodes
    "89.248.167.131", "89.248.165.134",           # Shodan scanners
    "193.32.162.157",                             # AbuseIPDB-registered
    "45.33.32.156",                               # nmap.scanme.org source
    "198.20.69.74", "198.20.69.98",               # Shodan scanners
    "162.247.74.74", "162.247.74.200",            # Tor exit nodes (EFF)
    "212.47.235.82",                              # European blacklists
    "194.165.16.11",                              # SSH brute-force source
    "80.82.77.139", "80.82.77.33",                # ZMap/Shodan scanners
}

# Suspicious ISP/Org keywords (indicates infrastructure often used in attacks)
SUSPICIOUS_ISP_KEYWORDS = [
    "tor", "vpn", "proxy", "anonymous", "bulletproof",
    "hosting", "datacenter", "vps", "colocation",
    "serverius", "frantech", "leaseweb",
]

# ─── Attack classification thresholds ────────────────────────────────────────
DOS_THRESHOLD             = 500  # attempts → DoS
PORT_SCAN_THRESHOLD       = 10   # distinct ports → Port Scan
CRED_STUFFING_USERS_THRESHOLD = 10   # distinct usernames
CRED_STUFFING_ATTEMPTS_THRESHOLD = 20  # min attempts
DICT_ATTACK_ATTEMPTS_THRESHOLD = 50    # attempts → Dictionary Attack
BRUTE_FORCE_ATTEMPTS_THRESHOLD = 10    # attempts → Brute Force
SUSPICIOUS_ATTEMPTS_THRESHOLD  = 5    # attempts → Suspicious

# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

DB_MAX_DISPLAY_ROWS: int = 100    # Max rows in table display
DB_WAL_MODE_ENABLED = True        # Write-Ahead Logging for concurrency
DB_FOREIGN_KEYS_ENABLED = True    # PRAGMA foreign_keys=ON

# ─── Database schema versioning ──────────────────────────────────────────────
DB_SCHEMA_VERSION = "2.0"  # upgraded to include geolocation cache

# ═══════════════════════════════════════════════════════════════════════════════
# PIPELINE SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

# Whether to perform geolocation during normal analysis
ENABLE_GEOLOCATION_BY_DEFAULT = True

# Whether to use SQLite persistence during analysis
ENABLE_DATABASE_BY_DEFAULT = True

# Output format options: 'table', 'json', 'csv'
DEFAULT_OUTPUT_FORMAT = 'table'

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

# Log file settings
LOG_FILE_MAX_SIZE_MB = 5       # Rotate when reaching 5 MB
LOG_FILE_BACKUP_COUNT = 5      # Keep last 5 rotated files
LOG_FORMAT = "%(asctime)s — [%(name)s] — %(levelname)s — %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
