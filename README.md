# 🔐 Mini SIEM Simulator

**A Python-based security log analyzer for suspicious authentication activity, IP geolocation enrichment, and threat scoring.**

The Mini SIEM Simulator is a defensive security project designed to analyze authentication logs, identify suspicious activity patterns, enrich IP addresses with geolocation data, and prioritize findings through a unified threat score.

The project brings together authentication analysis and suspicious IP investigation in a single command-line workflow.

## 📌 Overview

| Item | Description |
|---|---|
| **Project** | Mini SIEM Simulator |
| **Version** | 1.0 |
| **Language** | Python |
| **Input** | Authentication logs in CSV format |
| **Analysis** | Authentication patterns, IP context, and threat scoring |
| **Output** | Threat analysis report in the terminal |
| **Persistence** | Optional SQLite database |
| **Geolocation** | [ip-api.com](http://ip-api.com/) |
| **Python requirement** | Python 3.8+ |

### What does it do?

- Analyzes authentication logs to identify suspicious activity.
- Detects patterns associated with brute-force attempts, credential stuffing, and possible account compromise.
- Checks IP addresses against a local blacklist.
- Enriches IP information using a geolocation API, with caching.
- Combines detection indicators into a threat score from 0 to 100.
- Presents findings, threat classifications, and suggested mitigation steps.

The project is intended for learning, experimentation, and demonstrating a basic defensive security analysis workflow. It is not presented as a replacement for a production SIEM.

## ✨ Features

### 🔎 Authentication Analysis

The analyzer examines authentication events and looks for patterns such as:

- **Brute force:** repeated failed authentication attempts within a time window.
- **Credential stuffing:** authentication attempts involving multiple usernames.
- **Possible account compromise:** a successful authentication following failed attempts.
- **Blacklist matching:** identification of IP addresses listed in a local blacklist.

The results depend on the available log data and the detection logic implemented in the project.

### 🌐 IP Geolocation Enrichment

The geolocation component retrieves contextual information about IP addresses through `ip-api.com`.

Available enrichment fields include:

- Country and city.
- Internet service provider (ISP).
- Organization.
- Geographic coordinates.

The component includes per-IP caching and a fallback path for API failures.

Geolocation provides additional investigation context; it does not, by itself, establish that an IP address is malicious.

### 🎯 Unified Threat Scoring

The scoring component combines authentication patterns and contextual indicators into a score ranging from **0 to 100**.

The project uses the following severity ranges:

| Score | Severity | Suggested response |
|---:|---|---|
| 80–100 | Critical | Immediate blocking is recommended |
| 55–79 | High | Blocking or rate limiting is recommended |
| 30–54 | Medium | Review is recommended |
| 0–29 | Low | Monitoring is recommended |

Scoring factors documented in the project include activity volume, attack classification, blacklist matches, successful intrusions, malicious payload indicators, and suspicious ISP information.

These scores are prioritization signals, not proof of compromise. The suggested responses should be evaluated in the context of the environment being investigated.

### 📋 Reports and Recommendations

The command-line report brings together the analysis results, including:

- Threat scores and severity levels.
- Attack classifications.
- Detection indicators.
- Suggested mitigation actions.
- Response guidance for critical findings.

The project also includes terminal output formatting through `Rich` and `Colorama`.

### 🗄️ Optional SQLite Storage

SQLite persistence is optional. The project includes a database component and a database location for runtime data.

The CLI provides a `--no-db` option to run without database persistence.

### 🧰 Supporting Components

The project also includes:

- CSV parsing and input validation.
- A configuration module.
- A pipeline coordinating the analysis stages.
- A threat classification component.
- A utility for input validation and sanitization.
- A rotating file logger.
- A bridge for the previous SIEM-related components.

## ⚙️ Technology Stack

| Technology | Role |
|---|---|
| **Python 3.8+** | Main programming language |
| **SQLite** | Optional local persistence |
| **Requests** | HTTP requests for geolocation |
| **ip-api.com** | IP geolocation data source |
| **Rich** | Formatted terminal output |
| **Colorama** | Terminal colors |
| **Pytest** | Automated testing |
| **Ruff** | Python linting |
| **Mypy** | Static type checking |

## 🏗️ Project Structure

```text
mini-siem-sim/
├── src/
│   ├── main.py
│   ├── config.py
│   ├── pipeline.py
│   ├── parser.py
│   ├── analyzer.py
│   ├── database.py
│   ├── ui.py
│   ├── bridge.py
│   ├── detector/
│   │   ├── geo_locator.py
│   │   ├── attack_classifier.py
│   │   ├── threat_scorer.py
│   │   └── ip_analyzer.py
│   ├── models/
│   │   └── event.py
│   ├── report/
│   │   └── reporter.py
│   └── utils/
│       ├── logger.py
│       └── validator.py
├── data/
│   └── auth_logs.csv
├── config/
│   └── malicious_ips.txt
├── database/
│   └── logs.db
├── tests/
│   └── test_analyzer.py
├── run.py
├── requirements.txt
└── .gitignore
```

The database and generated exports are runtime artifacts rather than required source files. The project also includes a SIEM bridge that can generate an export file.

## 🔄 Analysis Pipeline

The documented workflow follows these stages:

```text
Authentication CSV
        |
        v
CSV Parsing and Validation
        |
        v
Authentication Threat Detection
        |
        v
IP Geolocation Enrichment
        |
        v
Unified Threat Scoring
        |
        v
Report and Recommendations
```

SQLite storage is optional and can be disabled through the command-line interface.

## 🚀 Getting Started

### Requirements

- Python 3.8 or later.
- `pip`.
- Internet access for geolocation lookups through `ip-api.com`, unless geolocation is disabled.

### Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/ItsMazzu/mini-siem-sim.git
cd mini-siem-sim
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

### Run the project

Start the CLI:

```bash
python run.py
```

The project includes sample authentication data at `data/auth_logs.csv`.

### Command-line options

The README documents the following options:

```bash
python run.py --help
```

| Option | Purpose |
|---|---|
| `--csv` | Specify the CSV input |
| `--no-geo` | Disable geolocation enrichment |
| `--no-db` | Disable database persistence |
| `--help` | Display command-line help |

For example, to run without geolocation and database persistence:

```bash
python run.py --no-geo --no-db
```

For the exact supported syntax and defaults, consult the CLI help output.

## 🧪 Tests

The repository includes automated tests under `tests/`, including `tests/test_analyzer.py`.

Run the test suite with:

```bash
pytest tests/
```

To run tests with coverage, use:

```bash
pytest --cov=src tests/
```

The repository also lists Ruff and Mypy among its development tools.

Test execution results and coverage percentages should be measured in the target environment rather than assumed from the presence of test files or commands.

## 🔐 Security Considerations

Security-oriented behavior documented in the project includes:

- Input validation and sanitization.
- SQL injection protection.
- Timestamp validation.
- Private IP detection.
- Rotating log files.
- Caching of geolocation lookups to reduce repeated API requests.

These are implementation areas relevant to the project’s defensive security goals. Their effectiveness depends on the underlying code and should be assessed through code review and appropriate tests.

### Current scope and limitations

- The documented input is authentication data in CSV format.
- The primary interface is a command-line application.
- Geolocation depends on an external service when enabled.
- Threat scores and geolocation results are indicators for investigation, not definitive proof of malicious activity.
- The documented workflow does not establish continuous log ingestion, real-time monitoring, or automated blocking of threats.

The project should therefore be understood as a **SIEM simulator and security log analysis tool**, not a complete production SIEM or an automated incident response platform.

## 🎯 Project Goals

The project brings together several defensive security concepts in one Python application:

- Authentication log analysis.
- Suspicious activity detection.
- IP intelligence enrichment.
- Threat classification and prioritization.
- Input validation and data handling.
- Optional local persistence.
- Structured reporting and mitigation recommendations.

The focus is on combining these components into a single workflow that helps make suspicious authentication activity easier to inspect and investigate.

## 📄 License

Check the repository for license information and applicable usage terms.
