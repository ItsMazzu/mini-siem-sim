"""
src/pipeline.py — Unified pipeline orchestrator for Mini SIEM Simulator.

Coordinates the full analysis flow:
  1. Load auth logs from CSV
  2. Validate logs
  3. Analyze threats (brute force, credential stuffing, etc.)  [AUTH → GEO]
  4. Geolocation for each IP (with caching)
  5. Unified threat scoring
  6. Generate recommendations

Flow:
  CSV → Validator → Auth Analysis → Geolocation (cached) → Unified Scoring → Results
"""

from datetime import datetime
from typing import Dict, List, Optional, Tuple

from src import analyzer, database
from src.parser import load_csv_logs, validate_logs
from src.detector.geo_locator import get_geo_info
from src.detector.attack_classifier import classify_attack
from src.detector.threat_scorer import calculate_threat_score, get_threat_level
from src.models.event import AccessEvent, AnalysisResult, GeoInfo, ThreatLevel, AttackType
from src.config import GEO_CACHE_ENABLED, ENABLE_GEOLOCATION_BY_DEFAULT, ENABLE_DATABASE_BY_DEFAULT
from src.utils.logger import setup_logger

logger = setup_logger("pipeline")


class UnifiedPipeline:
    """Main orchestrator for Mini SIEM Simulator analysis."""

    def __init__(
        self,
        use_geolocation: bool = ENABLE_GEOLOCATION_BY_DEFAULT,
        use_database: bool = ENABLE_DATABASE_BY_DEFAULT,
    ):
        """
        Initialize pipeline.

        Parameters
        ----------
        use_geolocation : whether to perform geolocation (can be expensive)
        use_database    : whether to persist results to SQLite
        """
        self.use_geolocation = use_geolocation
        self.use_database = use_database
        self.geo_cache: Dict[str, GeoInfo] = {}  # IP → GeoInfo
        self.geo_fetch_failed: Dict[str, str] = {}  # IP → failure reason

    def run(self, csv_path) -> Tuple[List[Dict], List[AnalysisResult]]:
        """
        Execute complete pipeline from CSV to analysis results.

        Parameters
        ----------
        csv_path : path to authentication logs CSV

        Returns
        -------
        (auth_logs: List[Dict], results: List[AnalysisResult])
        """
        # Phase 1: Load & validate logs
        logger.info("=" * 70)
        logger.info("PHASE 1: Loading authentication logs")
        logger.info("=" * 70)

        auth_logs = load_csv_logs(csv_path)
        if not auth_logs:
            logger.error("No logs found. Aborting.")
            return [], []

        logger.info(f"✓ {len(auth_logs)} log(s) loaded")

        # Phase 2: Validate logs
        logger.info("=" * 70)
        logger.info("PHASE 2: Validating logs")
        logger.info("=" * 70)

        valid_logs, invalid_count = validate_logs(auth_logs)
        if invalid_count:
            logger.warning(f"⚠ {invalid_count} invalid entry(ies) discarded")

        logger.info(f"✓ {len(valid_logs)} valid log(s)")

        # Phase 3: Persist raw logs (optional)
        if self.use_database:
            logger.info("=" * 70)
            logger.info("PHASE 3: Storing logs in database")
            logger.info("=" * 70)

            database.initialize_database()
            database.store_logs_batch(valid_logs, clear_existing=False)
            logger.info(f"✓ Logs persisted to SQLite")

        # Phase 4: Analyze threats from auth logs (AUTH FIRST)
        logger.info("=" * 70)
        logger.info("PHASE 4: Analyzing authentication patterns")
        logger.info("=" * 70)

        malicious_ips = analyzer.load_malicious_ips()
        auth_threats = analyzer.detect_all_threats(valid_logs, malicious_ips)

        logger.info(f"✓ Identified {len(auth_threats)} IP(s) with threats")

        # Phase 5: Enriched analysis with geolocation (GEO AFTER AUTH)
        logger.info("=" * 70)
        logger.info("PHASE 5: Enriching threats with geolocation")
        logger.info("=" * 70)

        results = self._enrich_threats(auth_threats, valid_logs)

        # Phase 6: Return results
        logger.info("=" * 70)
        logger.info("PHASE 6: Pipeline complete")
        logger.info("=" * 70)

        return valid_logs, results

    def _enrich_threats(
        self,
        auth_threats: Dict[str, Dict],
        all_logs: List[Dict],
    ) -> List[AnalysisResult]:
        """
        Enrich auth threats with geolocation and unified scoring.

        Parameters
        ----------
        auth_threats : Dict[ip] → threat metadata from auth analysis
        all_logs     : all validated auth logs

        Returns
        -------
        List of AnalysisResult with full enrichment
        """
        results: List[AnalysisResult] = []

        for ip, threat_data in auth_threats.items():
            # Build AccessEvent from threat data
            event = AccessEvent(
                ip=ip,
                timestamp=threat_data.get("first_timestamp", datetime.now()),
                attempts=threat_data.get("attempts", 0),
                ports_tried=[],
                usernames_tried=list(threat_data.get("usernames", set())),
                success=threat_data.get("success", False),
                user_agent="",
                payload_sample="",
            )

            # Get or fetch geolocation (with caching)
            geo_info = self._get_cached_geo(ip)

            # Classify attack type
            attack_type = classify_attack(event)

            # Calculate unified threat score
            score, details = calculate_threat_score(event, attack_type, geo_info.org)

            # Determine threat level
            threat_level = get_threat_level(score)

            # Check if intrusion detected (successful + suspicious)
            intrusion = event.success and threat_data.get("success", False)

            # Generate recommendations
            recommendations = self._generate_recommendations(attack_type, threat_level, intrusion)

            # Add geolocation warning if fetch failed
            if geo_info.country == "Desconhecido" and self.use_geolocation:
                if ip in self.geo_fetch_failed:
                    details.append(f"⚠ Geolocation failed: {self.geo_fetch_failed[ip]}")

            # Create result
            result = AnalysisResult(
                event=event,
                geo_info=geo_info,
                threat_score=score,
                threat_level=threat_level,
                attack_type=attack_type,
                intrusion_detected=intrusion,
                details=details,
                recommendations=recommendations,
            )

            results.append(result)
            logger.debug(f"IP {ip}: score={score}, level={threat_level.value}")

        return results

    def _get_cached_geo(self, ip: str) -> GeoInfo:
        """
        Get geolocation with caching to avoid redundant API calls.

        Parameters
        ----------
        ip : IP address

        Returns
        -------
        GeoInfo object (either cached or fetched)
        """
        if ip in self.geo_cache:
            logger.debug(f"Geo cache hit for {ip}")
            return self.geo_cache[ip]

        if not self.use_geolocation:
            logger.debug(f"Geolocation disabled, using empty GeoInfo for {ip}")
            geo = GeoInfo()
        else:
            logger.debug(f"Fetching geolocation for {ip}...")
            try:
                geo = get_geo_info(ip)
                if geo.country == "Desconhecido":
                    self.geo_fetch_failed[ip] = "API returned unknown values"
            except Exception as e:
                logger.warning(f"Geolocation failed for {ip}: {e}. Using empty GeoInfo.")
                geo = GeoInfo()
                self.geo_fetch_failed[ip] = str(e)

        # Cache result
        if GEO_CACHE_ENABLED:
            self.geo_cache[ip] = geo

        return geo

    def _generate_recommendations(
        self,
        attack_type: AttackType,
        threat_level: ThreatLevel,
        intrusion_detected: bool,
    ) -> List[str]:
        """Generate mitigation recommendations based on attack type and threat."""
        recommendations = []

        # Intrusion confirmed — immediate response
        if intrusion_detected:
            recommendations.append("🚨 CRITICAL: Intrusion confirmed — activate incident response")
            recommendations.append("🚨 Isolate affected systems immediately")
            recommendations.append("🚨 Preserve all logs for forensics")
            recommendations.append("🚨 Block IP at firewall / revoke sessions")
            return recommendations

        # Base recommendations by threat level
        if threat_level == ThreatLevel.CRITICAL:
            recommendations.append("🔴 IMMEDIATE ACTION: Block IP address")
            recommendations.append("🔴 Review recent access logs for breach evidence")
            recommendations.append("🔴 Enable enhanced monitoring")

        elif threat_level == ThreatLevel.HIGH:
            recommendations.append("🟠 Block IP or enforce strict rate limiting")
            recommendations.append("🟠 Monitor account activity for compromise signs")
            recommendations.append("🟠 Review access logs for lateral movement")

        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.append("🟡 Review access logs for patterns")
            recommendations.append("🟡 Consider temporary IP restrictions")
            recommendations.append("🟡 Monitor for repeat attempts")

        else:  # LOW
            recommendations.append("🟢 Continue monitoring")
            recommendations.append("🟢 No immediate action required")

        # Specific recommendations by attack type
        if attack_type == AttackType.BRUTE_FORCE:
            recommendations.append("→ Enforce stronger password policies")
            recommendations.append("→ Implement MFA (Multi-Factor Authentication)")
            recommendations.append("→ Deploy account lockout mechanisms")

        elif attack_type == AttackType.CREDENTIAL_STUFFING:
            recommendations.append("→ Alert affected users to change passwords")
            recommendations.append("→ Check for unauthorized access attempts")
            recommendations.append("→ Consider credential rotation across systems")

        elif attack_type == AttackType.SQL_INJECTION:
            recommendations.append("→ Review application code for SQL injection flaws")
            recommendations.append("→ Update WAF rules to block similar payloads")
            recommendations.append("→ Conduct code security audit")

        elif attack_type == AttackType.PORT_SCAN:
            recommendations.append("→ Review open ports and close unnecessary services")
            recommendations.append("→ Update firewall rules aggressively")
            recommendations.append("→ Deploy intrusion detection system (IDS)")

        elif attack_type == AttackType.DOS_ATTEMPT:
            recommendations.append("→ Activate DDoS mitigation (rate limiting, filtering)")
            recommendations.append("→ Increase bandwidth allocation temporarily")
            recommendations.append("→ Consider blocking entire AS range if needed")

        return recommendations
