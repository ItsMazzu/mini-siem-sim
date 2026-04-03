"""
detector/ip_analyzer.py — Orquestrador do pipeline de análise.

Responsabilidades:
  1. Ler e validar eventos de um arquivo CSV
  2. Para cada evento, orquestrar:
       geo_locator → attack_classifier → threat_scorer
  3. Retornar lista de AnalysisResult prontos para exibição

Segurança aplicada no parser CSV:
  - Todos os campos passam por sanitização antes do uso
  - IPs inválidos são rejeitados com log de aviso
  - Portas fora do range 0–65535 são descartadas
  - Strings têm tamanho máximo definido
  - Erros por linha não interrompem o processamento do arquivo
"""

import csv
import os
from datetime import datetime
from typing import List, Optional

from src.detector.attack_classifier import classify_attack
from src.detector.geo_locator import get_geo_info
from src.detector.threat_scorer import (
    calculate_threat_score,
    get_recommendations,
    get_threat_level,
)
from src.models.event import AccessEvent, AnalysisResult
from src.utils.logger import setup_logger
from src.utils.validator import (
    sanitize_string,
    sanitize_username,
    validate_ip,
    validate_port,
)

logger = setup_logger("ip_analyzer")

# Limite de usernames por evento para evitar abusos de memória
_MAX_USERNAMES_PER_EVENT = 100
_MAX_PORTS_PER_EVENT     = 200


# ─────────────────────────────────────────────
# Parser CSV
# ─────────────────────────────────────────────

def _parse_ports(raw: str) -> List[int]:
    """Converte string 'porta1|porta2|...' em lista de inteiros válidos."""
    ports: List[int] = []
    for token in str(raw).split("|"):
        validated = validate_port(token.strip())
        if validated is not None:
            ports.append(validated)
        if len(ports) >= _MAX_PORTS_PER_EVENT:
            break
    return ports


def _parse_usernames(raw: str) -> List[str]:
    """Converte string 'user1|user2|...' em lista de strings sanitizadas."""
    users: List[str] = []
    for token in str(raw).split("|"):
        token = token.strip()
        if token:
            users.append(sanitize_username(token))
        if len(users) >= _MAX_USERNAMES_PER_EVENT:
            break
    return users


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes", "sim")


def _parse_timestamp(raw: str) -> datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(raw.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    logger.debug(f"Timestamp não reconhecido '{raw}' — usando now()")
    return datetime.now()


def parse_csv(filepath: str) -> List[AccessEvent]:
    """
    Lê um arquivo CSV e retorna lista de AccessEvent válidos.

    Formato esperado das colunas:
      ip, timestamp, attempts, ports_tried, usernames_tried,
      success, user_agent, payload_sample

    Colunas ausentes recebem valor padrão seguro.
    """
    events: List[AccessEvent] = []

    if not os.path.isfile(filepath):
        logger.error(f"Arquivo CSV não encontrado: {filepath}")
        return events

    try:
        with open(filepath, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for line_num, row in enumerate(reader, start=2):  # linha 1 = header
                try:
                    ip = sanitize_string(row.get("ip", "").strip(), 45)

                    if not validate_ip(ip):
                        logger.warning(f"Linha {line_num}: IP inválido '{ip}' — ignorado")
                        continue

                    raw_attempts = row.get("attempts", "1")
                    attempts     = max(1, int(str(raw_attempts).strip() or "1"))

                    event = AccessEvent(
                        ip              = ip,
                        timestamp       = _parse_timestamp(row.get("timestamp", "")),
                        attempts        = attempts,
                        ports_tried     = _parse_ports(row.get("ports_tried", "")),
                        usernames_tried = _parse_usernames(row.get("usernames_tried", "")),
                        success         = _parse_bool(row.get("success", "false")),
                        user_agent      = sanitize_string(row.get("user_agent",     ""), 300),
                        payload_sample  = sanitize_string(row.get("payload_sample", ""), 500),
                    )
                    events.append(event)
                    logger.debug(f"Linha {line_num}: evento para {ip} adicionado")

                except (ValueError, KeyError, OverflowError) as exc:
                    logger.error(f"Linha {line_num}: erro ao processar — {exc}")

    except OSError as exc:
        logger.error(f"Erro ao abrir {filepath}: {exc}")

    logger.info(f"CSV '{filepath}': {len(events)} evento(s) válido(s) lidos")
    return events


# ─────────────────────────────────────────────
# Pipeline de análise
# ─────────────────────────────────────────────

def analyze_event(event: AccessEvent) -> AnalysisResult:
    """
    Executa o pipeline completo de análise para um único AccessEvent.

      geo_locator → attack_classifier → threat_scorer → AnalysisResult
    """
    logger.info(f"Analisando: {event.ip} ({event.attempts} tentativas)")

    geo         = get_geo_info(event.ip)
    attack_type = classify_attack(event)
    score, details = calculate_threat_score(event, attack_type, geo.isp)
    level       = get_threat_level(score)
    recs        = get_recommendations(level, attack_type, event.success)

    result = AnalysisResult(
        event              = event,
        geo_info           = geo,
        threat_score       = score,
        threat_level       = level,
        attack_type        = attack_type,
        intrusion_detected = event.success,
        details            = details,
        recommendations    = recs,
    )
    logger.info(
        f"Resultado: {event.ip} | {level.value} ({score}/100) | {attack_type.value}"
    )
    return result


def analyze_from_csv(filepath: str) -> List[AnalysisResult]:
    """
    Lê o CSV e retorna resultados de análise para todos os eventos válidos.
    """
    events = parse_csv(filepath)
    if not events:
        return []

    results: List[AnalysisResult] = []
    for event in events:
        results.append(analyze_event(event))

    return results


def analyze_single_ip(ip: str, attempts: int = 1) -> Optional[AnalysisResult]:
    """
    Atalho para analisar um único IP a partir da linha de comando.
    """
    if not validate_ip(ip):
        logger.error(f"IP inválido para análise single: {ip!r}")
        return None

    event = AccessEvent(
        ip        = ip,
        timestamp = datetime.now(),
        attempts  = max(1, attempts),
    )
    return analyze_event(event)
