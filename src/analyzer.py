"""
src/analyzer.py — Motor de análise de ameaças com scoring de severidade.

Melhorias em relação à versão original:
  - parse_timestamp() removida daqui (centralizada em parser.py)
  - Sistema de pontuação 0–100 com ThreatLevel (LOW/MEDIUM/HIGH/CRITICAL)
  - load_malicious_ips() valida cada IP antes de adicionar ao set
  - Tratamento seguro de exceções em parse de timestamps
  - Thresholds extraídos de config.py (sem magic numbers)
  - Docstrings completas em PT-BR
"""

import ipaddress
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Dict, List, Set, Tuple

from src.config import (
    ACCOUNT_COMPROMISE_MIN_FAILURES,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    CREDENTIAL_STUFFING_MIN_USERS,
    MALICIOUS_IPS_PATH,
    SCORE_ACCOUNT_COMPROMISE,
    SCORE_ATTEMPTS,
    SCORE_BRUTE_FORCE,
    SCORE_CREDENTIAL_STUFFING,
    SCORE_MALICIOUS_IP,
    THREAT_LEVEL_CRITICAL,
    THREAT_LEVEL_HIGH,
    THREAT_LEVEL_MEDIUM,
)
from src.parser import parse_timestamp
from src.utils.logger import setup_logger

logger = setup_logger("analyzer")


# ─────────────────────────────────────────────
# Carregamento da blacklist
# ─────────────────────────────────────────────

def load_malicious_ips() -> Set[str]:
    """
    Carrega IPs maliciosos conhecidos do arquivo de configuração.

    Valida cada IP com ipaddress.ip_address() antes de inserir no set.
    Linhas vazias e comentários (# ...) são ignorados silenciosamente.
    """
    malicious: Set[str] = set()

    if not MALICIOUS_IPS_PATH.exists():
        logger.warning(f"Blacklist não encontrada: {MALICIOUS_IPS_PATH}")
        return malicious

    try:
        with open(MALICIOUS_IPS_PATH, "r", encoding="utf-8") as fh:
            for line_num, raw in enumerate(fh, start=1):
                ip = raw.strip()
                if not ip or ip.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(ip)
                    malicious.add(ip)
                except ValueError:
                    logger.warning(f"Blacklist linha {line_num}: IP inválido '{ip}' — ignorado")
    except OSError as exc:
        logger.error(f"Erro ao abrir blacklist: {exc}")

    logger.info(f"Blacklist carregada: {len(malicious)} IP(s)")
    return malicious


# ─────────────────────────────────────────────
# Detecções
# ─────────────────────────────────────────────

def detect_time_based_brute_force(
    logs: List[Dict],
    window_seconds: int = BRUTE_FORCE_WINDOW_SECONDS,
    threshold: int = BRUTE_FORCE_THRESHOLD,
) -> Dict[str, List[Dict]]:
    """
    Detecta força bruta por janela de tempo deslizante.

    Identifica IPs com `threshold`+ falhas dentro de `window_seconds` segundos.

    Retorna {ip: [logs_da_janela_detectada]}.
    """
    failed = [log for log in logs if log["status"] == "failed"]

    by_ip: Dict[str, List[Dict]] = defaultdict(list)
    for log in failed:
        by_ip[log["ip"]].append(log)

    threats: Dict[str, List[Dict]] = {}

    for ip, ip_logs in by_ip.items():
        try:
            sorted_logs = sorted(ip_logs, key=lambda x: parse_timestamp(x["timestamp"]))
        except ValueError as exc:
            logger.warning(f"Timestamp inválido ignorado na detecção de brute-force ({ip}): {exc}")
            continue

        for log in sorted_logs:
            try:
                t_start = parse_timestamp(log["timestamp"])
            except ValueError:
                continue
            t_end = t_start + timedelta(seconds=window_seconds)

            window = []
            for l in sorted_logs:
                try:
                    lt = parse_timestamp(l["timestamp"])
                except ValueError:
                    continue
                if t_start <= lt <= t_end:
                    window.append(l)

            if len(window) >= threshold:
                threats[ip] = window
                break

    return threats


def detect_credential_stuffing(logs: List[Dict]) -> Dict[str, int]:
    """
    Detecta credential stuffing: um mesmo IP atacando muitos usuários distintos.

    Retorna {ip: quantidade_de_usuários_distintos} para IPs acima do limiar.
    """
    failed = [log for log in logs if log["status"] == "failed"]

    by_ip: Dict[str, set] = defaultdict(set)
    for log in failed:
        by_ip[log["ip"]].add(log["username"])

    return {
        ip: len(users)
        for ip, users in by_ip.items()
        if len(users) >= CREDENTIAL_STUFFING_MIN_USERS
    }


def detect_account_compromise_pattern(logs: List[Dict]) -> Dict[str, Dict]:
    """
    Detecta padrão: N falhas seguidas de login bem-sucedido (mesmo IP + usuário).

    Indica possível comprometimento de conta por força bruta bem-sucedida.

    Retorna {ip: {username: {failed_attempts, recovery_time, first_failure}}}.
    """
    patterns: Dict[str, Dict] = {}

    by_ip_user: Dict[Tuple, List[Dict]] = defaultdict(list)
    for log in logs:
        by_ip_user[(log["ip"], log["username"])].append(log)

    for (ip, username), user_logs in by_ip_user.items():
        try:
            sorted_logs = sorted(user_logs, key=lambda x: parse_timestamp(x["timestamp"]))
        except ValueError:
            continue

        failures = 0
        failure_logs: List[Dict] = []

        for log in sorted_logs:
            if log["status"] == "failed":
                failures += 1
                failure_logs.append(log)
            elif log["status"] == "success" and failures >= ACCOUNT_COMPROMISE_MIN_FAILURES:
                patterns.setdefault(ip, {})[username] = {
                    "failed_attempts": failures,
                    "recovery_time":   log["timestamp"],
                    "first_failure":   failure_logs[0]["timestamp"] if failure_logs else None,
                }
                failures = 0
                failure_logs = []

    return patterns


def detect_known_malicious_activity(logs: List[Dict]) -> Dict[str, int]:
    """
    Detecta atividade de IPs presentes na blacklist.

    Retorna {ip: total_de_tentativas} para IPs reconhecidos.
    """
    malicious_ips = load_malicious_ips()
    if not malicious_ips:
        return {}

    counts: Dict[str, int] = {}
    for log in logs:
        if log["ip"] in malicious_ips:
            counts[log["ip"]] = counts.get(log["ip"], 0) + 1

    return counts


# ─────────────────────────────────────────────
# Classificação e Scoring
# ─────────────────────────────────────────────

def classify_attack_type(logs: List[Dict], ip: str) -> str:
    """
    Classifica o tipo de ataque de um IP com base nos seus logs.

    Pode retornar múltiplos tipos combinados (ex: 'Força Bruta & Credential Stuffing').
    """
    ip_failed = [log for log in logs if log["ip"] == ip and log["status"] == "failed"]

    if not ip_failed:
        return "Desconhecido"

    targeted_users: Dict[str, int] = {}
    for log in ip_failed:
        targeted_users[log["username"]] = targeted_users.get(log["username"], 0) + 1

    unique_users      = len(targeted_users)
    max_per_user      = max(targeted_users.values()) if targeted_users else 0
    total_failures    = len(ip_failed)

    attack_types = []

    if max_per_user >= BRUTE_FORCE_THRESHOLD:
        attack_types.append("Força Bruta")

    if unique_users >= CREDENTIAL_STUFFING_MIN_USERS:
        attack_types.append("Credential Stuffing")

    if not attack_types and total_failures >= BRUTE_FORCE_THRESHOLD:
        attack_types.append("Força Bruta")

    return " & ".join(attack_types) if attack_types else "Suspeito"


def calculate_threat_score(
    ip: str,
    logs: List[Dict],
    brute_force_ips: set,
    stuffing_ips: set,
    compromise_ips: set,
    malicious_ips: set,
) -> int:
    """
    Calcula pontuação de ameaça (0–100) para um IP.

    Fatores:
      - Volume de tentativas falhas     (0–40 pts)
      - Força bruta detectada           (+20 pts)
      - Credential stuffing detectado   (+25 pts)
      - Comprometimento de conta        (+30 pts)
      - IP na blacklist                 (+35 pts)
    """
    score = 0
    failed_count = sum(1 for log in logs if log["ip"] == ip and log["status"] == "failed")

    # Volume de tentativas
    for label, (min_attempts, pts) in SCORE_ATTEMPTS.items():
        if failed_count >= min_attempts:
            score += pts
            break

    if ip in brute_force_ips:
        score += SCORE_BRUTE_FORCE
    if ip in stuffing_ips:
        score += SCORE_CREDENTIAL_STUFFING
    if ip in compromise_ips:
        score += SCORE_ACCOUNT_COMPROMISE
    if ip in malicious_ips:
        score += SCORE_MALICIOUS_IP

    return min(100, score)


def get_threat_level(score: int) -> str:
    """Converte pontuação em nível de ameaça textual."""
    if score >= THREAT_LEVEL_CRITICAL:
        return "CRITICAL"
    if score >= THREAT_LEVEL_HIGH:
        return "HIGH"
    if score >= THREAT_LEVEL_MEDIUM:
        return "MEDIUM"
    return "LOW"


# ─────────────────────────────────────────────
# Sumário completo
# ─────────────────────────────────────────────

def get_threat_summary(logs: List[Dict]) -> Dict:
    """
    Executa todas as detecções e retorna sumário consolidado.

    Campos retornados:
      threatened_ips            : {ip: falhas} para IPs com >= threshold falhas
      time_based_brute_force    : {ip: [logs_da_janela]}
      credential_stuffing       : {ip: nº_usuários_distintos}
      account_compromise_patterns: {ip: {username: detalhes}}
      known_malicious_ips       : {ip: total_tentativas}
      scores                    : {ip: (score, threat_level)}
    """
    failed_counts = Counter(log["ip"] for log in logs if log["status"] == "failed")

    bf      = detect_time_based_brute_force(logs)
    cs      = detect_credential_stuffing(logs)
    ac      = detect_account_compromise_pattern(logs)
    mal     = detect_known_malicious_activity(logs)

    # IPs relevantes: qualquer IP com ameaça detectada OU >= threshold falhas
    all_threat_ips = (
        set(failed_counts.keys()) |
        set(bf.keys()) | set(cs.keys()) | set(ac.keys()) | set(mal.keys())
    )
    threatened = {ip: failed_counts[ip] for ip in all_threat_ips if failed_counts[ip] > 0}

    # Scores individuais
    scores = {}
    for ip in all_threat_ips:
        s = calculate_threat_score(
            ip, logs,
            brute_force_ips=set(bf.keys()),
            stuffing_ips=set(cs.keys()),
            compromise_ips=set(ac.keys()),
            malicious_ips=set(mal.keys()),
        )
        scores[ip] = (s, get_threat_level(s))

    return {
        "threatened_ips":              threatened,
        "time_based_brute_force":      bf,
        "credential_stuffing":         cs,
        "account_compromise_patterns": ac,
        "known_malicious_ips":         mal,
        "scores":                      scores,
    }
