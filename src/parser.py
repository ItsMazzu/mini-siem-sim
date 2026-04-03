"""
src/parser.py — Parser e validador seguro de logs CSV.

Melhorias em relação à versão original:
  - Validação de IP com módulo `ipaddress` (substitui regex inseguro)
  - Sanitização de username (remove caracteres de controle)
  - Logger estruturado substitui print()
  - Erros por linha não interrompem o processamento
  - parse_timestamp() centralizado aqui (elimina duplicata no analyzer)
"""

import csv
import ipaddress
import re
from datetime import datetime
from typing import Dict, List, Tuple

from src.config import DEFAULT_CSV_PATH
from src.utils.logger import setup_logger

logger = setup_logger("parser")

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_VALID_STATUSES = {"success", "failed"}


# ─────────────────────────────────────────────
# Funções de validação e sanitização
# ─────────────────────────────────────────────

def parse_timestamp(ts: str) -> datetime:
    """
    Converte string de timestamp em datetime.

    Formatos suportados:
      - YYYY-MM-DD HH:MM:SS  (padrão)
      - YYYY-MM-DDTHH:MM:SS  (ISO 8601)

    Lança ValueError se nenhum formato for reconhecido.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts.strip(), fmt)
        except (ValueError, AttributeError):
            continue
    raise ValueError(f"Timestamp não reconhecido: {ts!r}")


def validate_timestamp(ts: str) -> bool:
    """Retorna True se a string for um timestamp válido."""
    try:
        parse_timestamp(ts)
        return True
    except ValueError:
        return False


def validate_ip(ip: str) -> bool:
    """
    Valida endereço IPv4 ou IPv6 usando o módulo `ipaddress`.

    Mais seguro que regex: rejeita '999.999.999.999', '256.0.0.1' etc.
    """
    if not ip or not isinstance(ip, str):
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def sanitize_username(username: str, max_length: int = 64) -> str:
    """
    Sanitiza username: remove caracteres de controle e limita o tamanho.

    Permite apenas caracteres alfanuméricos, ponto, hífen, underscore e @.
    """
    if not isinstance(username, str):
        return ""
    cleaned = _CONTROL_CHARS.sub("", username)
    cleaned = re.sub(r"[^a-zA-Z0-9._\-@]", "", cleaned)
    return cleaned[:max_length]


# ─────────────────────────────────────────────
# Carregamento do CSV
# ─────────────────────────────────────────────

def load_csv_logs(filepath=None) -> List[Dict]:
    """
    Carrega logs de autenticação de um arquivo CSV.

    Colunas esperadas: timestamp, username, ip, status

    Parâmetros
    ----------
    filepath : caminho para o CSV (padrão: data/auth_logs.csv)

    Retorna lista de dicts com chaves: timestamp, username, ip, status.
    Entradas com colunas ausentes recebem string vazia como padrão.
    """
    path = filepath or DEFAULT_CSV_PATH

    if not path.exists():
        logger.error(f"CSV não encontrado: {path}")
        return []

    logs: List[Dict] = []
    try:
        with open(path, "r", encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for line_num, row in enumerate(reader, start=2):
                logs.append({
                    "timestamp": str(row.get("timestamp", "")).strip(),
                    "username":  str(row.get("username",  "")).strip(),
                    "ip":        str(row.get("ip",        "")).strip(),
                    "status":    str(row.get("status",    "")).strip(),
                })
    except OSError as exc:
        logger.error(f"Erro ao abrir CSV '{path}': {exc}")

    logger.info(f"CSV '{path.name}': {len(logs)} linha(s) lidas")
    return logs


def validate_logs(logs: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Valida e sanitiza todos os logs carregados.

    Verificações:
      - Timestamp no formato reconhecido
      - IP válido (ipaddress.ip_address)
      - Status: 'success' ou 'failed'

    Retorna (logs_válidos, contagem_de_inválidos).
    """
    valid: List[Dict] = []
    invalid_count = 0

    for i, log in enumerate(logs):
        errors = []

        if not validate_timestamp(log["timestamp"]):
            errors.append(f"timestamp inválido: {log['timestamp']!r}")

        if not validate_ip(log["ip"]):
            errors.append(f"IP inválido: {log['ip']!r}")

        if log["status"].lower() not in _VALID_STATUSES:
            errors.append(f"status inválido: {log['status']!r}")

        if errors:
            logger.warning(f"Linha {i + 2}: {'; '.join(errors)} — descartada")
            invalid_count += 1
            continue

        valid.append({
            "timestamp": log["timestamp"],
            "username":  sanitize_username(log["username"]),
            "ip":        log["ip"].strip(),
            "status":    log["status"].lower(),
        })

    logger.info(f"Validação: {len(valid)} válidos, {invalid_count} descartados")
    return valid, invalid_count
