"""
utils/logger.py — Logger seguro com rotação de arquivos.

- Logs em arquivo com rotação (máx 5 MB, 5 backups)
- Logs no console apenas para WARNING+
- Diretório de logs criado automaticamente
- Formato padronizado com timestamp ISO
"""

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Resolve o diretório data/logs/ relativo à raiz do projeto
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
LOG_DIR = os.path.join(_PROJECT_ROOT, "data", "logs")

_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)-16s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def setup_logger(name: str = "siem") -> logging.Logger:
    """
    Cria e configura um logger nomeado.

    Parâmetros
    ----------
    name : identificador do módulo (ex.: "ip_analyzer", "geo_locator")

    Retorna
    -------
    logging.Logger configurado com handlers de arquivo e console.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger(name)

    # Evita adicionar handlers duplicados em chamadas repetidas
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Handler de arquivo com rotação ──────────────────────────────
    log_filename = f"siem_{datetime.now().strftime('%Y%m%d')}.log"
    log_filepath = os.path.join(LOG_DIR, log_filename)

    file_handler = RotatingFileHandler(
        log_filepath,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(_FORMATTER)

    # ── Handler de console (somente WARNING+) ───────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(_FORMATTER)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger
