"""
src/database.py — Operações SQLite com segurança e performance.

Melhorias em relação à versão original:
  - WAL mode: permite leituras concorrentes sem bloquear escritas
  - Índices em ip_address e timestamp para queries rápidas
  - Context manager garante fechamento de conexão mesmo com exceção
  - Histórico preservado: flag clear_existing=False por padrão
  - Queries parametrizadas (já existiam, mantidas)
  - Logger substitui print()
"""

import sqlite3
from contextlib import contextmanager
from typing import Dict, Generator, List

from src.config import DB_DIR, DB_PATH
from src.utils.logger import setup_logger

logger = setup_logger("database")


# ─────────────────────────────────────────────
# Context manager de conexão
# ─────────────────────────────────────────────

@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    """
    Context manager que abre, configura e fecha a conexão com segurança.

    Configurações aplicadas:
      - WAL mode: melhor concorrência (leitores não bloqueiam escritores)
      - row_factory: retorna dicts em vez de tuplas
      - foreign_keys: PRAGMA de integridade referencial
    """
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# Inicialização
# ─────────────────────────────────────────────

def initialize_database() -> None:
    """
    Cria a tabela auth_logs e seus índices (se não existirem).

    Schema:
      id          INTEGER  PRIMARY KEY AUTOINCREMENT
      timestamp   TEXT     NOT NULL
      username    TEXT     NOT NULL
      ip_address  TEXT     NOT NULL
      status      TEXT     NOT NULL   CHECK(success|failed)
      inserted_at TEXT     NOT NULL DEFAULT (datetime('now'))

    Índices: ip_address, timestamp — aceleram queries de análise.
    """
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                ip_address  TEXT    NOT NULL,
                status      TEXT    NOT NULL
                            CHECK(status IN ('success', 'failed')),
                inserted_at TEXT    NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_ip
            ON auth_logs (ip_address)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_auth_ts
            ON auth_logs (timestamp)
        """)
    logger.info("Banco de dados inicializado")


# ─────────────────────────────────────────────
# Escrita
# ─────────────────────────────────────────────

def store_logs_batch(logs: List[Dict], clear_existing: bool = False) -> None:
    """
    Armazena logs em lote usando executemany().

    Parâmetros
    ----------
    logs           : lista de dicts com chaves timestamp/username/ip/status
    clear_existing : se True, apaga os logs anteriores antes de inserir
                     (padrão False — preserva histórico)
    """
    if not logs:
        logger.warning("store_logs_batch chamado com lista vazia")
        return

    initialize_database()

    with _get_conn() as conn:
        if clear_existing:
            conn.execute("DELETE FROM auth_logs")
            logger.info("Logs anteriores removidos (clear_existing=True)")

        tuples = [
            (log["timestamp"], log["username"], log["ip"], log["status"])
            for log in logs
        ]
        conn.executemany(
            "INSERT INTO auth_logs (timestamp, username, ip_address, status) VALUES (?, ?, ?, ?)",
            tuples,
        )

    logger.info(f"{len(logs)} log(s) inseridos no banco")


# ─────────────────────────────────────────────
# Leitura
# ─────────────────────────────────────────────

def get_all_logs() -> List[Dict]:
    """Retorna todos os logs ordenados por timestamp."""
    if not DB_PATH.exists():
        return []

    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM auth_logs ORDER BY timestamp ASC"
        ).fetchall()

    return [dict(row) for row in rows]


def get_logs_by_ip(ip_address: str) -> List[Dict]:
    """
    Retorna logs de um IP específico, ordenados por timestamp.

    Usa query parametrizada — sem risco de SQL Injection.
    """
    if not DB_PATH.exists():
        return []

    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM auth_logs WHERE ip_address = ? ORDER BY timestamp ASC",
            (ip_address,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_failure_count_by_ip() -> Dict[str, int]:
    """Retorna {ip: total_de_falhas} para todos os IPs com pelo menos 1 falha."""
    if not DB_PATH.exists():
        return {}

    with _get_conn() as conn:
        rows = conn.execute("""
            SELECT ip_address, COUNT(*) as cnt
            FROM auth_logs
            WHERE status = 'failed'
            GROUP BY ip_address
            ORDER BY cnt DESC
        """).fetchall()

    return {row["ip_address"]: row["cnt"] for row in rows}
