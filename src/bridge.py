"""
src/bridge.py — Ponte de integração com o SIEM Simulator.

Converte o output do Security Log Analyzer para o formato CSV aceito
pelo SIEM Simulator (ip_analyzer.py), permitindo análise enriquecida
com geolocalização e pontuação de ameaça detalhada.

Fluxo de integração:
  Log Analyzer                    SIEM Simulator
  ─────────────                   ───────────────
  auth_logs.csv  →  bridge.py  →  siem_export.csv  →  ip_analyzer.py

Formato de saída (compatível com siem-simulator/data/test_ips.csv):
  ip, timestamp, attempts, ports_tried, usernames_tried,
  success, user_agent, payload_sample

Uso:
  python -m src.main --export-siem          # exporta CSV
  python -m src.main --export-siem --run-siem   # exporta e roda o SIEM
"""

import csv
from collections import defaultdict
from datetime import datetime
from typing import Dict, List

from src.config import SIEM_EXPORT_PATH
from src.utils.logger import setup_logger

logger = setup_logger("bridge")


def _aggregate_by_ip(logs: List[Dict]) -> Dict[str, Dict]:
    """
    Agrega eventos de log por IP para o formato do SIEM Simulator.

    Para cada IP calcula:
      - attempts        : total de tentativas (falhas + sucessos)
      - usernames_tried : lista de usuários tentados (sem duplicatas)
      - success         : True se houve pelo menos 1 login bem-sucedido
      - first_timestamp : timestamp do primeiro evento
    """
    by_ip: Dict[str, Dict] = defaultdict(lambda: {
        "attempts":        0,
        "usernames_tried": set(),
        "success":         False,
        "first_timestamp": None,
    })

    for log in logs:
        ip = log["ip"]
        by_ip[ip]["attempts"] += 1
        by_ip[ip]["usernames_tried"].add(log["username"])

        if log["status"] == "success":
            by_ip[ip]["success"] = True

        ts = log["timestamp"]
        if by_ip[ip]["first_timestamp"] is None or ts < by_ip[ip]["first_timestamp"]:
            by_ip[ip]["first_timestamp"] = ts

    return by_ip


def export_to_siem_csv(logs: List[Dict], output_path=None) -> int:
    """
    Exporta logs agregados por IP no formato CSV do SIEM Simulator.

    Parâmetros
    ----------
    logs        : lista de logs validados do Log Analyzer
    output_path : caminho de saída (padrão: data/siem_export.csv)

    Retorna o número de IPs exportados.
    """
    path = output_path or SIEM_EXPORT_PATH
    aggregated = _aggregate_by_ip(logs)

    if not aggregated:
        logger.warning("Nenhum log para exportar ao SIEM")
        return 0

    fieldnames = [
        "ip", "timestamp", "attempts", "ports_tried",
        "usernames_tried", "success", "user_agent", "payload_sample",
    ]

    try:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()

            for ip, data in aggregated.items():
                writer.writerow({
                    "ip":              ip,
                    "timestamp":       data["first_timestamp"] or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "attempts":        data["attempts"],
                    "ports_tried":     "",   # Log Analyzer não rastreia portas
                    "usernames_tried": "|".join(sorted(data["usernames_tried"])),
                    "success":         "true" if data["success"] else "false",
                    "user_agent":      "",   # Log Analyzer não rastreia UA
                    "payload_sample":  "",   # Log Analyzer não rastreia payloads
                })
    except OSError as exc:
        logger.error(f"Erro ao exportar CSV do SIEM: {exc}")
        return 0

    logger.info(f"SIEM export: {len(aggregated)} IP(s) exportados → {path}")
    return len(aggregated)


def run_siem_analysis(siem_root: str = None) -> None:
    """
    Executa o pipeline do SIEM Simulator sobre o CSV exportado.

    Parâmetros
    ----------
    siem_root : caminho para a raiz do projeto siem-simulator.
                Se None, busca em '../siem-simulator' (estrutura padrão
                onde ambos os projetos ficam lado a lado).

    Lança ImportError se o siem-simulator não for encontrado.
    """
    import sys
    from pathlib import Path

    if siem_root is None:
        candidate = Path(__file__).parent.parent.parent / "siem-simulator"
        siem_root = str(candidate)

    sys.path.insert(0, siem_root)

    try:
        from src.detector.ip_analyzer import analyze_from_csv
        from src.report.reporter import print_result, print_summary
    except ImportError as exc:
        raise ImportError(
            f"SIEM Simulator não encontrado em '{siem_root}'.\n"
            f"Clone o repositório lado a lado e tente novamente.\n"
            f"Erro original: {exc}"
        ) from exc

    results = analyze_from_csv(str(SIEM_EXPORT_PATH))
    for result in results:
        print_result(result)
    print_summary(results)
