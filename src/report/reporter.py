"""
report/reporter.py — Exibição formatada dos resultados no terminal.

Usa colorama para cores ANSI portáveis (Windows/Linux/macOS).
Apresenta cada AnalysisResult como um card detalhado e,
ao final, um painel de resumo com contagem por nível de ameaça.
"""

from datetime import datetime
from typing import List

from colorama import Fore, Style, init

from src.models.event import AnalysisResult, ThreatLevel

# Inicializa colorama (strip=False preserva cores no Windows com ConEmu/WT)
init(autoreset=True)

# ─────────────────────────────────────────────
# Mapeamentos de estilo
# ─────────────────────────────────────────────

_LEVEL_COLOR = {
    ThreatLevel.LOW:      Fore.GREEN,
    ThreatLevel.MEDIUM:   Fore.YELLOW,
    ThreatLevel.HIGH:     Fore.RED,
    ThreatLevel.CRITICAL: Fore.MAGENTA + Style.BRIGHT,
}

_LEVEL_ICON = {
    ThreatLevel.LOW:      "🟢",
    ThreatLevel.MEDIUM:   "🟡",
    ThreatLevel.HIGH:     "🔴",
    ThreatLevel.CRITICAL: "⛔",
}

_LINE_LEN = 68


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _sep(char: str = "─", length: int = _LINE_LEN) -> str:
    return char * length


def _threat_bar(score: int) -> str:
    """Barra de progresso visual para a pontuação de ameaça."""
    total_blocks = 20
    filled = min(total_blocks, score // 5)
    empty  = total_blocks - filled

    if score >= 80:
        color = Fore.MAGENTA + Style.BRIGHT
    elif score >= 55:
        color = Fore.RED
    elif score >= 30:
        color = Fore.YELLOW
    else:
        color = Fore.GREEN

    return f"{color}[{'█' * filled}{'░' * empty}]{Style.RESET_ALL}"


# ─────────────────────────────────────────────
# Funções públicas
# ─────────────────────────────────────────────

def print_result(result: AnalysisResult) -> None:
    """Imprime o card completo de análise de um IP."""
    lvl   = result.threat_level
    color = _LEVEL_COLOR.get(lvl, Fore.WHITE)
    icon  = _LEVEL_ICON.get(lvl, "⚪")

    # ── Cabeçalho ───────────────────────────────────────────────────
    print(f"\n{_sep('═')}")
    print(f"{color}  {icon}  SIEM SIMULATOR — ANÁLISE DE IP{Style.RESET_ALL}")
    print(_sep())

    # ── Informações do IP e Geolocalização ──────────────────────────
    e   = result.event
    geo = result.geo_info

    _row("IP Analisado",   f"{Style.BRIGHT}{e.ip}{Style.RESET_ALL}")
    _row("Data / Hora",    e.timestamp.strftime("%d/%m/%Y  %H:%M:%S"))
    _row("País",           geo.country)
    _row("Região / Cidade",f"{geo.city}, {geo.region}")
    _row("ISP",            geo.isp)
    _row("Organização",    geo.org)
    _row("Coordenadas",    f"{geo.lat:.4f}, {geo.lon:.4f}")
    _row("Fuso Horário",   geo.timezone)

    print(_sep())

    # ── Avaliação de Ameaça ─────────────────────────────────────────
    bar = _threat_bar(result.threat_score)
    _row("Pontuação",       f"{color}{result.threat_score:>3}/100{Style.RESET_ALL}  {bar}")
    _row("Nível de Ameaça", f"{color}{icon} {lvl.value}{Style.RESET_ALL}")
    _row("Tipo de Ataque",  f"{Style.BRIGHT}{result.attack_type.value}{Style.RESET_ALL}")

    if result.intrusion_detected:
        intrusion_str = f"{Fore.RED + Style.BRIGHT}⚠  SIM — INTRUSÃO CONFIRMADA{Style.RESET_ALL}"
    else:
        intrusion_str = f"{Fore.GREEN}Não detectada{Style.RESET_ALL}"
    _row("Intrusão no Sistema", intrusion_str)

    print(_sep())

    # ── Metadados do Evento ─────────────────────────────────────────
    _row("Tentativas",       str(e.attempts))
    _row("Portas Testadas",  f"{len(e.ports_tried)} porta(s)"
                              + (f"  {e.ports_tried[:8]}{' ...' if len(e.ports_tried) > 8 else ''}"
                                 if e.ports_tried else ""))
    _row("Usuários Tentados", str(len(e.usernames_tried))
                              + (f"  {e.usernames_tried[:5]}{' ...' if len(e.usernames_tried) > 5 else ''}"
                                 if e.usernames_tried else ""))

    if e.user_agent:
        ua_display = e.user_agent[:62] + ("…" if len(e.user_agent) > 62 else "")
        _row("User-Agent", ua_display)

    if e.payload_sample:
        p_display = e.payload_sample[:62] + ("…" if len(e.payload_sample) > 62 else "")
        _row("Payload", f"{Fore.RED}{p_display}{Style.RESET_ALL}")

    # ── Indicadores Detectados ──────────────────────────────────────
    if result.details:
        print(f"\n  {Style.BRIGHT}Indicadores Detectados:{Style.RESET_ALL}")
        for detail in result.details:
            prefix = f"{Fore.RED}⚠ {Style.RESET_ALL}" if "INTRUSÃO" in detail.upper() else "• "
            print(f"    {prefix}{detail}")

    # ── Recomendações ───────────────────────────────────────────────
    if result.recommendations:
        print(f"\n  {Style.BRIGHT}Recomendações de Mitigação:{Style.RESET_ALL}")
        for rec in result.recommendations:
            print(f"    {rec}")

    print(f"\n  {Style.DIM}Analisado em: {result.analyzed_at.strftime('%d/%m/%Y %H:%M:%S')}{Style.RESET_ALL}")
    print(_sep("═") + "\n")


def print_summary(results: List[AnalysisResult]) -> None:
    """Imprime o painel de resumo após todas as análises."""
    now = datetime.now().strftime("%d/%m/%Y  %H:%M")
    print(_sep("═"))
    print(f"  📊  RESUMO DA SESSÃO DE ANÁLISE — {now}")
    print(_sep())

    total      = len(results)
    intrusions = sum(1 for r in results if r.intrusion_detected)

    counts = {lvl: 0 for lvl in ThreatLevel}
    for r in results:
        counts[r.threat_level] += 1

    print(f"  Total de IPs analisados  : {Style.BRIGHT}{total}{Style.RESET_ALL}")
    print()

    for lvl in ThreatLevel:
        count = counts[lvl]
        color = _LEVEL_COLOR.get(lvl, Fore.WHITE)
        icon  = _LEVEL_ICON.get(lvl, "")
        bar   = f"{color}{'■' * count}{'□' * (total - count)}{Style.RESET_ALL}" if total else ""
        print(f"  {icon} {lvl.value:<10}  {color}{count:>3}{Style.RESET_ALL}  {bar}")

    if intrusions:
        print()
        print(f"  {Fore.RED + Style.BRIGHT}⚠  Intrusões confirmadas : {intrusions}{Style.RESET_ALL}")
    else:
        print()
        print(f"  {Fore.GREEN}✔  Nenhuma intrusão confirmada nesta sessão{Style.RESET_ALL}")

    print(_sep("═") + "\n")


# ─────────────────────────────────────────────
# Helper interno
# ─────────────────────────────────────────────

def _row(label: str, value: str, label_width: int = 20) -> None:
    """Imprime uma linha formatada label: valor."""
    print(f"  {label:<{label_width}}: {value}")
