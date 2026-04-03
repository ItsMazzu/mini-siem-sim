"""
src/ui.py — Camada de interface Rich com scoring de severidade.

Melhorias em relação à versão original:
  - Cores por ThreatLevel (CRITICAL/HIGH/MEDIUM/LOW)
  - Barra visual de pontuação por IP
  - Painel de resumo de scores integrado ao display_threats()
  - Função display_status() recebe logger como parâmetro (sem print global)
"""

from typing import Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

# ─────────────────────────────────────────────
# Mapeamentos de estilo
# ─────────────────────────────────────────────

_LEVEL_COLOR = {
    "CRITICAL": "bold magenta",
    "HIGH":     "bold red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}
_LEVEL_ICON = {
    "CRITICAL": "⛔",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


def _threat_bar(score: int) -> str:
    """Barra de progresso visual para o score (0–100)."""
    filled = min(20, score // 5)
    empty  = 20 - filled
    level  = (
        "magenta" if score >= 80
        else "red"    if score >= 55
        else "yellow" if score >= 30
        else "green"
    )
    return f"[{level}][{'█' * filled}{'░' * empty}][/{level}]"


# ─────────────────────────────────────────────
# Helpers internos
# ─────────────────────────────────────────────

def _get_ip_timeline(logs: List[Dict], ip: str) -> Tuple:
    ip_fails = sorted(
        [l for l in logs if l["ip"] == ip and l["status"] == "failed"],
        key=lambda x: x["timestamp"],
    )
    if not ip_fails:
        return None, None, 0
    return ip_fails[0]["timestamp"], ip_fails[-1]["timestamp"], len(ip_fails)


# ─────────────────────────────────────────────
# Funções públicas
# ─────────────────────────────────────────────

def display_header() -> None:
    header = Text()
    header.append("[SECURITY LOG ANALYZER]\n", style="bold cyan")
    header.append("Sistema de Monitoramento de Autenticação — SOC Style", style="dim white")
    console.print(Panel(header, expand=False, border_style="cyan"))


def display_status(message: str, status_type: str = "info") -> None:
    colors = {"info": "cyan", "success": "green", "warning": "yellow", "error": "red"}
    color = colors.get(status_type, "white")
    console.print(f"[{color}]{message}[/{color}]")


def display_logs_table(logs: List[Dict], max_rows: int = 100) -> None:
    """Exibe logs em tabela formatada com status color-coded."""
    table = Table(
        title=f"[bold]Logs de Autenticação[/bold] ({len(logs)} entradas)",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Timestamp",    style="white")
    table.add_column("Usuário",      style="cyan")
    table.add_column("IP de Origem", style="magenta")
    table.add_column("Status",       justify="center")

    for log in logs[:max_rows]:
        status_color = "green" if log["status"] == "success" else "red"
        status_label = "✔ success" if log["status"] == "success" else "✘ failed"
        table.add_row(
            log["timestamp"],
            log["username"],
            log["ip"],
            f"[{status_color}]{status_label}[/{status_color}]",
        )

    if len(logs) > max_rows:
        console.print(f"[dim]... mostrando {max_rows} de {len(logs)} entradas[/dim]")

    console.print(table)


def display_summary(logs: List[Dict]) -> None:
    total     = len(logs)
    successes = sum(1 for l in logs if l["status"] == "success")
    failures  = sum(1 for l in logs if l["status"] == "failed")
    u_users   = len({l["username"] for l in logs})
    u_ips     = len({l["ip"] for l in logs})

    text = (
        f"[bold cyan]Total de Logs:[/bold cyan]      {total}\n"
        f"[bold green]Acessos bem-sucedidos:[/bold green] {successes}\n"
        f"[bold red]Tentativas falhas:[/bold red]     {failures}\n"
        f"[bold magenta]Usuários únicos:[/bold magenta]      {u_users}\n"
        f"[bold yellow]IPs únicos:[/bold yellow]           {u_ips}"
    )
    console.print(Panel(text, title="[bold]Resumo[/bold]", border_style="cyan", expand=False))


def display_threats(threat_summary: Dict, logs: List[Dict]) -> None:
    """Exibe todas as ameaças detectadas com scoring e classificação."""
    from src.analyzer import classify_attack_type

    all_threats  = threat_summary["threatened_ips"]
    scores       = threat_summary.get("scores", {})

    if not all_threats:
        console.print(Panel(
            "[green]✔  Nenhuma ameaça detectada[/green]",
            title="[bold]Status de Segurança[/bold]",
            border_style="green",
        ))
        return

    # ── Tabela de ameaças com scores ────────────────────────────────
    table = Table(
        title="[bold red]Ameaças Detectadas[/bold red]",
        show_header=True,
        header_style="bold red",
        border_style="red",
    )
    table.add_column("IP",             style="white",   min_width=16)
    table.add_column("Falhas",         justify="right")
    table.add_column("Tipo de Ataque", style="cyan")
    table.add_column("Score",          justify="right",  min_width=6)
    table.add_column("Nível",          justify="center", min_width=10)
    table.add_column("Barra",          min_width=22)

    for ip, count in sorted(all_threats.items(), key=lambda x: scores.get(x[0], (0,))[0], reverse=True):
        attack_type     = classify_attack_type(logs, ip)
        score, level    = scores.get(ip, (0, "LOW"))
        level_color     = _LEVEL_COLOR.get(level, "white")
        level_icon      = _LEVEL_ICON.get(level, "")

        table.add_row(
            ip,
            str(count),
            attack_type,
            f"[{level_color}]{score}[/{level_color}]",
            f"[{level_color}]{level_icon} {level}[/{level_color}]",
            _threat_bar(score),
        )

    console.print(table)

    # ── Detalhes por tipo de alerta ─────────────────────────────────
    if threat_summary["account_compromise_patterns"]:
        console.print()
        display_account_compromise_alerts(threat_summary["account_compromise_patterns"])

    if threat_summary["known_malicious_ips"]:
        console.print()
        display_malicious_ip_alerts(threat_summary["known_malicious_ips"], logs)


def display_account_compromise_alerts(patterns: Dict) -> None:
    text = ""
    for ip, users in patterns.items():
        for username, details in users.items():
            text += (
                f"[bold yellow][SUSPEITO][/bold yellow]  {details['recovery_time']}\n"
                f"[bold yellow]IP de Origem:[/bold yellow]  {ip}\n"
                f"[bold yellow]Conta Alvo:[/bold yellow]    {username}\n"
                f"[bold yellow]Padrão:[/bold yellow]        {details['failed_attempts']} falhas → login bem-sucedido\n"
                f"[bold yellow]Janela:[/bold yellow]        {details['first_failure']} → {details['recovery_time']}\n\n"
            )
    if text:
        console.print(Panel(
            text.strip(),
            title="[bold yellow]⚠  Possível Comprometimento de Conta[/bold yellow]",
            border_style="yellow",
            expand=False,
        ))


def display_malicious_ip_alerts(malicious_ips: Dict, logs: List[Dict] = None) -> None:
    text = ""
    for ip, count in sorted(malicious_ips.items(), key=lambda x: x[1], reverse=True):
        if logs:
            first_ts, last_ts, _ = _get_ip_timeline(logs, ip)
            text += (
                f"[bold red][BLACKLIST][/bold red]  {first_ts} → {last_ts}\n"
                f"[bold red]IP Malicioso:[/bold red] {ip}\n"
                f"[bold red]Atividade:[/bold red]    {count} tentativa(s) de fonte de ameaça conhecida\n\n"
            )
        else:
            text += f"[bold red][BLACKLIST] {ip}[/bold red] — {count} tentativa(s)\n"

    if text:
        console.print(Panel(
            text.strip(),
            title="[bold red]IP em Blacklist[/bold red]",
            border_style="red",
            expand=False,
        ))
