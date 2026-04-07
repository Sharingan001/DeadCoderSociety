#!/usr/bin/env python3
"""
Split-Screen TUI Layout Engine - LogSentinel Pro v4.0
Professional 70/30 split-screen terminal interface with live log monitoring.

Layout:
┌──────────────────────────────┬───────────────┐
│                              │  STATUS (30%)  │
│     MAIN PANEL (70%)         │  System Info   │
│     Command Center           │  Active Peers  │
│     Scan Results             ├───────────────┤
│     Interactive Menus        │  LOGS (30%)    │
│                              │  Event Stream  │
│                              │  Audit Trail   │
└──────────────────────────────┴───────────────┘
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable
from collections import deque

try:
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.box import DOUBLE, ROUNDED, HEAVY, SIMPLE
    from rich.align import Align
    from rich.columns import Columns
    from rich.tree import Tree
    from rich.progress import SpinnerColumn, Progress, TextColumn, BarColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class LogBuffer:
    """Thread-safe circular log buffer for real-time display."""

    def __init__(self, maxlen: int = 200):
        self._buffer = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, entry: str, level: str = "INFO"):
        with self._lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            self._buffer.append({
                "time": timestamp,
                "message": entry[:120],
                "level": level
            })

    def get_recent(self, count: int = 15) -> List[Dict]:
        with self._lock:
            return list(self._buffer)[-count:]

    def clear(self):
        with self._lock:
            self._buffer.clear()


class SystemStatus:
    """Track system status for the status panel."""

    def __init__(self):
        self.node_id = ""
        self.organization = ""
        self.license_status = "Active"
        self.uptime_start = time.time()
        self.threats_detected = 0
        self.events_processed = 0
        self.active_scans = 0
        self.peer_count = 0
        self.peers: List[Dict] = []
        self.share_active = False
        self.last_scan_time = ""
        self.risk_level = "LOW"
        self.risk_score = 0
        self.blockchain_blocks = 0
        self.cve_count = 0
        self._lock = threading.Lock()

    def update(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)

    def get_uptime(self) -> str:
        elapsed = int(time.time() - self.uptime_start)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class SplitScreenTUI:
    """Professional split-screen TUI engine."""

    def __init__(self):
        if not RICH_AVAILABLE:
            raise RuntimeError("Rich library required for split-screen TUI")

        self.console = Console()
        self.log_buffer = LogBuffer()
        self.status = SystemStatus()
        self._live = None
        self._running = False
        self._main_content = ""
        self._main_renderable = None
        self._lock = threading.Lock()

    def add_log(self, message: str, level: str = "INFO"):
        """Add entry to the log panel."""
        self.log_buffer.add(message, level)

    def update_status(self, **kwargs):
        """Update status panel data."""
        self.status.update(**kwargs)

    def set_main_content(self, renderable):
        """Set the main panel content (Rich renderable)."""
        with self._lock:
            self._main_renderable = renderable

    def _build_status_panel(self) -> Panel:
        """Build the right-side status panel."""
        s = self.status
        risk_colors = {
            "CRITICAL": "red", "HIGH": "yellow",
            "MEDIUM": "blue", "LOW": "green"
        }
        rc = risk_colors.get(s.risk_level, "white")

        # Build status content
        lines = []
        lines.append(f"[bold cyan]◆ SYSTEM STATUS[/bold cyan]")
        lines.append(f"[dim]{'─' * 22}[/dim]")
        lines.append(f"[dim]Org:[/dim] [bold]{s.organization or 'N/A'}[/bold]")
        lines.append(f"[dim]Node:[/dim] [cyan]{s.node_id[:12] or 'N/A'}[/cyan]")
        lines.append(f"[dim]License:[/dim] [green]● {s.license_status}[/green]")
        lines.append(f"[dim]Uptime:[/dim] [white]{s.get_uptime()}[/white]")
        lines.append("")
        lines.append(f"[bold yellow]◆ THREAT OVERVIEW[/bold yellow]")
        lines.append(f"[dim]{'─' * 22}[/dim]")
        # Risk gauge bar
        filled = s.risk_score // 5
        bar = "█" * filled + "░" * (20 - filled)
        lines.append(f"[{rc}]{bar}[/{rc}]")
        lines.append(f"[dim]Risk:[/dim] [{rc}]{s.risk_score}/100 {s.risk_level}[/{rc}]")
        lines.append(f"[dim]Threats:[/dim] [red]{s.threats_detected}[/red]")
        lines.append(f"[dim]Events:[/dim] [white]{s.events_processed:,}[/white]")
        lines.append(f"[dim]CVEs:[/dim] [yellow]{s.cve_count}[/yellow]")
        lines.append(f"[dim]Blockchain:[/dim] {s.blockchain_blocks} blocks")
        lines.append("")
        lines.append(f"[bold magenta]◆ INDUSTRY SHARE[/bold magenta]")
        lines.append(f"[dim]{'─' * 22}[/dim]")
        share_status = "[green]● ACTIVE[/green]" if s.share_active else "[red]● OFFLINE[/red]"
        lines.append(f"[dim]Status:[/dim] {share_status}")
        lines.append(f"[dim]Peers:[/dim] [cyan]{s.peer_count}[/cyan] connected")

        if s.peers:
            for peer in s.peers[:3]:
                ip = peer.get("ip", "?")
                lines.append(f"  [dim]├─[/dim] [green]{ip}[/green]")
            if len(s.peers) > 3:
                lines.append(f"  [dim]└─ +{len(s.peers)-3} more[/dim]")

        content = "\n".join(lines)
        return Panel(
            content,
            title="[bold white]📊 STATUS[/bold white]",
            border_style="cyan",
            box=ROUNDED,
            padding=(0, 1),
        )

    def _build_log_panel(self) -> Panel:
        """Build the bottom-right log panel."""
        entries = self.log_buffer.get_recent(12)
        level_colors = {
            "INFO": "white", "WARN": "yellow", "WARNING": "yellow",
            "ERROR": "red", "CRITICAL": "bold red",
            "DEBUG": "dim", "SHARE": "magenta",
            "SCAN": "cyan", "THREAT": "red",
        }

        if not entries:
            content = "[dim]No log entries yet...\nPerform a scan or enable Industry Share[/dim]"
        else:
            lines = []
            for entry in entries:
                color = level_colors.get(entry["level"], "white")
                lvl = entry["level"][:4].ljust(4)
                msg = entry["message"][:80]
                lines.append(
                    f"[dim]{entry['time']}[/dim] "
                    f"[{color}]{lvl}[/{color}] "
                    f"{msg}"
                )
            content = "\n".join(lines)

        return Panel(
            content,
            title="[bold white]📋 LIVE LOGS[/bold white]",
            border_style="green",
            box=ROUNDED,
            padding=(0, 1),
        )

    def _build_main_panel(self) -> Panel:
        """Build the main (left) panel."""
        with self._lock:
            if self._main_renderable:
                content = self._main_renderable
            else:
                content = self._build_default_main()

        return Panel(
            content,
            title="[bold white]🛡️  LOGSENTINEL PRO v4.0[/bold white]",
            border_style="blue",
            box=DOUBLE,
            padding=(0, 1),
        )

    def _build_default_main(self):
        """Default main panel content — command center."""
        banner = (
            "[bold cyan]"
            "██╗      ██████╗  ██████╗ ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗\n"
            "██║     ██╔═══██╗██╔════╝ ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║\n"
            "██║     ██║   ██║██║  ███╗███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║\n"
            "██║     ██║   ██║██║   ██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║\n"
            "███████╗╚██████╔╝╚██████╔╝███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗\n"
            "╚══════╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
            "[/bold cyan]"
        )

        commands = Table(box=SIMPLE, show_header=False, padding=(0, 2))
        commands.add_column("Cmd", style="bold cyan", min_width=18)
        commands.add_column("Desc", style="dim")
        commands.add_row("scan FILE [-v] [-r]", "Threat analysis with ML + PDF report")
        commands.add_row("cve FILE", "CVE vulnerability correlation")
        commands.add_row("share --status", "Industry Share status")
        commands.add_row("share --connect IP", "Connect to peer")
        commands.add_row("share --send FILE", "Share report with peers")
        commands.add_row("blockchain --verify", "Verify chain integrity")
        commands.add_row("settings --show", "View configuration")
        commands.add_row("analytics --dashboard", "Threat dashboard")
        commands.add_row("help", "Full command reference")
        commands.add_row("[yellow]logout[/yellow]", "Exit and lock")

        return Group(
            Align.center(Text.from_markup(banner)),
            Text(""),
            Align.center(Text.from_markup(
                "[bold green]Enterprise SIEM Platform[/bold green] "
                "[dim]v4.0[/dim]  "
                "[bold magenta]Industry Share Edition[/bold magenta]"
            )),
            Text(""),
            commands,
        )

    def build_layout(self) -> Layout:
        """Build the complete split-screen layout."""
        layout = Layout()

        # Main split: 70% left, 30% right
        layout.split_row(
            Layout(name="main", ratio=70),
            Layout(name="sidebar", ratio=30),
        )

        # Sidebar split: top status, bottom logs
        layout["sidebar"].split_column(
            Layout(name="status", ratio=55),
            Layout(name="logs", ratio=45),
        )

        # Populate panels
        layout["main"].update(self._build_main_panel())
        layout["status"].update(self._build_status_panel())
        layout["logs"].update(self._build_log_panel())

        return layout

    def render_once(self):
        """Render the layout once (non-interactive)."""
        self.console.clear()
        layout = self.build_layout()
        self.console.print(layout)

    def render_static(self):
        """Render a static version for terminals that don't support Live."""
        self.console.clear()
        term_width = self.console.width
        main_width = int(term_width * 0.68)
        side_width = term_width - main_width - 3

        # Top bar
        self.console.print(Panel(
            "[bold cyan]🛡️ LOGSENTINEL PRO v4.0[/bold cyan]  "
            "[bold green]Enterprise SIEM[/bold green]  "
            f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            border_style="cyan", box=HEAVY
        ))

        # Build status summary
        s = self.status
        rc = {"CRITICAL": "red", "HIGH": "yellow",
              "MEDIUM": "blue", "LOW": "green"}.get(s.risk_level, "white")

        status_table = Table(box=ROUNDED, border_style="cyan",
                            title="📊 System Status", width=term_width)
        status_table.add_column("Metric", style="bold")
        status_table.add_column("Value")
        status_table.add_column("Metric", style="bold")
        status_table.add_column("Value")
        status_table.add_row(
            "Organization", s.organization or "N/A",
            "Risk Level", f"[{rc}]{s.risk_level} ({s.risk_score}/100)[/{rc}]"
        )
        status_table.add_row(
            "Node ID", s.node_id[:16] or "N/A",
            "Threats", f"[red]{s.threats_detected}[/red]"
        )
        status_table.add_row(
            "Uptime", s.get_uptime(),
            "Events", f"{s.events_processed:,}"
        )
        share_st = "[green]● ACTIVE[/green]" if s.share_active else "[red]● OFFLINE[/red]"
        status_table.add_row(
            "Industry Share", share_st,
            "Peers", f"[cyan]{s.peer_count}[/cyan]"
        )
        self.console.print(status_table)

        # Main content
        with self._lock:
            if self._main_renderable:
                self.console.print(self._main_renderable)

        # Recent logs
        entries = self.log_buffer.get_recent(8)
        if entries:
            log_table = Table(box=ROUNDED, border_style="green",
                            title="📋 Recent Logs", width=term_width)
            log_table.add_column("Time", style="dim", width=8)
            log_table.add_column("Level", width=6)
            log_table.add_column("Message")
            lc = {"INFO": "white", "WARN": "yellow", "ERROR": "red",
                  "CRITICAL": "bold red", "SHARE": "magenta",
                  "SCAN": "cyan", "THREAT": "red"}
            for e in entries:
                c = lc.get(e["level"], "white")
                log_table.add_row(
                    e["time"],
                    f"[{c}]{e['level'][:4]}[/{c}]",
                    e["message"][:100]
                )
            self.console.print(log_table)


# ═══════════════════════════════════════════════════════════════════════════════
#  COMMAND CENTER — Interactive shell with split-screen awareness
# ═══════════════════════════════════════════════════════════════════════════════

class CommandCenter:
    """Enhanced interactive shell that integrates with the split-screen TUI."""

    def __init__(self, tui: SplitScreenTUI):
        self.tui = tui
        self.console = tui.console

    def show_scan_results(self, summary: Dict, premium_results: Dict = None):
        """Display scan results in the main panel."""
        rc = {"CRITICAL": "red", "HIGH": "yellow",
              "MEDIUM": "blue", "LOW": "green"}.get(
            summary.get("level", "LOW"), "white"
        )

        table = Table(title="📊 Scan Results", box=ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        table.add_row("Lines Analyzed", f"{summary.get('lines', 0):,}")
        table.add_row("Events Parsed", f"{summary.get('events', 0):,}")
        table.add_row("Threats Found", f"[red]{summary.get('threats', 0)}[/red]")
        table.add_row("Risk Score", f"[{rc}]{summary.get('score', 0)}/100[/{rc}]")
        table.add_row("Risk Level", f"[{rc}]{summary.get('level', 'LOW')}[/{rc}]")

        if premium_results:
            table.add_row("IOC Matches",
                         f"[red]{len(premium_results.get('intelligence_matches', []))}[/red]")
            table.add_row("ML Anomalies",
                         f"[yellow]{len(premium_results.get('anomalies', []))}[/yellow]")
            table.add_row("Attack Chains",
                         f"[magenta]{len(premium_results.get('attack_chains', []))}[/magenta]")

        self.tui.set_main_content(table)
        self.tui.update_status(
            risk_score=summary.get("score", 0),
            risk_level=summary.get("level", "LOW"),
            threats_detected=summary.get("threats", 0),
            events_processed=summary.get("events", 0),
            last_scan_time=datetime.now().strftime("%H:%M:%S"),
        )
        self.tui.add_log(
            f"Scan complete: {summary.get('threats', 0)} threats, "
            f"risk {summary.get('score', 0)}/100",
            "SCAN"
        )

    def show_cve_results(self, results: Dict):
        """Display CVE analysis results."""
        table = Table(title="🔍 CVE Analysis Results", box=ROUNDED)
        table.add_column("CVE ID", style="bold red")
        table.add_column("Severity")
        table.add_column("CVSS", justify="right")
        table.add_column("Software")
        table.add_column("Description", max_width=35)

        for vuln in results.get("potential_vulnerabilities", [])[:15]:
            sc = {"CRITICAL": "red", "HIGH": "yellow"}.get(
                vuln["severity"], "white"
            )
            table.add_row(
                vuln["cve_id"],
                f"[{sc}]{vuln['severity']}[/{sc}]",
                f"{vuln['cvss_score']}",
                vuln["detected_software"],
                vuln["description"][:35],
            )

        risk = results.get("risk_summary", {})
        summary_text = (
            f"\n[bold]Software Detected:[/bold] {risk.get('software_detected', 0)}  "
            f"[bold]Vulnerabilities:[/bold] [red]{risk.get('total_vulns', 0)}[/red]  "
            f"[bold]Critical:[/bold] [red]{risk.get('critical', 0)}[/red]  "
            f"[bold]Log4Shell:[/bold] "
            f"{'[red]YES[/red]' if risk.get('log4shell_detected') else '[green]NO[/green]'}"
        )

        self.tui.set_main_content(Group(table, Text.from_markup(summary_text)))
        self.tui.update_status(cve_count=risk.get("total_vulns", 0))
        self.tui.add_log(
            f"CVE scan: {risk.get('total_vulns', 0)} vulns, "
            f"{risk.get('critical', 0)} critical",
            "SCAN"
        )

    def show_share_status(self, status: Dict):
        """Display Industry Share status."""
        table = Table(title="🌐 Industry Share Status", box=ROUNDED)
        table.add_column("Property", style="bold")
        table.add_column("Value")

        active = status.get("active", False)
        table.add_row("Status",
                      "[green]● ACTIVE[/green]" if active else "[red]● OFFLINE[/red]")
        table.add_row("Node ID", f"[cyan]{status.get('node_id', 'N/A')}[/cyan]")
        table.add_row("Listen Port", str(status.get("listen_port", 9100)))
        table.add_row("Discovered Peers",
                      f"[cyan]{status.get('discovered_peers', 0)}[/cyan]")
        table.add_row("Reports Received",
                      str(status.get("received_reports", 0)))

        # Peer list
        peers = status.get("peers", {})
        if peers:
            peer_table = Table(title="Connected Peers", box=SIMPLE)
            peer_table.add_column("ID", style="dim")
            peer_table.add_column("IP", style="green")
            peer_table.add_column("Port")
            peer_table.add_column("Status")

            for pid, info in list(peers.items())[:10]:
                peer_table.add_row(
                    pid[:12], info.get("ip", "?"),
                    str(info.get("port", "?")), "[green]● Online[/green]"
                )

            self.tui.set_main_content(Group(table, Text(""), peer_table))
        else:
            self.tui.set_main_content(table)

        self.tui.update_status(
            share_active=active,
            peer_count=status.get("discovered_peers", 0),
            peers=list(peers.values()) if isinstance(peers, dict) else [],
        )


def test_tui():
    """Test the TUI layout."""
    if not RICH_AVAILABLE:
        print("Rich library required. Install: pip install rich")
        return

    tui = SplitScreenTUI()
    tui.update_status(
        organization="Test Corp",
        node_id="abc123def456",
        risk_score=42,
        risk_level="MEDIUM",
        threats_detected=7,
        events_processed=1523,
        share_active=True,
        peer_count=2,
        blockchain_blocks=15,
        cve_count=3,
    )
    tui.add_log("System initialized", "INFO")
    tui.add_log("Premium engines loaded", "INFO")
    tui.add_log("Industry Share started on port 9100", "SHARE")
    tui.add_log("Peer discovered: 192.168.1.20", "SHARE")
    tui.add_log("Scan started: /var/log/auth.log", "SCAN")
    tui.add_log("3 CRITICAL threats detected", "THREAT")
    tui.add_log("Report shared with 2 peers", "SHARE")

    tui.render_static()
    print("\n[Split-Screen TUI Test Complete]")


if __name__ == "__main__":
    test_tui()
