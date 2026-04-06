#!/usr/bin/env python3
"""
LogSentinel Pro v3.0 - Admin CLI
License key generation and management tool for administrators.
"""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import socket
import sys
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich.box import DOUBLE, ROUNDED, HEAVY
    from rich.tree import Tree
    from rich.align import Align
    from rich.prompt import Prompt, Confirm
    RICH = True
except ImportError:
    RICH = False

console = Console() if RICH else None

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

class Config:
    VERSION = "3.0.0"
    APP_NAME = "LogSentinel Admin"
    DATA_DIR = Path.home() / ".local" / "share" / "LogSentinel Pro"
    DB_PATH = DATA_DIR / "licenses.db"
    ADMIN_SESSION = DATA_DIR / ".admin_session"
    ADMIN_PASSWORD_HASH = "68b88e7a13da5235eb6ee3818c8f115879752c890d3e8c13da5af2d0db07f1e7"  # Dead-Coder-Society

# ═══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════════════

BANNER = """[bold red]
 ▄▄▄      ▓█████▄  ███▄ ▄███▓ ██▓ ███▄    █ 
▒████▄    ▒██▀ ██▌▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █ 
▒██  ▀█▄  ░██   █▌▓██    ▓██░▒██▒▓██  ▀█ ██▒
░██▄▄▄▄██ ░▓█▄   ▌▒██    ▒██ ░██░▓██▒  ▐▌██▒
 ▓█   ▓██▒░▒████▓ ▒██▒   ░██▒░██░▒██░   ▓██░
 ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░ ░ ▒  ▒ ░  ░      ░ ▒ ░░ ░░   ░ ▒░
  ░   ▒    ░ ░  ░ ░      ░    ▒ ░   ░   ░ ░ 
      ░  ░   ░           ░    ░           ░ 
           ░                                 
[/bold red][bold yellow]
  ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██╗     ███████╗
 ██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██║     ██╔════╝
 ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║     █████╗  
 ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║     ██╔══╝  
 ╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝███████╗███████╗
  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚══════╝╚══════╝
[/bold yellow]"""

MINI_BANNER = """[bold red]╔═══════════════════════════════════════════════════════════════════╗
║[/bold red] [bold white]🔐 LOGSENTINEL ADMIN[/bold white] [dim]v3.0.0[/dim]  [bold red]License Management Console[/bold red]     [bold red]║
╚═══════════════════════════════════════════════════════════════════╝[/bold red]"""

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS & ANIMATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def spinner(msg: str, duration: float = 1.0):
    if not RICH:
        print(f"{msg}...")
        time.sleep(duration)
        return
    with console.status(f"[bold yellow]{msg}...", spinner="dots12"):
        time.sleep(duration)

def loading_bar(description: str, total: int = 100, duration: float = 1.0):
    """Show a loading bar with specified duration."""
    if not RICH:
        print(f"{description}...")
        time.sleep(duration)
        return
    
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn(f"[bold red]{description}"),
        BarColumn(bar_width=30, complete_style="red", finished_style="yellow"),
        TextColumn("[bold]{task.percentage:>3.0f}%"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(description, total=total)
        step_delay = duration / total
        for _ in range(total):
            progress.update(task, advance=1)
            time.sleep(step_delay)

def boot_sequence():
    """Admin console boot animation."""
    if not RICH:
        print("\n[Starting Admin Console...]\n")
        return
    
    boot_items = [
        ("Initializing admin modules", "red"),
        ("Loading license database", "yellow"),
        ("Connecting to audit system", "red"),
        ("Starting management console", "yellow"),
    ]
    
    with Progress(
        SpinnerColumn(spinner_name="dots12"),
        TextColumn("[bold {task.fields[color]}]{task.description}"),
        BarColumn(bar_width=25, complete_style="yellow", finished_style="green"),
        TextColumn("[dim]{task.percentage:>3.0f}%[/dim]"),
        console=console,
        transient=True
    ) as progress:
        for item, color in boot_items:
            task = progress.add_task(item, total=100, color=color)
            for _ in range(100):
                progress.update(task, advance=1)
                time.sleep(0.006)
    
    console.print("[bold yellow]✓[/bold yellow] [dim]Admin console ready[/dim]")
    console.print()

def display_banner_animated():
    """Display admin banner with animation."""
    if not RICH:
        print("\n=== LOGSENTINEL ADMIN v3.0.0 ===\n")
        return
    
    console.print(BANNER)
    time.sleep(0.2)

def success(msg: str):
    if RICH:
        console.print(f"[bold green]✅ {msg}[/bold green]")
    else:
        print(f"✅ {msg}")

def error(msg: str):
    if RICH:
        console.print(f"[bold red]❌ {msg}[/bold red]")
    else:
        print(f"❌ {msg}")

def warning(msg: str):
    if RICH:
        console.print(f"[bold yellow]⚠️  {msg}[/bold yellow]")
    else:
        print(f"⚠️  {msg}")

def show_admin_status():
    """Show admin status line."""
    if not RICH:
        return
    timestamp = datetime.now().strftime("%H:%M:%S")
    console.print(
        f"[dim]┌─ Mode:[/dim] [bold red]ADMINISTRATOR[/bold red] "
        f"[dim]│ Status:[/dim] [yellow]● Active[/yellow] "
        f"[dim]│ Time:[/dim] [cyan]{timestamp}[/cyan] [dim]─┐[/dim]"
    )

def admin_auth_check() -> Tuple[bool, str]:
    """
    Check admin authentication. Prompt for password if needed.
    Returns (success, admin_name).
    """
    # Check for existing session
    if Config.ADMIN_SESSION.exists():
        try:
            session = json.loads(Config.ADMIN_SESSION.read_text())
            if datetime.fromisoformat(session.get("expires", "2000-01-01")) > datetime.now():
                return True, session.get("admin", "Admin")
        except:
            pass
    
    # Show admin login screen
    if RICH:
        console.clear()
        display_banner_animated()
        loading_bar("Loading admin console", 50, 0.4)
        console.print()
        
        console.print(Panel(
            "[bold red]🔐 ADMIN AUTHENTICATION[/bold red]\n\n"
            "[dim]This is a restricted administrative console.[/dim]\n"
            "[dim]Unauthorized access is prohibited and logged.[/dim]",
            title="⚠️  Security Notice", border_style="red", box=DOUBLE
        ))
        console.print()
    else:
        print("\n=== ADMIN AUTHENTICATION ===\n")
    
    # Prompt for credentials
    max_attempts = 3
    for attempt in range(max_attempts):
        remaining = max_attempts - attempt
        
        if RICH:
            attempt_bar = "[yellow]●[/yellow]" * attempt + "[red]○[/red]" + "[dim]○[/dim]" * (remaining - 1)
            console.print(f"[dim]Attempts:[/dim] {attempt_bar}  [dim]({remaining} remaining)[/dim]")
            console.print()
            
            try:
                admin_name = console.input("[bold yellow]Admin Name > [/bold yellow]").strip()
                password = console.input("[bold yellow]Password > [/bold yellow]", password=True).strip()
            except (KeyboardInterrupt, EOFError):
                console.print("\n[dim]Cancelled.[/dim]")
                return False, ""
        else:
            try:
                admin_name = input("Admin Name: ").strip()
                password = input("Password: ").strip()
            except (KeyboardInterrupt, EOFError):
                return False, ""
        
        if not admin_name or not password:
            warning("Please enter credentials.")
            continue
        
        # Validate password hash
        spinner("Authenticating", 1.0)
        
        # Check password against stored hash
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if admin_name and password_hash == Config.ADMIN_PASSWORD_HASH:
            # Save session
            Config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            session = {
                "admin": admin_name,
                "expires": (datetime.now() + timedelta(hours=8)).isoformat(),
                "authenticated_at": datetime.now().isoformat()
            }
            Config.ADMIN_SESSION.write_text(json.dumps(session))
            
            if RICH:
                console.print()
                console.print(Panel(
                    f"[bold green]✅ AUTHENTICATED[/bold green]\n\n"
                    f"[dim]Admin:[/dim] [bold white]{admin_name}[/bold white]\n"
                    f"[dim]Session:[/dim] [green]8 hours[/green]",
                    title="🔓 Access Granted", border_style="green"
                ))
                boot_sequence()
            return True, admin_name
        else:
            if RICH:
                console.print(Panel("[bold red]Invalid credentials[/bold red]", title="❌ Failed", border_style="red"))
            else:
                print("❌ Invalid credentials")
    
    # Max attempts
    if RICH:
        console.print(Panel(
            "[bold red]Maximum attempts reached.[/bold red]\n\n"
            "[dim]This incident has been logged.[/dim]",
            title="🚫 Access Denied", border_style="red"
        ))
    return False, ""

# ═══════════════════════════════════════════════════════════════════════════════
#  DATABASE MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

class LicenseDB:
    def __init__(self):
        self.db_path = Config.DB_PATH
        self._ensure_db()
    
    def _ensure_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                device_fingerprint TEXT,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                issued_by TEXT,
                organization TEXT,
                max_duration_hours INTEGER,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT,
                action TEXT,
                device_fingerprint TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT,
                error_message TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def generate_key(self, org: str, hours: int, issuer: str, notes: str = "") -> str:
        combined = str(uuid.uuid4()) + str(uuid.uuid4()) + str(datetime.now().timestamp()) + org
        key = hashlib.sha256(combined.encode()).hexdigest()
        
        now = datetime.now()
        expires = now + timedelta(hours=hours)
        
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO licenses (key, issued_at, expires_at, is_used, issued_by, organization, max_duration_hours, notes)
            VALUES (?, ?, ?, 0, ?, ?, ?, ?)
        """, (key, now.isoformat(), expires.isoformat(), issuer, org, hours, notes))
        conn.commit()
        conn.close()
        
        return key
    
    def get_all_licenses(self) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT key, organization, is_used, device_fingerprint, expires_at, issued_at, issued_by, notes
            FROM licenses ORDER BY created_at DESC
        """)
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            "key": r[0], "organization": r[1], "is_used": r[2],
            "device_fingerprint": r[3], "expires_at": r[4],
            "issued_at": r[5], "issued_by": r[6], "notes": r[7]
        } for r in rows]
    
    def get_stats(self) -> Dict:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        stats = {}
        cursor.execute("SELECT COUNT(*) FROM licenses")
        stats["total"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 0")
        stats["available"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE is_used = 1")
        stats["activated"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE datetime(expires_at) < datetime('now')")
        stats["expired"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM auth_audit")
        stats["audit_entries"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM auth_audit WHERE status = 'FAILED'")
        stats["failed_attempts"] = cursor.fetchone()[0]
        
        conn.close()
        return stats
    
    def revoke_key(self, key: str) -> bool:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("DELETE FROM licenses WHERE key = ?", (key,))
        affected = cursor.rowcount
        conn.commit()
        conn.close()
        return affected > 0
    
    def get_audit_trail(self, limit: int = 50) -> List[Dict]:
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, license_key, action, device_fingerprint, timestamp, status, error_message
            FROM auth_audit ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        return [{
            "id": r[0], "key": r[1], "action": r[2],
            "device": r[3], "timestamp": r[4], "status": r[5], "error": r[6]
        } for r in rows]
    
    def export_keys(self, filepath: str) -> int:
        licenses = self.get_all_licenses()
        with open(filepath, 'w') as f:
            f.write("key,organization,status,expires_at,issued_by,notes\n")
            for lic in licenses:
                status = "ACTIVATED" if lic["is_used"] else "AVAILABLE"
                f.write(f"{lic['key']},{lic['organization']},{status},{lic['expires_at']},{lic['issued_by']},{lic['notes'] or ''}\n")
        return len(licenses)

# ═══════════════════════════════════════════════════════════════════════════════
#  COMMANDS
# ═══════════════════════════════════════════════════════════════════════════════

def cmd_generate(args):
    """Generate new license key."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    
    spinner("Generating cryptographic license key", 1.5)
    
    key = db.generate_key(args.org, args.hours, args.issuer, args.notes or "")
    expires = datetime.now() + timedelta(hours=args.hours)
    
    if RICH:
        console.print()
        
        # Key box
        key_panel = Panel(
            f"[bold green]{key}[/bold green]",
            title="🔑 Generated License Key",
            border_style="green",
            box=HEAVY
        )
        console.print(key_panel)
        
        # Details
        table = Table(box=ROUNDED, border_style="yellow", show_header=False)
        table.add_column("Property", style="bold")
        table.add_column("Value")
        
        table.add_row("🏢 Organization", f"[bold]{args.org}[/bold]")
        table.add_row("👤 Issued By", args.issuer)
        table.add_row("⏱️  Valid For", f"{args.hours} hours ({args.hours//24} days)")
        table.add_row("📅 Expires", expires.strftime('%Y-%m-%d %H:%M:%S'))
        if args.notes:
            table.add_row("📝 Notes", args.notes)
        table.add_row("✅ Status", "[bold green]READY FOR ACTIVATION[/bold green]")
        
        console.print(table)
        console.print()
        console.print(Panel(
            "[bold yellow]⚠️  IMPORTANT[/bold yellow]\n\n"
            "• This key can only be used [bold]ONCE[/bold]\n"
            "• It will be bound to [bold]ONE DEVICE[/bold] upon first use\n"
            "• Store securely and share only with authorized personnel",
            border_style="yellow"
        ))
        console.print()
    else:
        print(f"\nGenerated Key: {key}")
        print(f"Organization: {args.org}")
        print(f"Expires: {expires}\n")
    
    return 0


def cmd_list(args):
    """List all licenses."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    spinner("Loading licenses", 0.8)
    
    licenses = db.get_all_licenses()
    
    if not licenses:
        warning("No licenses found in database")
        return 0
    
    if RICH:
        console.print()
        
        table = Table(title=f"📋 License Inventory ({len(licenses)} total)", box=ROUNDED, border_style="cyan")
        table.add_column("#", justify="right", style="dim")
        table.add_column("Key", max_width=20)
        table.add_column("Organization", style="bold")
        table.add_column("Status")
        table.add_column("Device Bound")
        table.add_column("Expires")
        table.add_column("Issued By")
        
        for i, lic in enumerate(licenses, 1):
            key_short = lic["key"][:16] + "..."
            
            # Status
            now = datetime.now()
            expires = datetime.fromisoformat(lic["expires_at"])
            
            if expires < now:
                status = "[red]EXPIRED[/red]"
            elif lic["is_used"]:
                status = "[yellow]ACTIVATED[/yellow]"
            else:
                status = "[green]AVAILABLE[/green]"
            
            # Device
            device = lic["device_fingerprint"][:12] + "..." if lic["device_fingerprint"] else "[dim]-[/dim]"
            
            table.add_row(
                str(i),
                f"[dim]{key_short}[/dim]",
                lic["organization"],
                status,
                device,
                expires.strftime('%Y-%m-%d'),
                lic["issued_by"] or "-"
            )
        
        console.print(table)
        console.print()
    else:
        for lic in licenses:
            status = "ACTIVATED" if lic["is_used"] else "AVAILABLE"
            print(f"{lic['key'][:20]}... | {lic['organization']} | {status}")
    
    return 0


def cmd_stats(args):
    """Show statistics."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    spinner("Loading statistics", 0.8)
    
    stats = db.get_stats()
    
    if RICH:
        console.print()
        
        # Stats panels
        from rich.columns import Columns
        
        panels = [
            Panel(f"[bold cyan]{stats['total']}[/bold cyan]\n[dim]Total Keys[/dim]", border_style="cyan"),
            Panel(f"[bold green]{stats['available']}[/bold green]\n[dim]Available[/dim]", border_style="green"),
            Panel(f"[bold yellow]{stats['activated']}[/bold yellow]\n[dim]Activated[/dim]", border_style="yellow"),
            Panel(f"[bold red]{stats['expired']}[/bold red]\n[dim]Expired[/dim]", border_style="red"),
        ]
        
        console.print(Columns(panels, equal=True))
        console.print()
        
        # Security stats
        sec_table = Table(title="🔒 Security Metrics", box=ROUNDED)
        sec_table.add_column("Metric", style="bold")
        sec_table.add_column("Value", justify="right")
        
        sec_table.add_row("Audit Log Entries", str(stats["audit_entries"]))
        sec_table.add_row("Failed Auth Attempts", f"[red]{stats['failed_attempts']}[/red]")
        sec_table.add_row("Database Path", str(Config.DB_PATH))
        
        console.print(sec_table)
        console.print()
    else:
        print(f"\nTotal: {stats['total']}, Available: {stats['available']}, Activated: {stats['activated']}, Expired: {stats['expired']}\n")
    
    return 0


def cmd_revoke(args):
    """Revoke a license key."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    
    if RICH:
        if not Confirm.ask(f"[bold red]Revoke key?[/bold red] {args.key[:20]}..."):
            warning("Revocation cancelled")
            return 0
    
    spinner("Revoking license key", 1.0)
    
    if db.revoke_key(args.key):
        success(f"License key revoked: {args.key[:20]}...")
        return 0
    else:
        error("License key not found")
        return 1


def cmd_audit(args):
    """Show audit trail."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    spinner("Loading audit trail", 0.8)
    
    entries = db.get_audit_trail(args.limit)
    
    if not entries:
        warning("No audit entries found")
        return 0
    
    if RICH:
        console.print()
        
        table = Table(title="📜 Authentication Audit Trail", box=ROUNDED, border_style="cyan")
        table.add_column("ID", justify="right", style="dim")
        table.add_column("Timestamp")
        table.add_column("Action")
        table.add_column("Status")
        table.add_column("Device", max_width=18)
        table.add_column("Error", max_width=20)
        
        for entry in entries:
            status_color = "green" if entry["status"] == "SUCCESS" else "red"
            table.add_row(
                str(entry["id"]),
                entry["timestamp"][:19] if entry["timestamp"] else "-",
                entry["action"],
                f"[{status_color}]{entry['status']}[/{status_color}]",
                entry["device"] or "-",
                entry["error"] or "-"
            )
        
        console.print(table)
        console.print()
    else:
        for e in entries:
            print(f"{e['id']} | {e['action']} | {e['status']}")
    
    return 0


def cmd_export(args):
    """Export licenses to CSV."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    spinner("Exporting licenses", 1.0)
    
    count = db.export_keys(args.file)
    success(f"Exported {count} licenses to {args.file}")
    return 0


def cmd_batch(args):
    """Generate multiple keys at once."""
    if RICH:
        console.print(MINI_BANNER)
    
    db = LicenseDB()
    
    if RICH:
        console.print()
        console.print(Panel(
            f"[bold]Batch Generation[/bold]\n\n"
            f"Organization: [cyan]{args.org}[/cyan]\n"
            f"Count: [cyan]{args.count}[/cyan]\n"
            f"Validity: [cyan]{args.hours} hours[/cyan]",
            title="📦 Batch Config",
            border_style="yellow"
        ))
        
        if not Confirm.ask("Proceed with batch generation?"):
            return 0
        
        console.print()
        
        keys = []
        with Progress() as progress:
            task = progress.add_task("Generating keys...", total=args.count)
            
            for i in range(args.count):
                key = db.generate_key(args.org, args.hours, args.issuer, f"Batch #{i+1}")
                keys.append(key)
                progress.update(task, advance=1)
        
        console.print()
        
        # Show generated keys
        table = Table(title=f"✅ Generated {args.count} Keys", box=ROUNDED)
        table.add_column("#", justify="right")
        table.add_column("License Key")
        
        for i, key in enumerate(keys, 1):
            table.add_row(str(i), f"[green]{key}[/green]")
        
        console.print(table)
        console.print()
        
        # Save to file
        if args.output:
            with open(args.output, 'w') as f:
                for key in keys:
                    f.write(key + "\n")
            success(f"Keys saved to {args.output}")
    else:
        for i in range(args.count):
            key = db.generate_key(args.org, args.hours, args.issuer, f"Batch #{i+1}")
            print(key)
    
    return 0


def cmd_version(args):
    """Show version."""
    if RICH:
        console.print(BANNER)
        console.print(Align.center("[bold white]v3.0.0[/bold white] • [dim]License Management Console[/dim]"))
        console.print(Align.center("[dim]Part of LogSentinel Pro Enterprise SIEM[/dim]"))
        console.print()
    else:
        print(f"\n{Config.APP_NAME} v{Config.VERSION}\n")
    return 0


def cmd_interactive(args):
    """Interactive admin mode."""
    if not RICH:
        print("Interactive mode requires 'rich' library")
        return 1
    
    console.print(BANNER)
    console.print(Align.center("[bold]Interactive Admin Console[/bold]"))
    console.print()
    
    db = LicenseDB()
    
    while True:
        console.print()
        choice = Prompt.ask(
            "[bold cyan]Admin>[/bold cyan]",
            choices=["generate", "list", "stats", "audit", "revoke", "export", "batch", "quit"],
            default="stats"
        )
        
        if choice == "quit":
            console.print("[dim]Goodbye![/dim]")
            break
        elif choice == "generate":
            org = Prompt.ask("Organization")
            hours = int(Prompt.ask("Hours", default="720"))
            key = db.generate_key(org, hours, "Admin Console", "")
            console.print(Panel(f"[green]{key}[/green]", title="🔑 New Key"))
        elif choice == "list":
            cmd_list(args)
        elif choice == "stats":
            cmd_stats(args)
        elif choice == "audit":
            cmd_audit(args)
        elif choice == "revoke":
            key = Prompt.ask("Key to revoke")
            if db.revoke_key(key):
                success("Key revoked")
            else:
                error("Key not found")
        elif choice == "export":
            filepath = Prompt.ask("Export file", default="licenses.csv")
            count = db.export_keys(filepath)
            success(f"Exported {count} keys")
        elif choice == "batch":
            org = Prompt.ask("Organization")
            count = int(Prompt.ask("Count", default="5"))
            hours = int(Prompt.ask("Hours", default="720"))
            for i in range(count):
                key = db.generate_key(org, hours, "Admin Console", f"Batch #{i+1}")
                console.print(f"  [green]{key}[/green]")
    
    return 0

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # ═══════════════════════════════════════════════════════════════════════════
    # ADMIN AUTHENTICATION GATE
    # ═══════════════════════════════════════════════════════════════════════════
    
    authenticated, admin_name = admin_auth_check()
    
    if not authenticated:
        return 1
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHENTICATED - Show admin interface
    # ═══════════════════════════════════════════════════════════════════════════
    
    if RICH:
        show_admin_status()
        console.print()
    
    parser = argparse.ArgumentParser(
        description="LogSentinel Admin - License Management Console",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  generate    Generate a new license key
  batch       Generate multiple keys at once
  list        List all licenses
  stats       Show license statistics
  audit       View audit trail
  revoke      Revoke a license key
  export      Export licenses to CSV
  interactive Interactive admin mode
  logout      End admin session
        """
    )
    
    subparsers = parser.add_subparsers(dest="command")
    
    # Generate
    gen = subparsers.add_parser("generate", aliases=["gen", "g"], help="Generate license key")
    gen.add_argument("-o", "--org", required=True, help="Organization name")
    gen.add_argument("-H", "--hours", type=int, default=720, help="Validity hours (default: 720)")
    gen.add_argument("-i", "--issuer", default=admin_name, help="Issuer name")
    gen.add_argument("-n", "--notes", help="Notes")
    gen.set_defaults(func=cmd_generate)
    
    # Batch
    batch = subparsers.add_parser("batch", aliases=["b"], help="Generate multiple keys")
    batch.add_argument("-o", "--org", required=True, help="Organization name")
    batch.add_argument("-c", "--count", type=int, required=True, help="Number of keys")
    batch.add_argument("-H", "--hours", type=int, default=720, help="Validity hours")
    batch.add_argument("-i", "--issuer", default=admin_name, help="Issuer")
    batch.add_argument("--output", help="Save keys to file")
    batch.set_defaults(func=cmd_batch)
    
    # List
    lst = subparsers.add_parser("list", aliases=["ls", "l"], help="List all licenses")
    lst.set_defaults(func=cmd_list)
    
    # Stats
    stats = subparsers.add_parser("stats", aliases=["s"], help="Show statistics")
    stats.set_defaults(func=cmd_stats)
    
    # Audit
    audit = subparsers.add_parser("audit", aliases=["a"], help="Show audit trail")
    audit.add_argument("-l", "--limit", type=int, default=50, help="Limit entries")
    audit.set_defaults(func=cmd_audit)
    
    # Revoke
    revoke = subparsers.add_parser("revoke", aliases=["r"], help="Revoke a license")
    revoke.add_argument("-k", "--key", required=True, help="License key to revoke")
    revoke.set_defaults(func=cmd_revoke)
    
    # Export
    export = subparsers.add_parser("export", aliases=["e"], help="Export licenses to CSV")
    export.add_argument("-f", "--file", default="licenses.csv", help="Output file")
    export.set_defaults(func=cmd_export)
    
    # Interactive
    interactive = subparsers.add_parser("interactive", aliases=["i"], help="Interactive mode")
    interactive.set_defaults(func=cmd_interactive)
    
    # Version
    version = subparsers.add_parser("version", aliases=["v"], help="Show version")
    version.set_defaults(func=cmd_version)
    
    # Logout
    logout_cmd = subparsers.add_parser("logout", help="End admin session")
    logout_cmd.set_defaults(func=cmd_logout)
    
    args = parser.parse_args()
    
    if not args.command:
        # Enter interactive admin mode
        return interactive_admin_shell(admin_name)
    
    return args.func(args)


def interactive_admin_shell(admin_name: str):
    """Interactive admin command shell."""
    if not RICH:
        print(f"\nLogSentinel Admin Console - Logged in as: {admin_name}")
        print("Type 'help' for commands, 'exit' to quit\n")
    
    db = LicenseDB()
    
    while True:
        try:
            if RICH:
                console.print()
                show_admin_status()
                console.print()
                
                # Show admin menu
                console.print(Panel(
                    "[bold white]╔═══════════════════════════════════════════════════════╗[/bold white]\n"
                    "[bold white]║[/bold white]           [bold red]ADMIN COMMAND CENTER[/bold red]                     [bold white]║[/bold white]\n"
                    "[bold white]╠═══════════════════════════════════════════════════════╣[/bold white]\n"
                    "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]generate[/cyan] ORG          [dim]Create license key[/dim]     [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]batch[/cyan] ORG COUNT      [dim]Batch generate keys[/dim]    [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]list[/cyan]                 [dim]Show all licenses[/dim]      [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]stats[/cyan]                [dim]License statistics[/dim]     [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]audit[/cyan]                [dim]View audit trail[/dim]       [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]revoke[/cyan] KEY           [dim]Revoke a license[/dim]       [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]export[/cyan] [FILE]        [dim]Export to CSV[/dim]          [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold yellow]▸[/bold yellow] [cyan]help[/cyan]                 [dim]Show help[/dim]              [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]  [bold red]▸[/bold red] [yellow]logout[/yellow]               [dim]End admin session[/dim]      [bold white]║[/bold white]\n"
                    "[bold white]║[/bold white]                                                       [bold white]║[/bold white]\n"
                    "[bold white]╚═══════════════════════════════════════════════════════╝[/bold white]",
                    title="🔐 LogSentinel Admin", border_style="red", box=DOUBLE
                ))
                
                command = console.input("\n[bold red]Admin>[/bold red] ").strip()
            else:
                command = input(f"Admin ({admin_name})> ").strip()
            
            if not command:
                continue
            
            # Parse command
            cmd_parts = command.split()
            cmd = cmd_parts[0].lower()
            
            if cmd in ['exit', 'quit', 'logout']:
                if RICH:
                    console.print(Panel(
                        "[bold green]Admin session ended[/bold green]\n\n[dim]Goodbye![/dim]",
                        title="👋 Logged Out", border_style="green"
                    ))
                else:
                    print("Admin session ended. Goodbye!")
                # Clear session and exit
                if Config.ADMIN_SESSION.exists():
                    Config.ADMIN_SESSION.unlink()
                return 0
            
            elif cmd == 'help':
                if RICH:
                    console.print()
                    console.print(Panel(
                        "[bold]Available Commands:[/bold]\n\n"
                        "  [cyan]generate[/cyan] ORG [hours]         Generate single license key\n"
                        "  [cyan]batch[/cyan] ORG COUNT [hours]     Generate multiple keys\n"
                        "  [cyan]list[/cyan]                        Show all licenses\n"
                        "  [cyan]stats[/cyan]                       License statistics\n"
                        "  [cyan]audit[/cyan] [limit]              View audit trail\n"
                        "  [cyan]revoke[/cyan] KEY                 Revoke a license key\n"
                        "  [cyan]export[/cyan] [filename]          Export to CSV\n"
                        "  [cyan]help[/cyan]                        Show this help\n"
                        "  [cyan]logout[/cyan]                      End admin session\n\n"
                        "[dim]Examples:[/dim]\n"
                        "  generate \"Acme Corp\" 720\n"
                        "  batch \"Test Corp\" 5 168\n"
                        "  revoke ab09b0e5d2805dca...",
                        title="📋 Admin Help", border_style="blue"
                    ))
                else:
                    print("\nCommands: generate, batch, list, stats, audit, revoke, export, help, logout\n")
                continue
            
            # Execute commands
            try:
                if cmd == 'generate':
                    if len(cmd_parts) < 2:
                        error("Usage: generate ORG [hours]")
                        continue
                    org = cmd_parts[1]
                    hours = int(cmd_parts[2]) if len(cmd_parts) > 2 else 720
                    
                    spinner("Generating key", 0.5)
                    key = db.generate_key(org, hours, admin_name, "Interactive console")
                    
                    if RICH:
                        console.print(Panel(f"[green]{key}[/green]", title="🔑 New License Key"))
                    else:
                        print(f"Generated: {key}")
                
                elif cmd == 'batch':
                    if len(cmd_parts) < 3:
                        error("Usage: batch ORG COUNT [hours]")
                        continue
                    org = cmd_parts[1]
                    count = int(cmd_parts[2])
                    hours = int(cmd_parts[3]) if len(cmd_parts) > 3 else 720
                    
                    if RICH:
                        keys = []
                        with Progress() as progress:
                            task = progress.add_task("Generating keys...", total=count)
                            for i in range(count):
                                key = db.generate_key(org, hours, admin_name, f"Batch #{i+1}")
                                keys.append(key)
                                progress.update(task, advance=1)
                        
                        table = Table(title=f"✅ Generated {count} Keys")
                        table.add_column("#", justify="right")
                        table.add_column("License Key")
                        for i, key in enumerate(keys, 1):
                            table.add_row(str(i), f"[green]{key}[/green]")
                        console.print(table)
                    else:
                        for i in range(count):
                            key = db.generate_key(org, hours, admin_name, f"Batch #{i+1}")
                            print(f"{i+1}: {key}")
                
                elif cmd == 'list':
                    cmd_list_interactive()
                
                elif cmd == 'stats':
                    cmd_stats_interactive()
                
                elif cmd == 'audit':
                    limit = int(cmd_parts[1]) if len(cmd_parts) > 1 else 20
                    cmd_audit_interactive(limit)
                
                elif cmd == 'revoke':
                    if len(cmd_parts) < 2:
                        error("Usage: revoke KEY")
                        continue
                    key = cmd_parts[1]
                    if db.revoke_key(key):
                        success(f"Key revoked: {key[:16]}...")
                    else:
                        error("Key not found")
                
                elif cmd == 'export':
                    filename = cmd_parts[1] if len(cmd_parts) > 1 else "licenses.csv"
                    spinner("Exporting licenses", 0.5)
                    count = db.export_keys(filename)
                    success(f"Exported {count} licenses to {filename}")
                
                else:
                    if RICH:
                        console.print(f"[red]Unknown command: {cmd}[/red]")
                    else:
                        print(f"Unknown command: {cmd}")
            
            except ValueError as e:
                error(f"Invalid input: {str(e)}")
            except Exception as e:
                error(f"Error: {str(e)}")
        
        except (KeyboardInterrupt, EOFError):
            if RICH:
                console.print("\n[dim]Admin session ended.[/dim]")
            else:
                print("\nAdmin session ended.")
            # Clear session and exit
            if Config.ADMIN_SESSION.exists():
                Config.ADMIN_SESSION.unlink()
            return 0


def cmd_list_interactive():
    """Interactive list command."""
    db = LicenseDB()
    licenses = db.get_all_licenses()
    
    if RICH:
        table = Table(title=f"📋 License Inventory ({len(licenses)} total)", box=ROUNDED)
        table.add_column("#", justify="right", width=3)
        table.add_column("Key", max_width=20)
        table.add_column("Organization", max_width=15)
        table.add_column("Status", width=9)
        table.add_column("Device Bound", max_width=16)
        table.add_column("Expires", width=10)
        table.add_column("Issued By", max_width=15)
        
        for i, lic in enumerate(licenses, 1):
            status = "[green]ACTIVATED[/green]" if lic["is_used"] else "[yellow]AVAILABLE[/yellow]"
            device = lic["device_fingerprint"][:16] + "..." if lic["device_fingerprint"] else "-"
            expires = datetime.fromisoformat(lic["expires_at"]).strftime("%Y-%m-%d") if lic["expires_at"] else "-"
            
            table.add_row(
                str(i), lic["key"][:20] + "...", lic["organization"] or "-",
                status, device, expires, lic["issued_by"] or "-"
            )
        
        console.print(table)
    else:
        for i, lic in enumerate(licenses, 1):
            status = "ACTIVATED" if lic["is_used"] else "AVAILABLE"
            print(f"{i}: {lic['key'][:32]}... | {lic['organization']} | {status}")


def cmd_stats_interactive():
    """Interactive stats command."""
    db = LicenseDB()
    stats = db.get_stats()
    
    if RICH:
        table = Table(title="📊 License Statistics", box=DOUBLE, border_style="yellow")
        table.add_column("Metric", style="bold")
        table.add_column("Count", justify="right", style="cyan")
        table.add_row("Total Licenses", str(stats["total"]))
        table.add_row("Available", str(stats["available"]))
        table.add_row("Activated", str(stats["activated"]))
        table.add_row("Expired", str(stats["expired"]))
        table.add_row("Audit Entries", str(stats["audit_entries"]))
        console.print(table)
    else:
        print(f"Total: {stats['total']}, Available: {stats['available']}, Activated: {stats['activated']}")


def cmd_audit_interactive(limit: int):
    """Interactive audit command."""
    db = LicenseDB()
    entries = db.get_audit_trail(limit)
    
    if RICH and entries:
        table = Table(title=f"🔍 Audit Trail (Last {len(entries)} entries)", box=ROUNDED)
        table.add_column("ID", width=4)
        table.add_column("Time", width=19)
        table.add_column("Action", width=12)
        table.add_column("Status", width=7)
        table.add_column("Device", max_width=18)
        
        for entry in entries:
            status_color = "green" if entry["status"] == "SUCCESS" else "red"
            table.add_row(
                str(entry["id"]),
                entry["timestamp"][:19] if entry["timestamp"] else "-",
                entry["action"],
                f"[{status_color}]{entry['status']}[/{status_color}]",
                entry["device"][:16] + "..." if entry["device"] else "-"
            )
        
        console.print(table)
    else:
        for e in entries:
            print(f"{e['id']} | {e['action']} | {e['status']}")


def cmd_logout(args):
    """End admin session."""
    if RICH:
        console.print(MINI_BANNER)
    
    if Config.ADMIN_SESSION.exists():
        Config.ADMIN_SESSION.unlink()
        if RICH:
            console.print(Panel(
                "[bold green]Session ended[/bold green]\n\n"
                "[dim]You have been logged out of the admin console.[/dim]",
                title="👋 Logged Out", border_style="green"
            ))
        else:
            print("✅ Logged out")
    else:
        if RICH:
            console.print(Panel("[dim]No active session[/dim]", title="ℹ️ Info", border_style="blue"))
        else:
            print("No active session")
    return 0


if __name__ == "__main__":
    sys.exit(main())
