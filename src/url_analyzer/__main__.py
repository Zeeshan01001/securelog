#!/usr/bin/env python3
"""
SecureLog - Command Line Interface

Enterprise-grade security analysis tool for OWASP Top 10 vulnerability detection
in web access logs with advanced security features.
"""

import sys
import logging
import argparse
from pathlib import Path
from typing import Optional
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich.align import Align
from rich import box
import pyfiglet

from .core.analyzer import AdvancedLogAnalyzer, analyze_log_file
from .utils.parsers import LogParser
from .utils.exporters import ReportExporter


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('url_analyzer.log')
        ]
    )


def print_banner() -> None:
    """Print the SECURELOG banner with GEMINI-style retro colors."""
    console = Console()
    
    # Print retro computer boot-style header
    console.print("[dim bright_green]> SYSTEM INITIALIZING...[/dim bright_green]")
    console.print("[dim bright_green]> LOADING SECURITY PROTOCOLS...[/dim bright_green]")
    console.print("[dim bright_green]> ACTIVATING THREAT DETECTION...[/dim bright_green]")
    console.print()
    
    # Create GEMINI-style ASCII art banner with authentic retro colors
    banner = Text()
    banner.append("███████ ███████  ██████ ██    ██ ██████  ███████ ██       ██████   ██████\n", style="bold bright_magenta")
    banner.append("██      ██      ██      ██    ██ ██   ██ ██      ██      ██    ██ ██     \n", style="bold bright_cyan")
    banner.append("███████ █████   ██      ██    ██ ██████  █████   ██      ██    ██ ██   ██\n", style="bold bright_yellow") 
    banner.append("     ██ ██      ██      ██    ██ ██   ██ ██      ██      ██    ██ ██   ██\n", style="bold bright_green")
    banner.append("███████ ███████  ██████  ██████  ██   ██ ███████ ███████  ██████   ██████", style="bold bright_blue")
    
    # Add retro computer-style info lines
    info_line = Text("\n──────────────────────────────────────────────────────────────────", style="bright_white")
    subtitle = Text("\nENTERPRISE-GRADE SECURITY ANALYSIS TOOL", style="bold bright_white")
    specs = Text("\n[ VERSION 2.0.0 ] [ OWASP TOP 10 ] [ REAL-TIME MONITORING ]", style="dim bright_green")
    status = Text("\n[ STATUS: READY ] [ THREAT LEVEL: SCANNING ] [ MODE: ACTIVE ]", style="dim bright_cyan")
    
    # Create panel with authentic retro computer styling
    panel = Panel(
        Align.center(banner + info_line + subtitle + specs + status),
        border_style="bright_cyan",
        box=box.DOUBLE,
        padding=(1, 2),
        title="[bold bright_yellow]◄◄◄ SECURELOG ONLINE ►►►[/bold bright_yellow]"
    )
    
    console.print(panel)
    console.print("[dim bright_green]> SYSTEM READY FOR SECURITY ANALYSIS[/dim bright_green]")
    console.print()


def print_security_notice() -> None:
    """Print security notice with retro styling."""
    console = Console()
    
    notice_text = Text()
    notice_text.append("🔒 SECURITY NOTICE\n\n", style="bold bright_yellow")
    notice_text.append("This tool is designed for authorized security testing and analysis only.\n", style="bright_white")
    notice_text.append("Always obtain proper authorization before testing any systems or applications.\n", style="bright_white")
    notice_text.append("Unauthorized testing may be illegal and could result in legal consequences.", style="bright_white")
    
    panel = Panel(
        notice_text,
        border_style="bright_yellow",
        box=box.ROUNDED,
        padding=(1, 2),
        title="⚠️  WARNING"
    )
    
    console.print(panel)
    console.print()


def print_analysis_results(results: dict, log_file: str) -> None:
    """Print analysis results with retro styling."""
    console = Console()
    
    # Create results table
    table = Table(title="🔍 Security Analysis Results", box=box.ROUNDED)
    table.add_column("Metric", style="bright_cyan", no_wrap=True)
    table.add_column("Value", style="bright_white")
    table.add_column("Status", style="bold")
    
    # Add data to table
    total_entries = results.get('total_entries', 0)
    vulnerabilities = results.get('total_findings', 0)
    risk_score = results.get('risk_score', 0)
    
    # Determine status colors with retro palette
    if vulnerabilities == 0:
        vuln_status = "✅ CLEAN"
        vuln_style = "bold bright_green"
    elif vulnerabilities < 5:
        vuln_status = "⚠️  LOW RISK"
        vuln_style = "bold bright_yellow"
    elif vulnerabilities < 10:
        vuln_status = "🚨 MEDIUM RISK"
        vuln_style = "bold bright_magenta"
    else:
        vuln_status = "🔥 HIGH RISK"
        vuln_style = "bold bright_red"
    
    if risk_score < 30:
        risk_status = "✅ LOW"
        risk_style = "bold bright_green"
    elif risk_score < 70:
        risk_status = "⚠️  MEDIUM"
        risk_style = "bold bright_yellow"
    else:
        risk_status = "🔥 HIGH"
        risk_style = "bold bright_red"
    
    table.add_row("📁 Log File", log_file, "📋")
    table.add_row("📊 Total Entries", str(total_entries), "📈")
    table.add_row("🛡️ Vulnerabilities Found", str(vulnerabilities), vuln_status, style=vuln_style)
    table.add_row("🎯 Risk Score", f"{risk_score}/100", risk_status, style=risk_style)
    
    console.print(table)
    console.print()
    
    # Print executive summary
    if 'executive_summary' in results:
        summary = results['executive_summary']
        summary_panel = Panel(
            Text(summary, style="bright_white"),
            title="📋 Executive Summary",
            border_style="bright_cyan",
            box=box.ROUNDED
        )
        console.print(summary_panel)
        console.print()


def print_progress(message: str) -> None:
    """Print progress message with spinner."""
    console = Console()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task(message, total=None)
        progress.update(task, advance=0)


def main() -> int:
    """Main CLI entry point."""
    # Print banner and security notice
    print_banner()
    print_security_notice()
    
    parser = argparse.ArgumentParser(
        description="SecureLog - OWASP Top 10 Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze a single log file
  python -m url_analyzer analyze logs/access.log

  # Real-time streaming analysis
  python -m url_analyzer stream --source /var/log/nginx/access.log

  # Batch analysis with custom output
  python -m url_analyzer batch logs/ --output report.pdf

  # Generate compliance report
  python -m url_analyzer compliance --standard PCI-DSS

Security Notice:
  This tool is designed for authorized security testing and analysis only.
  Always obtain proper authorization before testing any systems or applications.
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log file for vulnerabilities')
    analyze_parser.add_argument('log_file', help='Path to log file to analyze')
    analyze_parser.add_argument('--output', '-o', default='json', 
                               choices=['json', 'csv', 'html', 'pdf'],
                               help='Output format (default: json)')
    analyze_parser.add_argument('--verbose', '-v', action='store_true',
                               help='Enable verbose logging')
    
    # Stream command
    stream_parser = subparsers.add_parser('stream', help='Real-time streaming analysis')
    stream_parser.add_argument('--source', '-s', required=True,
                              help='Source for streaming logs (file path or URL)')
    stream_parser.add_argument('--output', '-o', default='console',
                              help='Output destination (default: console)')
    stream_parser.add_argument('--verbose', '-v', action='store_true',
                              help='Enable verbose logging')
    
    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Batch analysis of multiple files')
    batch_parser.add_argument('directory', help='Directory containing log files')
    batch_parser.add_argument('--output', '-o', default='json',
                             help='Output format (default: json)')
    batch_parser.add_argument('--pattern', '-p', default='*.log',
                             help='File pattern to match (default: *.log)')
    batch_parser.add_argument('--verbose', '-v', action='store_true',
                             help='Enable verbose logging')
    
    # Compliance command
    compliance_parser = subparsers.add_parser('compliance', help='Generate compliance reports')
    compliance_parser.add_argument('--standard', '-s', required=True,
                                  choices=['PCI-DSS', 'SOX', 'GDPR', 'HIPAA', 'ISO27001'],
                                  help='Compliance standard')
    compliance_parser.add_argument('--input', '-i', required=True,
                                  help='Input analysis results file')
    compliance_parser.add_argument('--output', '-o', required=True,
                                  help='Output compliance report file')
    compliance_parser.add_argument('--verbose', '-v', action='store_true',
                                  help='Enable verbose logging')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--init', action='store_true',
                              help='Initialize secure configuration')
    config_parser.add_argument('--validate', action='store_true',
                              help='Validate current configuration')
    config_parser.add_argument('--verbose', '-v', action='store_true',
                              help='Enable verbose logging')
    
    # Global options
    parser.add_argument('--version', action='version', version='%(prog)s 2.0.0')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    

    
    try:
        if args.command == 'analyze':
            return handle_analyze(args)
        elif args.command == 'stream':
            return handle_stream(args)
        elif args.command == 'batch':
            return handle_batch(args)
        elif args.command == 'compliance':
            return handle_compliance(args)
        elif args.command == 'config':
            return handle_config(args)
        else:
            parser.print_help()
            return 1
            
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1


def handle_analyze(args) -> int:
    """Handle analyze command."""
    logger = logging.getLogger(__name__)
    console = Console()
    
    log_file = Path(args.log_file)
    if not log_file.exists():
        console.print(f"[bold bright_red]❌ Error:[/bold bright_red] Log file not found: {log_file}")
        return 1
    
    # Show progress
    print_progress("🔍 Initializing security analyzers...")
    
    try:
        # Use convenience function for quick analysis
        print_progress("📊 Analyzing log entries for vulnerabilities...")
        report = analyze_log_file(str(log_file), args.output)
        
        # Prepare results for retro display
        results = {
            'total_entries': report.total_entries,
            'total_findings': report.vulnerability_findings['total_findings'],
            'risk_score': report.overall_risk_score,
            'executive_summary': report.executive_summary
        }
        
        # Print retro results
        print_analysis_results(results, str(log_file))
        
        return 0
        
    except Exception as e:
        console.print(f"[bold bright_red]❌ Analysis failed:[/bold bright_red] {e}")
        return 1


def handle_stream(args) -> int:
    """Handle stream command."""
    logger = logging.getLogger(__name__)
    
    logger.info(f"Starting real-time analysis from {args.source}")
    
    try:
        analyzer = AdvancedLogAnalyzer()
        
        # Create log stream
        if Path(args.source).exists():
            # File-based streaming
            with open(args.source, 'r') as f:
                log_stream = iter(f)
                import asyncio
                asyncio.run(analyzer.analyze_real_time_stream(log_stream))
        else:
            logger.error(f"Source not found: {args.source}")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Streaming analysis failed: {e}")
        return 1


def handle_batch(args) -> int:
    """Handle batch command."""
    logger = logging.getLogger(__name__)
    
    directory = Path(args.directory)
    if not directory.exists() or not directory.is_dir():
        logger.error(f"Directory not found: {directory}")
        return 1
    
    log_files = list(directory.glob(args.pattern))
    if not log_files:
        logger.error(f"No log files found matching pattern: {args.pattern}")
        return 1
    
    logger.info(f"Found {len(log_files)} log files for batch analysis")
    
    try:
        analyzer = AdvancedLogAnalyzer()
        all_results = []
        
        for log_file in log_files:
            logger.info(f"Analyzing {log_file}")
            try:
                result = analyzer.analyze_log_file(str(log_file), args.output)
                all_results.append(result)
            except Exception as e:
                logger.warning(f"Failed to analyze {log_file}: {e}")
                continue
        
        # Generate batch report
        if all_results:
            logger.info(f"Batch analysis completed. Processed {len(all_results)} files")
            # TODO: Implement batch report generation
        else:
            logger.error("No files were successfully analyzed")
            return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Batch analysis failed: {e}")
        return 1


def handle_compliance(args) -> int:
    """Handle compliance command."""
    logger = logging.getLogger(__name__)
    
    logger.info(f"Generating {args.standard} compliance report")
    
    try:
        # TODO: Implement compliance report generation
        logger.info("Compliance report generation not yet implemented")
        return 0
        
    except Exception as e:
        logger.error(f"Compliance report generation failed: {e}")
        return 1


def handle_config(args) -> int:
    """Handle config command."""
    logger = logging.getLogger(__name__)
    
    if args.init:
        logger.info("Initializing secure configuration")
        # TODO: Implement configuration initialization
        return 0
    elif args.validate:
        logger.info("Validating configuration")
        # TODO: Implement configuration validation
        return 0
    else:
        logger.error("No configuration action specified")
        return 1


if __name__ == '__main__':
    import asyncio
    sys.exit(main())
