#!/usr/bin/env python3
"""
Tool for scanning files privately using VirusTotal API.
Supports code insight analysis and waiting for scan completion.
"""

import sys
import asyncio
import argparse
from pathlib import Path
import vt
from rich.console import Console
from rich.progress import Progress

console = Console()

async def scan_file_private(
    api_key: str,
    file_path: Path,
    code_insight: bool = False,
    wait: bool = False
) -> None:
    """
    Scan a file privately on VirusTotal.
    
    Args:
        api_key: VirusTotal API key
        file_path: Path to file to scan
        code_insight: Enable code analysis
        wait: Wait for scan completion
    """
    async with vt.Client(api_key) as client:
        try:
            with Progress() as progress:
                task = progress.add_task(
                    "Scanning file...",
                    total=None if wait else 1
                )
                
                analysis = await client.scan_file_private_async(
                    str(file_path),
                    code_insight=code_insight,
                    wait_for_completion=wait
                )
                
                progress.update(task, advance=1)
                
                console.print("\n[green]Scan submitted successfully[/green]")
                console.print(f"Analysis ID: {analysis.id}")
                
                if wait:
                    console.print(f"\nScan Status: {analysis.status}")
                    if hasattr(analysis, 'stats'):
                        console.print("Detection Stats:")
                        for k, v in analysis.stats.items():
                            console.print(f"  {k}: {v}")
                
        except vt.error.APIError as e:
            console.print(f"[red]API Error: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

def main():
    parser = argparse.ArgumentParser(
        description="Scan file privately using VirusTotal API"
    )
    parser.add_argument("apikey", help="VirusTotal API key")
    parser.add_argument("file_path", help="Path to file to scan")
    parser.add_argument(
        "--code-insight",
        action="store_true",
        help="Enable code analysis features"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for scan completion"
    )
    
    args = parser.parse_args()
    file_path = Path(args.file_path)

    if not file_path.exists():
        console.print(f"[red]Error: File {file_path} not found[/red]")
        sys.exit(1)
        
    if not file_path.is_file():
        console.print(f"[red]Error: {file_path} is not a file[/red]")
        sys.exit(1)

    asyncio.run(scan_file_private(
        args.apikey,
        file_path,
        args.code_insight,
        args.wait
    ))

if __name__ == "__main__":
    main()