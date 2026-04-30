#!/usr/bin/env python3
import json
import subprocess
import sys
import click
import requests  # For API checks later

with open('rules.json') as f:
    RULES = json.load(f)

@click.command()
@click.argument('target')
@click.option('--format', default='json')
def scan(target):
    issues = []
    
    # SIP scan
    try:
        result = subprocess.run(['svmap', target], capture_output=True, text=True, timeout=30)
        if "200 OK" in result.stdout:
            issues.append(RULES["exposed_extensions"])
    except:
        pass
    
    # Ping/jitter (one-way/choppy proxy)
    result = subprocess.run(['ping', '-c', '5', target], capture_output=True, text=True)
    if "packet loss" in result.stdout.lower():
        issues.append(RULES["choppy_audio"])
    
    # Output
    if issues:
        click.secho("🚨 ISSUES FOUND:", fg='red')
        for issue in issues:
            click.secho(f"  {issue['cause']}", fg='yellow')
            click.secho(f"  Fix: {issue['fix']}", fg='green')
    else:
        click.secho("✅ All clear!", fg='green')
    
    return json.dumps(issues, indent=2)

if __name__ == '__main__':
    scan()
