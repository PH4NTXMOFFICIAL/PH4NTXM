#!/usr/bin/env python3
"""Event-filter regression; never reaches DHCP mutation or reads session secrets."""
from pathlib import Path
import subprocess

dispatcher = Path(__file__).resolve().parents[5] / 'etc/NetworkManager/dispatcher.d/30-ph4ntxm-dhcp'
cases = [
    (['', 'connectivity-change'], 0),
    (['', 'dns-change'], 0),
    (['none', 'hostname'], 0),
    (['', 'hostname'], 0),
    (['missing-device', 'down'], 0),
    (['', 'up'], 1),
    (['', 'dhcp4-change'], 1),
    (['../bad', 'up'], 1),
    ([], 1),
]
for args, expected in cases:
    completed = subprocess.run(['bash', str(dispatcher), *args], capture_output=True, timeout=3)
    assert completed.returncode == expected, (args, completed.returncode, expected, completed.stderr)
print(f'dhcp-dispatcher event filtering: {len(cases)} cases PASS')
