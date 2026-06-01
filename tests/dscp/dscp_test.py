#!/usr/bin/env python3

# (C) 2026 by sysmocom s.f.m.c. GmbH
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import subprocess
import time
import os
import sys
from pathlib import Path

# Pfade definieren
SCRIPT_DIR = Path(__file__).parent.resolve()
STP_BINARY = SCRIPT_DIR / ".." / ".." / "stp" / "osmo-stp"
CONFIG_FILE = SCRIPT_DIR / "osmo-stp-dscp.cfg"
DIAG_BINARY = SCRIPT_DIR / "get_tos_diag"


def main():
    print(f"starting osmo-stp")

    # 1. osmo-stp im Hintergrund starten
    try:
        proc = subprocess.Popen(
            [STP_BINARY, "-c", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        print("File not found")
        sys.exit(1)

    # wait to establish socket connection
    time.sleep(1.0)

    # check process
    if proc.poll() is not None:
        print("Process failed")
        stdout, stderr = proc.communicate()
        print(f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}", file=sys.stderr)
        sys.exit(1)

    print("started osmo-stp")

    subprocess.run([DIAG_BINARY], check=True)

    print("stopping osmo-stp")
    proc.terminate()

    try:
        proc.wait(timeout=5)
        print("stopped osmo-stp")
    except subprocess.TimeoutExpired:
        print("failed to stop, killing...")
        proc.kill()

if __name__ == "__main__":
    main()
