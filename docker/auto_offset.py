
    
  
#!/usr/bin/env python3
"""Find PHP symbol RVAs from the Apache module or PHP-FPM executable in Docker.

Requires Docker on the host and /bin/sh in the target container.
Only ELF64 little-endian binaries with available ELF symbol information are supported.
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONTAINER = "php2shell-target"
DEFAULT_OUTPUT = os.path.join(os.path.dirname(HERE), "out", "offsets.env")

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1
SHN_UNDEF = 0
WANTED = ("zif_system", "zval_ptr_dtor")

# Probe what is *running*, not just what happens to be installed.
# /proc/*/maps identifies a mod_php-loaded Apache process; /proc/*/exe
# identifies a PHP-FPM process (including version-suffixed executables).
PROBE_RUNNING = r'''
for proc in /proc/[0-9]*; do
    [ -r "$proc/maps" ] || continue
    while IFS= read -r line; do
        case "$line" in
            *"/libphp"*.so*)
                rest=${line#* /}
                module=/${rest%% *}
                case "$module" in
                    */libphp*.so*)
                        printf 'apache\t%s\n' "$module"
                        break
                        ;;
                esac
                ;;
        esac
    done < "$proc/maps"
done
for proc in /proc/[0-9]*; do
    executable=$(readlink "$proc/exe" 2>/dev/null) || continue
    case "${executable##*/}" in
        php-fpm*) printf 'fpm\t%s\n' "$executable" ;;
    esac
done
exit 0
'''

# For a stopped service/container with an interactive shell, installed
# candidates provide a best-effort fallback. A busy service is preferred.
PROBE_INSTALLED = r'''
for file in \
    /usr/lib/apache2/modules/libphp*.so \
    /usr/local/apache2/modules/libphp*.so \
    /usr/local/lib/apache2/modules/libphp*.so; do
    [ -f "$file" ] && printf 'apache\t%s\n' "$file"
done
for file in \
    /usr/sbin/php-fpm* \
    /usr/local/sbin/php-fpm* \
    /usr/local/bin/php-fpm*; do
    [ -f "$file" ] && [ -x "$file" ] && printf 'fpm\t%s\n' "$file"
done
exit 0
'''


def docker_exec(container: str, script: str) -> str:
    try:
        result = subprocess.run(
            ["docker", "exec", container, "sh", "-c", script],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Docker not found in PATH") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Docker exec failed for {container!r}: {exc.stderr.strip()}"
        ) from exc
    return result.stdout


def parse_candidates(output: str) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []

