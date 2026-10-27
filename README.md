# CTF Tools

A collection of small Python utilities for authorized security labs and CTF
practice. Each tool is a standalone script; the collection currently includes a
hash-format identifier and a local reconnaissance report tool.

## Hash format identifier

Suggests likely formats for common hexadecimal digests and identifies several
well-known encoded hash prefixes:

```powershell
python hash_identifier.py "d41d8cd98f00b204e9800998ecf8427e"
```

The output lists possibilities, not a definitive identification: different
algorithms can share lengths, and salts or encodings can make identification
ambiguous. This tool only identifies likely formats; it does not decode or crack
hashes.

## Local reconnaissance report

The `recon_cli.py` tool parses Nmap XML and Gobuster text into a readable,
defensive triage report. It can optionally run a limited Nmap service scan against
**localhost only**.

> **Safety boundary:** active scans are restricted to loopback addresses. The
> tool is intended for your own machine and local labs, not remote hosts. Only
> scan systems and data you are authorized to assess.

It summarizes open services and discovered web paths, and adds rule-based
defensive review notes, such as reachable SMB or an SSH banner that may indicate
an older OpenSSH release. It is a triage helper, **not** a vulnerability scanner.
Banner-based hints can be incomplete or inaccurate; verify findings against the
software vendor and your configuration. It does not attempt exploitation or run
Gobuster.

## Requirements

- Python 3.10 or newer
- Nmap 7.80 or newer for active scans only

On Windows, install Nmap if you want to use active local scans:

```powershell
winget install --id Insecure.Nmap --exact
```

The CLI checks `PATH` and the standard Windows Nmap install locations. Parsing
existing files does not require Nmap.

## Quick start

From the project directory, scan the local machine using the default target and
port list:

```powershell
python recon_cli.py --scan --confirm-local-scan --format text
```

The default target is `127.0.0.1`. The default ports are:

```text
21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,
1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017
```

Active scanning requires both `--scan` and `--confirm-local-scan`. Override the
ports with a comma-separated list of explicit port numbers (maximum 128):

```powershell
python recon_cli.py --scan --target 127.0.0.1 --ports 22,80,8080 --confirm-local-scan
```

Targets must resolve exclusively to loopback addresses. The scan uses Nmap
service/version detection with a light probe profile; it does not test whether
services are exploitable.

### Try a temporary local service

In one PowerShell window, start a temporary web server bound to loopback:

```powershell
python -m http.server 8080 --bind 127.0.0.1
```

In another window, check that port:

```powershell
python recon_cli.py --scan --ports 8080 --confirm-local-scan
```

Stop the server with `Ctrl+C` and repeat the scan to confirm the port is no
longer open.

### Parse existing files

Parsing does not run any network scan:

```powershell
python recon_cli.py --nmap-xml scan.xml --gobuster gobuster.txt
```

Choose JSON output or write both report formats to files:

```powershell
python recon_cli.py --nmap-xml scan.xml --format json --output report.json
python recon_cli.py --nmap-xml scan.xml --gobuster gobuster.txt --format both --output report
```

The `both` example creates `report.txt` and `report.json`. Input options can be
repeated to combine multiple files.

## Tests

The test suite uses Python's standard library; no extra packages are required:

```powershell
python -m unittest discover -s tests -v
```
