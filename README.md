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

## Logging

Write only the findings (nuclei's matched results) to a file with `--log`:

```
php2shell-scanner --domain example.com --log findings.txt
```

Progress and status output still goes to the terminal; only matched results are written to the log file. Parent directories are created if needed.
