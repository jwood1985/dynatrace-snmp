#!/usr/bin/env python3
"""
Dynatrace SNMP Extension Generator
===================================
Reads a single-column CSV of OIDs and produces:

  <output-dir>/
    extension.yaml        – Dynatrace Extensions 2.0 SNMP definition
    certs/
      ca.key / ca.crt     – self-signed developer CA (upload ca.crt to Dynatrace)
      extension.key       – extension signing key
      extension.csr       – certificate signing request (intermediate artefact)
      extension.crt       – extension cert signed by the CA
    extension.zip         – packaged extension (contains extension.yaml)
    extension.zip.sig     – CMS/DER signature of the zip  (unless --no-sign)

Metric keys follow the pattern  ext:hostSnmp<N>  (0-indexed).

Requirements
------------
  • Python 3.9+
  • OpenSSL CLI on PATH  (for cert generation and signing)

Usage examples
--------------
  python generate_snmp_extension.py oids.csv
  python generate_snmp_extension.py oids.csv -o ./my-ext -n custom:my-snmp -a "Acme Corp"
  python generate_snmp_extension.py oids.csv --skip-certs     # YAML only
  python generate_snmp_extension.py oids.csv --no-sign        # YAML + certs, no signature
"""

import argparse
import csv
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from textwrap import dedent


# ---------------------------------------------------------------------------
# CSV / OID helpers
# ---------------------------------------------------------------------------

_HEADER_ALIASES = {"oid", "oids", "object id", "object ids", "object identifier"}


def read_oids(csv_path: str) -> list:
    """
    Return a deduplicated, ordered list of OIDs from a single-column CSV.
    Blank rows and common header row names are skipped.
    Duplicate OIDs are removed while preserving first-seen order.
    """
    oids = []
    seen = set()
    with open(csv_path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        for lineno, row in enumerate(reader, start=1):
            if not row:
                continue
            cell = row[0].strip()
            if not cell:
                continue
            if cell.lower() in _HEADER_ALIASES:
                continue
            if cell in seen:
                print(f"  [WARN] Duplicate OID on line {lineno} skipped: {cell}")
                continue
            seen.add(cell)
            oids.append(cell)

    if not oids:
        _die(f"No OIDs found in '{csv_path}'.")
    return oids


# ---------------------------------------------------------------------------
# YAML generation
# ---------------------------------------------------------------------------

def build_extension_yaml(
    oids: list,
    ext_name: str,
    version: str,
    author: str,
) -> str:
    """
    Build the Dynatrace Extensions 2.0 SNMP YAML as a plain string.
    Avoids a PyYAML dependency and keeps full control over key ordering.

    Each OID maps to metric key  ext:hostSnmp<N>  (N is 0-indexed).
    """
    lines = [
        f"name: {ext_name}",
        f'version: "{version}"',
        f'minDynatraceVersion: "1.217"',
        "author:",
        f'  name: "{author}"',
        "",
        "metrics:",
    ]

    for i in range(len(oids)):
        lines += [
            f"  - key: ext:hostSnmp{i}",
            "    metadata:",
            f'      displayName: "Host SNMP Metric {i}"',
            "      unit: Count",
        ]

    lines += [
        "",
        "snmp:",
        "  - group: snmp_metrics",
        "    interval:",
        "      minutes: 1",
        "    dimensions:",
        "      - key: device",
        "        value: this:device.address",
        "    subgroups:",
        "      - subgroup: host_metrics",
        "        table: false",
        "        metrics:",
    ]

    for i, oid in enumerate(oids):
        lines += [
            f"          - key: ext:hostSnmp{i}",
            f'            value: "oid:{oid}"',
        ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Certificate generation (OpenSSL CLI)
# ---------------------------------------------------------------------------

def _run(cmd: list, label: str = "") -> None:
    """Run a subprocess command; exit with a clear message on failure."""
    try:
        subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors="replace").strip()
        _die(f"OpenSSL command failed{' (' + label + ')' if label else ''}:\n  {detail}")
    except FileNotFoundError:
        _die(
            f"'{cmd[0]}' not found. Make sure OpenSSL is installed and on your PATH."
        )


def generate_certs(certs_dir: Path, org: str) -> dict:
    """
    Produce:
      ca.key / ca.crt       – self-signed 4096-bit RSA CA (365-day validity)
      extension.key         – 4096-bit RSA key for signing the extension
      extension.csr         – CSR for the extension cert
      extension.crt         – extension cert signed by the CA (365-day validity)

    Returns a dict of Path objects keyed by short name.
    """
    certs_dir.mkdir(parents=True, exist_ok=True)

    p = {
        "ca_key":   certs_dir / "ca.key",
        "ca_cert":  certs_dir / "ca.crt",
        "ext_key":  certs_dir / "extension.key",
        "ext_csr":  certs_dir / "extension.csr",
        "ext_cert": certs_dir / "extension.crt",
    }

    subj_ca  = f"/CN=Developer CA/O={org}"
    subj_ext = f"/CN=Extension Signing/O={org}"

    print("  Generating CA key (4096-bit RSA)...")
    _run(["openssl", "genrsa", "-out", str(p["ca_key"]), "4096"], "CA key")

    print("  Generating self-signed CA certificate (365 days)...")
    _run(
        [
            "openssl", "req", "-new", "-x509", "-days", "365",
            "-key", str(p["ca_key"]),
            "-out", str(p["ca_cert"]),
            "-subj", subj_ca,
        ],
        "CA cert",
    )

    print("  Generating extension signing key (4096-bit RSA)...")
    _run(["openssl", "genrsa", "-out", str(p["ext_key"]), "4096"], "ext key")

    print("  Generating extension CSR...")
    _run(
        [
            "openssl", "req", "-new",
            "-key", str(p["ext_key"]),
            "-out", str(p["ext_csr"]),
            "-subj", subj_ext,
        ],
        "ext CSR",
    )

    print("  Signing extension certificate with CA...")
    _run(
        [
            "openssl", "x509", "-req", "-days", "365",
            "-in",  str(p["ext_csr"]),
            "-CA",  str(p["ca_cert"]),
            "-CAkey", str(p["ca_key"]),
            "-CAcreateserial",
            "-out", str(p["ext_cert"]),
        ],
        "ext cert",
    )

    return p


# ---------------------------------------------------------------------------
# Packaging and signing
# ---------------------------------------------------------------------------

def package_extension(yaml_path: Path, zip_path: Path) -> None:
    """Create extension.zip containing extension.yaml at the archive root."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(yaml_path, "extension.yaml")


def sign_extension(zip_path: Path, certs: dict) -> Path:
    """
    Sign extension.zip with OpenSSL CMS (DER output).
    Produces extension.zip.sig alongside the zip.
    """
    sig_path = zip_path.parent / (zip_path.name + ".sig")
    _run(
        [
            "openssl", "cms", "-sign",
            "-signer", str(certs["ext_cert"]),
            "-inkey",  str(certs["ext_key"]),
            "-CAfile", str(certs["ca_cert"]),
            "-in",     str(zip_path),
            "-binary",
            "-outform", "DER",
            "-out",    str(sig_path),
        ],
        "CMS sign",
    )
    return sig_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"\n[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_snmp_extension.py",
        description=(
            "Generate a Dynatrace Extensions 2.0 SNMP extension "
            "from a CSV file of OIDs."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent(
            """\
            CSV format
            ----------
            A plain CSV with one OID per row in the first column.
            A header row whose first cell matches 'oid', 'object id', or
            'object identifier' (case-insensitive) is automatically skipped.
            Duplicate OIDs are deduplicated (first occurrence wins).

            Example oids.csv:
              1.3.6.1.2.1.1.1.0
              1.3.6.1.2.1.1.3.0
              1.3.6.1.4.1.9.2.1.57.0

            Dynatrace next steps
            --------------------
            1. Upload  certs/ca.crt  as a trusted certificate:
                 Dynatrace > Settings > Extension Execution Controller > Certificates
            2. Upload  extension.zip  (+ extension.zip.sig) via:
                 Dynatrace > Hub > My Hub > Upload custom extension
            """
        ),
    )

    parser.add_argument(
        "csv_file",
        help="CSV file with one OID per row (first column).",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./snmp-extension",
        metavar="DIR",
        help="Destination directory (default: ./snmp-extension).",
    )
    parser.add_argument(
        "--extension-name", "-n",
        default="custom:snmp-host-metrics",
        metavar="NAME",
        help="Dynatrace extension name (default: custom:snmp-host-metrics).",
    )
    parser.add_argument(
        "--version", "-V",
        default="1.0.0",
        metavar="VER",
        help="Extension version string (default: 1.0.0).",
    )
    parser.add_argument(
        "--author", "-a",
        default="Generated Extension",
        metavar="NAME",
        help="Author name in extension.yaml (default: 'Generated Extension').",
    )
    parser.add_argument(
        "--org",
        default="My Organization",
        metavar="ORG",
        help="Organization name used in certificate subjects (default: 'My Organization').",
    )
    parser.add_argument(
        "--no-sign",
        action="store_true",
        help="Generate YAML, certs, and zip but skip the CMS signature step.",
    )
    parser.add_argument(
        "--skip-certs",
        action="store_true",
        help="Generate only extension.yaml; skip certificates, zip, and signing.",
    )

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    # ---- validate inputs ---------------------------------------------------
    if not os.path.isfile(args.csv_file):
        _die(f"CSV file not found: {args.csv_file}")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ---- Step 1: read OIDs -------------------------------------------------
    print(f"\n[1/5] Reading OIDs from '{args.csv_file}'...")
    oids = read_oids(args.csv_file)
    print(f"      {len(oids)} unique OID(s) loaded.")

    # ---- Step 2: generate extension.yaml -----------------------------------
    print("\n[2/5] Generating extension.yaml...")
    yaml_content = build_extension_yaml(
        oids,
        ext_name=args.extension_name,
        version=args.version,
        author=args.author,
    )
    yaml_path = output_dir / "extension.yaml"
    yaml_path.write_text(yaml_content, encoding="utf-8")
    print(f"      Written: {yaml_path}")

    if args.skip_certs:
        print(
            "\n--skip-certs requested. "
            "Stopping after YAML generation (no certs, zip, or signature)."
        )
        _summary(output_dir, yaml_path, None, None, None)
        return

    # ---- Step 3: generate certificates ------------------------------------
    print("\n[3/5] Generating certificates (this may take a moment)...")
    certs_dir = output_dir / "certs"
    certs = generate_certs(certs_dir, args.org)
    print(f"      CA cert:        {certs['ca_cert']}")
    print(f"      Extension cert: {certs['ext_cert']}")

    # ---- Step 4: package into zip -----------------------------------------
    print("\n[4/5] Packaging extension.zip...")
    zip_path = output_dir / "extension.zip"
    package_extension(yaml_path, zip_path)
    print(f"      Written: {zip_path}")

    # ---- Step 5: sign ------------------------------------------------------
    sig_path = None
    if args.no_sign:
        print("\n[5/5] Signing skipped (--no-sign).")
    else:
        print("\n[5/5] Signing extension.zip with CMS/DER signature...")
        sig_path = sign_extension(zip_path, certs)
        print(f"      Signature: {sig_path}")

    _summary(output_dir, yaml_path, certs, zip_path, sig_path)


def _summary(
    output_dir: Path,
    yaml_path: Path,
    certs,
    zip_path,
    sig_path,
) -> None:
    print("\n" + "=" * 60)
    print("Done!  Output directory:", output_dir.resolve())
    print("=" * 60)
    print(f"  extension.yaml  : {yaml_path}")
    if certs:
        print(f"  ca.crt          : {certs['ca_cert']}")
        print(f"  extension.crt   : {certs['ext_cert']}")
    if zip_path:
        print(f"  extension.zip   : {zip_path}")
    if sig_path:
        print(f"  extension.zip.sig: {sig_path}")
    print()
    print("Next steps:")
    print("  1. Upload  certs/ca.crt  to Dynatrace as a trusted certificate:")
    print("       Settings > Extension Execution Controller > Certificates")
    print("  2. Upload  extension.zip  in the Dynatrace Hub:")
    print("       Hub > My Hub > Upload custom extension")
    if sig_path:
        print(f"     (include {sig_path.name} alongside the zip)")
    print()


if __name__ == "__main__":
    main()
