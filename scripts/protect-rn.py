#!/usr/bin/env python3
"""Protect an RN adapter APK. Output is unsigned; align and sign afterward."""
import argparse
from pathlib import Path
import subprocess
import os

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("input", type=Path)
parser.add_argument("output", type=Path)
parser.add_argument("--cert-sha256", required=True, help="Final installed signer SHA-256")
parser.add_argument("--mode", choices=["report", "restrict"], default="report")
parser.add_argument("--java", default=str(Path(os.environ.get("JAVA_HOME", "")) / "bin/java")
                    if os.environ.get("JAVA_HOME") else "java")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
jars = sorted((root / "packer/build/libs").glob("protector-packer-*.jar"))
if len(jars) != 1:
    parser.error("Build :packer:jar first; expected exactly one packer JAR")
if args.input.resolve() == args.output.resolve():
    parser.error("Use a separate output path")
args.output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run([
    args.java, "-jar", str(jars[0]), str(args.input.resolve()), "-o", str(args.output.resolve()),
    "--shell-dir", str(root / "executable/shell-files"),
    "--profile", "balanced", "--no-payment-auto-vmp", "--no-industry-auto-vmp",
    "--no-protect-so", "--encrypt-rn-bundle", "--risk-flags", "32",
    "--rasp-action", "0" if args.mode == "report" else "1", "--report-enabled", "1",
    "--cert-sha256", args.cert_sha256,
], check=True, cwd=root)
