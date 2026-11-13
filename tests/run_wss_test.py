"""Isolated TLS credentials and in-memory WSS integration; no network sockets."""
import argparse
import pathlib
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("binary")
parser.add_argument("--wrong-host", action="store_true")
parser.add_argument("--mode", default="")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="dpdk-wss-test-") as folder:
    root = pathlib.Path(folder)
    hostname = "wrong.test" if args.wrong_host else "demo.test"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
        "-days", "1", "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName=DNS:{hostname}",
    ], check=True, capture_output=True, timeout=15)
    result = subprocess.run([args.binary, str(root / "cert.pem"), str(root / "key.pem"), args.mode],
                            capture_output=True, text=True, timeout=15)
    if args.wrong_host:
        assert result.returncode != 0 and "TLS handshake/certificate" in result.stderr, result
        print("PASS: certificate hostname mismatch rejected")
    elif args.mode in ("bad_accept", "masked"):
        reason = {"bad_accept": "HTTP upgrade validation", "masked": "WS flags/mask"}[args.mode]
        assert result.returncode != 0 and reason in result.stderr, result
        print(f"PASS: malformed {args.mode} rejected")
    else:
        print(result.stdout, end="")
        assert result.returncode == 0, result.stderr
