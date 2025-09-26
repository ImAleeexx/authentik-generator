#!/usr/bin/env python3
import argparse
import json
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def pem_cert_to_der_b64(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def build_claims(cfg: dict) -> dict:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=int(cfg.get("expiry_days", 365)))
    return {
        "aud": cfg["aud"],
        "exp": int(exp.timestamp()),
        "name": cfg.get("name", "License"),
        "internal_users": int(cfg.get("internal_users", 0)),
        "external_users": int(cfg.get("external_users", 0)),
        "license_flags": list(cfg.get("license_flags", [])),
    }


def generate_intermediate(root_cert, root_key):
    """Generate intermediate cert signed by root"""
    key = ec.generate_private_key(ec.SECP521R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA512())
    )
    return key, cert


def generate_leaf(intermediate_cert, intermediate_key):
    """Generate leaf cert signed by intermediate"""
    key = ec.generate_private_key(ec.SECP521R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "License Leaf")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(intermediate_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(intermediate_key, hashes.SHA512())
    )
    return key, cert


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--config", "-c", type=Path, required=True, help="JSON config")
    p.add_argument("--rootca", type=Path, required=True, help="Root CA cert PEM")
    p.add_argument("--rootkey", type=Path, required=True, help="Root CA private key PEM")
    p.add_argument("--out", "-o", type=Path, default=Path("license.jwt"))
    args = p.parse_args()

    cfg = json.loads(args.config.read_text())

    # Load root cert + key
    root_cert = x509.load_pem_x509_certificate(args.rootca.read_bytes())
    root_key = serialization.load_pem_private_key(args.rootkey.read_bytes(), password=None)

    # Paths
    interm_key_p = Path("intermediate.key")
    interm_cert_p = Path("intermediate.pem")
    leaf_key_p = Path("leaf.key")
    leaf_cert_p = Path("leaf.pem")

    # Generate intermediate if missing
    if not interm_cert_p.exists():
        print("[+] Generating intermediate cert...")
        ikey, icert = generate_intermediate(root_cert, root_key)
        interm_key_p.write_bytes(
            ikey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        interm_cert_p.write_bytes(icert.public_bytes(serialization.Encoding.PEM))

    icert = x509.load_pem_x509_certificate(interm_cert_p.read_bytes())
    ikey = serialization.load_pem_private_key(interm_key_p.read_bytes(), password=None)

    # Generate leaf if missing
    if not leaf_cert_p.exists():
        print("[+] Generating leaf cert...")
        lkey, lcert = generate_leaf(icert, ikey)
        leaf_key_p.write_bytes(
            lkey.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        leaf_cert_p.write_bytes(lcert.public_bytes(serialization.Encoding.PEM))

    lcert = x509.load_pem_x509_certificate(leaf_cert_p.read_bytes())
    lkey = serialization.load_pem_private_key(leaf_key_p.read_bytes(), password=None)

    # Build JWT claims
    claims = build_claims(cfg)

    # x5c header: leaf + intermediate (DER b64)
    x5c = [pem_cert_to_der_b64(lcert), pem_cert_to_der_b64(icert)]

    token = jwt.encode(claims, lkey, algorithm="ES512", headers={"x5c": x5c})
    args.out.write_text(token)
    print(f"[+] Wrote license JWT to {args.out}")


if __name__ == "__main__":
    main()
