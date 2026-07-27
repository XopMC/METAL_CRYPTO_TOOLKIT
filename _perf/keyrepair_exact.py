#!/usr/bin/env python3
"""Executable CPU-to-Metal correctness contract for -keyrepair."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import subprocess
import tempfile


ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
G_COMPRESSED = (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
G_UNCOMPRESSED = (
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
PRIVATE_ONE = "0" * 63 + "1"
WIF_ONE = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
ADDRESS = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
ZERO_HASH_ADDRESS = "1111111111111111111114oLvT2"


def base58check(payload: bytes) -> str:
    encoded = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    leading = len(encoded) - len(encoded.lstrip(b"\0"))
    number = int.from_bytes(encoded, "big")
    digits = bytearray()
    while number:
        number, digit = divmod(number, 58)
        digits.append(ALPHABET[digit])
    return (ALPHABET[:1] * leading + digits[::-1]).decode("ascii")


def extended_keys() -> tuple[str, str]:
    chain = bytes(range(1, 33))
    common = b"\0" + b"\0" * 4 + b"\0" * 4 + chain
    xprv = base58check(bytes.fromhex("0488ade4") + common + b"\0" + bytes.fromhex(PRIVATE_ONE))
    xpub = base58check(bytes.fromhex("0488b21e") + common + bytes.fromhex(G_COMPRESSED))
    return xprv, xpub


def run(binary: pathlib.Path, args: list[str], expected_code: int = 0) -> str:
    completed = subprocess.run(
        [str(binary), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
        check=False,
    )
    if completed.returncode != expected_code:
        raise AssertionError(
            f"{args!r}: exit {completed.returncode}, expected {expected_code}\n"
            f"{completed.stdout}"
        )
    return completed.stdout


def require(output: str, *needles: str) -> None:
    missing = [needle for needle in needles if needle not in output]
    if missing:
        raise AssertionError(f"missing {missing!r} in output:\n{output}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        type=pathlib.Path,
        default=pathlib.Path("./METAL_CRYPTO_TOOLKIT"),
    )
    options = parser.parse_args()
    binary = options.binary.resolve()

    help_a = run(binary, ["-keyrepair", "-help"])
    help_b = run(binary, ["-help", "-keyrepair"])
    require(help_a, "MAIN MODE: -keyrepair", "Candidate/s", "Verify/s")
    if help_a != help_b:
        raise AssertionError("the two full-help orders differ")

    wif = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "wif",
            "-i",
            WIF_ONE[:-1] + "?",
            "-n",
            "128",
        ],
    )
    require(wif, f"VALUE:{WIF_ONE}", f"PRIVATE:{PRIVATE_ONE}")

    address = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "address",
            "-i",
            ADDRESS[:-1] + "?",
            "-n",
            "128",
        ],
    )
    require(address, f"VALUE:{ADDRESS}", "PAYLOAD:007680adec8eabcabac676be9e83854ade0bd22cdb")
    if ":PRIVATE:" in address:
        raise AssertionError("address repair must never report a private key")

    xprv, xpub = extended_keys()
    xprv_output = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "xprv",
            "-i",
            xprv[:-1] + "?",
            "-n",
            "128",
        ],
    )
    require(xprv_output, f"VALUE:{xprv}", f"PRIVATE:{PRIVATE_ONE}")
    xpub_output = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "xpub",
            "-i",
            xpub[:-1] + "?",
            "-n",
            "128",
        ],
    )
    require(xpub_output, f"VALUE:{xpub}")

    raw_private = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "raw-private",
            "-i",
            PRIVATE_ONE[:-1] + "?",
            "-target",
            G_COMPRESSED,
            "-n",
            "64",
        ],
    )
    require(raw_private, f"PRIVATE:{PRIVATE_ONE}", f"PUBLIC:{G_UNCOMPRESSED}")

    raw_public = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "raw-public",
            "-i",
            G_UNCOMPRESSED[:-1] + "?",
            "-target",
            G_COMPRESSED,
            "-n",
            "64",
        ],
    )
    require(raw_public, f"PUBLIC:{G_UNCOMPRESSED}")

    # 58^12 exceeds 64 bits. The valid all-zero HASH160 address is ordinal
    # zero, so this proves the U256 domain and Metal window without traversing
    # the enormous remainder.
    wide = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "address",
            "-i",
            "?" * 12 + ZERO_HASH_ADDRESS[12:],
            "-n",
            "128",
        ],
    )
    require(
        wide,
        f"VALUE:{ZERO_HASH_ADDRESS}",
        "candidate space: 0x00000000000000000000000000000000000000000000004e900abb53e6b71000",
    )

    invalid = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "wif",
            "-i",
            WIF_ONE[:-1] + ("1" if WIF_ONE[-1] != "1" else "2"),
        ],
    )
    if "KEYREPAIR:WIF:SOURCE" in invalid or "Found: 0 / 1" not in invalid:
        raise AssertionError(f"invalid checksum was accepted:\n{invalid}")

    missing_target = run(
        binary,
        [
            "-keyrepair",
            "-repair-type",
            "raw-private",
            "-i",
            PRIVATE_ONE[:-1] + "?",
        ],
        expected_code=2,
    )
    require(missing_target, "raw-private repair requires")

    with tempfile.TemporaryDirectory(prefix="keyrepair-exact-") as temp:
        target_file = pathlib.Path(temp) / "targets.txt"
        target_file.write_text(
            f"# canonical duplicate\n{G_COMPRESSED} first\n"
            f"{G_UNCOMPRESSED} same-point\n",
            encoding="ascii",
        )
        deduplicated = run(
            binary,
            [
                "-keyrepair",
                "-repair-type",
                "raw-private",
                "-i",
                PRIVATE_ONE[:-1] + "?",
                "-target",
                str(target_file),
                "-n",
                "64",
            ],
        )
        require(deduplicated, "targets: 1", f"PRIVATE:{PRIVATE_ONE}")

    print(
        "keyrepair exact: PASS "
        "(help, WIF, xprv/xpub, address, raw keys, U256, negatives, dedupe)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
