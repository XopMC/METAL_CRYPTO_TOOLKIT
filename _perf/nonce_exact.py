#!/usr/bin/env python3
"""Executable CPU-to-Metal correctness contract for -nonce."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import tempfile


ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
FIELD = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)
PRIVATE_ONE = "0" * 63 + "1"
PUBLIC_ONE = (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
PUBLIC_TWO = (
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
R_TWO = (
    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
R_FIVE = (
    "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4"
)
S_K2_Z3 = (
    "63023fca20f6beb69822a0374ae03e6c2e3bc725c6779e53d5d604dcae384f74"
)
S_K2_Z4 = (
    "e3023fca20f6beb69822a0374ae03e6b8b9335991e1bee71b5bf342316537015"
)
S_K5_Z9 = (
    "d64f2c75d2016cea445754a1021276a0c3dafe781eb40587c2307652970530fd"
)
S_MIRRORED_Z5 = (
    "9cfdc035df09414967dd5fc8b51fc1928c7315c0e8d101e7e9fc59b021fdf1cc"
)
S_HIGH_Z7 = (
    "8641998106234453aa5f9d6a3178f4f7b812e00b817a776265dfdd31b93e29a2"
)
BIP340_S = (
    "2a611524b69063bd7510422cf8ed5173cb45dfc1709233966cb967887f4e3890"
)


def scalar(value: int) -> str:
    return f"{value:064x}"


def ecdsa(r_value: str, s_value: str, z_value: int) -> str:
    return (
        f"ecdsa:{r_value}:{s_value}:{scalar(z_value)}:{PUBLIC_ONE}"
    )


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


def require_private_one(output: str, nonce: int) -> None:
    require(
        output,
        f"NONCE:{scalar(nonce)}",
        f"PRIVATE:{PRIVATE_ONE}",
        f"PUBLIC:{PUBLIC_ONE}",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--binary",
        type=pathlib.Path,
        default=pathlib.Path("./bin/METAL_CRYPTO_TOOLKIT"),
    )
    options = parser.parse_args()
    binary = options.binary.resolve()

    help_a = run(binary, ["-nonce", "-help"])
    help_b = run(binary, ["-help", "-nonce"])
    require(
        help_a,
        "MAIN MODE: -nonce",
        "ECDSA",
        "BIP340",
        "Nonce/s",
        "Verify/s",
    )
    if help_a != help_b:
        raise AssertionError("the two full-help orders differ")

    bounded = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-start",
            "1",
            "-end",
            "4",
            "-n",
            "16",
        ],
    )
    require_private_one(bounded, 2)
    require(bounded, "Solved: 1 / 1", "Processed 3 nonce candidates")

    bip340 = run(
        binary,
        [
            "-nonce",
            "-i",
            f"bip340:{R_TWO}{BIP340_S}:{'0' * 64}:{PUBLIC_ONE[2:]}",
            "-start",
            "1",
            "-end",
            "4",
            "-n",
            "16",
        ],
    )
    require_private_one(bip340, 2)
    require(bip340, "NONCE:BIP340")

    hex_mask = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-mask",
            "0" * 63 + "?",
            "-n",
            "16",
        ],
    )
    require_private_one(hex_mask, 2)
    require(hex_mask, "Processed 16 nonce candidates")

    binary_mask = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-mask",
            "0" * 252 + "????",
            "-n",
            "16",
        ],
    )
    require_private_one(binary_mask, 2)

    random_order = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-start",
            "1",
            "-end",
            "4",
            "-random",
            "-nonce-seed",
            "7",
            "-n",
            "16",
        ],
    )
    require_private_one(random_order, 2)

    with tempfile.TemporaryDirectory(prefix="nonce-exact-") as temp:
        candidates = pathlib.Path(temp) / "candidates.txt"
        candidates.write_text("# lattice output\n1\n0x2 candidate\n3\n", encoding="ascii")
        candidate_list = run(
            binary,
            [
                "-nonce",
                "-i",
                ecdsa(R_TWO, S_K2_Z3, 3),
                "-nonce-lattice",
                str(candidates),
                "-n",
                "16",
            ],
        )
        require_private_one(candidate_list, 2)
        require(candidate_list, "Processed 3 nonce candidates")

    reused = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-i",
            ecdsa(R_TWO, S_K2_Z4, 4),
            "-n",
            "16",
        ],
    )
    require_private_one(reused, 2)
    require(
        reused,
        "RELATION:same",
        f"SECOND_NONCE:{scalar(2)}",
        "Solved: 2 / 2",
        "Processed 0 nonce candidates",
    )

    mirrored = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-i",
            ecdsa(R_TWO, S_MIRRORED_Z5, 5),
            "-n",
            "16",
        ],
    )
    require_private_one(mirrored, 2)
    require(
        mirrored,
        "RELATION:mirrored",
        f"SECOND_NONCE:{scalar(ORDER - 2)}",
        "Solved: 2 / 2",
    )

    affine = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(R_TWO, S_K2_Z3, 3),
            "-i",
            ecdsa(R_FIVE, S_K5_Z9, 9),
            "-nonce-relation",
            "add:3",
            "-n",
            "16",
        ],
    )
    require_private_one(affine, 2)
    require(
        affine,
        "RELATION:add:3",
        f"SECOND_NONCE:{scalar(5)}",
        "Solved: 2 / 2",
    )

    high_range = run(
        binary,
        [
            "-nonce",
            "-i",
            ecdsa(PUBLIC_ONE[2:], S_HIGH_Z7, 7),
            "-start",
            scalar(ORDER - 2),
            "-end",
            scalar(ORDER),
            "-n",
            "16",
        ],
    )
    require_private_one(high_range, ORDER - 1)
    require(high_range, "Processed 2 nonce candidates")

    wrong_target = run(
        binary,
        [
            "-nonce",
            "-nonce-model",
            "ecdsa",
            "-i",
            f"{R_TWO}:{S_K2_Z3}:{scalar(3)}",
            "-target",
            PUBLIC_TWO,
            "-start",
            "1",
            "-end",
            "4",
            "-n",
            "16",
        ],
    )
    if ":PRIVATE:" in wrong_target:
        raise AssertionError(f"wrong public key was accepted:\n{wrong_target}")
    require(wrong_target, "Solved: 0 / 1")

    invalid_bip340 = run(
        binary,
        [
            "-nonce",
            "-i",
            f"bip340:{scalar(FIELD)}{scalar(1)}:{'0' * 64}:{PUBLIC_ONE[2:]}",
        ],
        expected_code=2,
    )
    require(invalid_bip340, "BIP340 r must be in 0..p-1")

    print(
        "nonce exact: PASS "
        "(help, ECDSA, BIP340, masks, random, list, relations, U256, negatives)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
