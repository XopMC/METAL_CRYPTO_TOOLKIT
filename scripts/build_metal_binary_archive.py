#!/usr/bin/env python3
"""Build and verify the v16.0.1 Apple Silicon Metal binary archive."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile
from typing import NamedTuple, Sequence


APPLE_GPU_SLICES = (
    "applegpu_g13g",
    "applegpu_g13s",
    "applegpu_g13d",
    "applegpu_g14g",
    "applegpu_g14s",
    "applegpu_g14d",
    "applegpu_g15g",
    "applegpu_g15s",
    "applegpu_g15d",
    "applegpu_g16g",
    "applegpu_g16s",
)

TRANSLATOR_TARGET = "air64-apple-macos15.0"


class FunctionConstant(NamedTuple):
    index: int
    value_type: str
    value: bool | int


class ArchiveProfile(NamedTuple):
    function: str
    specialized_name: str
    pipeline_key: str
    constants: tuple[FunctionConstant, ...]


def bool_constant(index: int, value: bool) -> FunctionConstant:
    return FunctionConstant(index, "ConstantBool", value)


def uint_constant(index: int, value: int) -> FunctionConstant:
    return FunctionConstant(index, "ConstantUInt", value)


def hmac_profile() -> ArchiveProfile:
    target_flags = tuple(
        bool_constant(index, index in (0, 14)) for index in range(27)
    )
    trailing_flags = tuple(bool_constant(index, False) for index in (66, 67, 68))
    flags_key = "".join("1" if index in (0, 14) else "0" for index in range(30))
    constants = target_flags + (
        uint_constant(32, 1023),
        uint_constant(33, 3),
        uint_constant(34, 1),
    ) + trailing_flags + (
        uint_constant(90, 16),
        uint_constant(91, 17),
    )
    return ArchiveProfile(
        function="workerHmac_seq",
        specialized_name="workerHmac_seq_v16_0_1_compressed_bip32",
        pipeline_key=(
            f"worker-targets:{flags_key}:ada:1023:"
            "ecmult-window:16:17:ada:1023:dot:3:der:1"
        ),
        constants=constants,
    )


def bip38_profile(profile: int, suffix: str) -> ArchiveProfile:
    return ArchiveProfile(
        function="workerBip38Grouped",
        specialized_name=f"workerBip38Grouped_v16_0_1_{suffix}",
        pipeline_key=(
            f"browser-vault-profile:{profile}:"
            "ecmult-window:16:17:ada:1023:dot:3:der:1"
        ),
        constants=(
            uint_constant(32, 1023),
            uint_constant(33, 3),
            uint_constant(34, 1),
            uint_constant(90, 16),
            uint_constant(91, 17),
            uint_constant(92, profile),
        ),
    )


PROFILES = (
    hmac_profile(),
    bip38_profile(28, "non_ec"),
    bip38_profile(30, "ec"),
)


def validate_manifest() -> None:
    if len(APPLE_GPU_SLICES) != 11 or len(set(APPLE_GPU_SLICES)) != 11:
        raise ValueError("Apple GPU slice manifest must contain 11 unique entries")
    if len(PROFILES) != 3:
        raise ValueError("binary archive must contain exactly three profiles")
    if len({profile.specialized_name for profile in PROFILES}) != len(PROFILES):
        raise ValueError("binary archive specialized names must be unique")
    if len({profile.pipeline_key for profile in PROFILES}) != len(PROFILES):
        raise ValueError("binary archive pipeline keys must be unique")
    for profile in PROFILES:
        indices = [constant.index for constant in profile.constants]
        if len(indices) != len(set(indices)):
            raise ValueError(f"duplicate function constant in {profile.specialized_name}")


def translation_config() -> dict:
    validate_manifest()
    specialized_functions = []
    compute_pipelines = []
    for profile in PROFILES:
        label = f"{profile.specialized_name}_library"
        specialized_functions.append(
            {
                "label": label,
                "function": profile.function,
                "specialized_name": profile.specialized_name,
                "constant_values": [
                    {
                        "id_type": "FunctionConstantIndex",
                        "id": {"data": constant.index},
                        "value_type": constant.value_type,
                        "value": {"data": constant.value},
                    }
                    for constant in profile.constants
                ],
            }
        )
        compute_pipelines.append(
            {
                "compute_function": (
                    f"alias:{label}#{profile.specialized_name}"
                )
            }
        )
    return {
        "libraries": {"specialized_functions": specialized_functions},
        "pipelines": {"compute_pipelines": compute_pipelines},
    }


def render_translation_config() -> str:
    return json.dumps(translation_config(), indent=2, sort_keys=False) + "\n"


def c_string(value: str) -> str:
    return json.dumps(value)


def render_runtime_header() -> str:
    validate_manifest()
    entries = "\n".join(
        "    {"
        f"{c_string(profile.function)}, "
        f"{c_string(profile.pipeline_key)}, "
        f"{c_string(profile.specialized_name)}"
        "},"
        for profile in PROFILES
    )
    return (
        "// Generated by scripts/build_metal_binary_archive.py. Do not edit.\n"
        "#pragma once\n\n"
        "namespace metal_crypto {\n\n"
        "struct MetalBinaryArchiveProfile {\n"
        "    const char* functionName;\n"
        "    const char* pipelineKey;\n"
        "    const char* specializedName;\n"
        "};\n\n"
        "inline constexpr MetalBinaryArchiveProfile kMetalBinaryArchiveProfiles[] = {\n"
        f"{entries}\n"
        "};\n\n"
        "} // namespace metal_crypto\n"
    )


def write_text_if_changed(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)


def archive_slices(archive: pathlib.Path) -> tuple[str, ...]:
    output = subprocess.check_output(
        ["xcrun", "metal-lipo", str(archive), "-archs"],
        text=True,
    )
    return tuple(output.split())


def verify_archive(archive: pathlib.Path) -> None:
    if not archive.is_file():
        raise FileNotFoundError(f"Metal binary archive is missing: {archive}")
    actual = archive_slices(archive)
    if actual != APPLE_GPU_SLICES:
        raise RuntimeError(
            "Metal binary archive slices differ: "
            f"expected={' '.join(APPLE_GPU_SLICES)}; actual={' '.join(actual) or 'missing'}"
        )


def run_checked(command: Sequence[str]) -> None:
    subprocess.run(list(command), check=True)


def build_archive(
    metallib: pathlib.Path,
    output: pathlib.Path,
    config_output: pathlib.Path,
    target: str,
) -> None:
    validate_manifest()
    if not metallib.is_file():
        raise FileNotFoundError(f"Metal IR library is missing: {metallib}")
    if config_output.suffix != ".mtlp-json":
        raise ValueError("Metal translator config must end in .mtlp-json")
    write_text_if_changed(config_output, render_translation_config())
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(
        prefix="metal-binary-archive.", dir=output.parent
    ) as temporary_directory:
        temporary_root = pathlib.Path(temporary_directory)
        thin_archives = []
        for gpu_slice in APPLE_GPU_SLICES:
            thin_archive = temporary_root / f"{gpu_slice}.metallib"
            run_checked(
                (
                    "xcrun",
                    "metal-tt",
                    str(metallib),
                    str(config_output),
                    "-target",
                    target,
                    "-arch",
                    gpu_slice,
                    "-o",
                    str(thin_archive),
                )
            )
            thin_archives.append(thin_archive)

        candidate = temporary_root / "default.binary.metallib"
        run_checked(
            (
                "xcrun",
                "metal-lipo",
                "-create",
                *(str(path) for path in thin_archives),
                "-output",
                str(candidate),
            )
        )
        verify_archive(candidate)
        os.replace(candidate, output)

    verify_archive(output)
    print(f"[!] Metal binary archive slices: {' '.join(APPLE_GPU_SLICES)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    header_parser = subparsers.add_parser("header")
    header_parser.add_argument("--output", type=pathlib.Path, required=True)

    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--metallib", type=pathlib.Path, required=True)
    build_parser.add_argument("--output", type=pathlib.Path, required=True)
    build_parser.add_argument("--config-output", type=pathlib.Path, required=True)
    build_parser.add_argument("--target", default=TRANSLATOR_TARGET)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--archive", type=pathlib.Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "header":
            write_text_if_changed(args.output, render_runtime_header())
        elif args.command == "build":
            build_archive(args.metallib, args.output, args.config_output, args.target)
        elif args.command == "verify":
            verify_archive(args.archive)
            print(f"[!] Metal binary archive slices: {' '.join(APPLE_GPU_SLICES)}")
        else:
            raise ValueError(f"unknown command: {args.command}")
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"[!] Metal binary archive error: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
