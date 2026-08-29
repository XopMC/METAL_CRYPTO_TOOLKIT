import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "scripts" / "build_metal_binary_archive.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("metal_binary_archive_builder", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MetalBinaryArchiveManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = load_builder()

    def test_exact_apple_silicon_slices(self):
        self.assertEqual(
            self.builder.TRANSLATOR_TARGETS,
            (
                "air64-apple-macos15.0",
                "air64-apple-macos26.0",
            ),
        )
        self.assertEqual(
            self.builder.APPLE_GPU_SLICES,
            (
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
            ),
        )

    def test_exact_specialization_profiles(self):
        profiles = self.builder.PROFILES
        self.assertEqual(len(profiles), 4)
        self.assertEqual(len({profile.specialized_name for profile in profiles}), 4)
        self.assertEqual(
            len({(profile.function, profile.pipeline_key) for profile in profiles}),
            4,
        )

        by_name = {profile.specialized_name: profile for profile in profiles}
        hmac = by_name["workerHmac_seq_v16_0_1_compressed_bip32"]
        self.assertEqual(hmac.function, "workerHmac_seq")
        hmac_constants = {constant.index: constant.value for constant in hmac.constants}
        for index in range(27):
            self.assertIn(index, hmac_constants)
            self.assertEqual(hmac_constants[index], index in (0, 14))
        self.assertEqual(
            {index: hmac_constants[index] for index in (32, 33, 34, 66, 67, 68, 90, 91)},
            {32: 1023, 33: 3, 34: 1, 66: False, 67: False, 68: False, 90: 16, 91: 17},
        )
        flags = "".join("1" if index in (0, 14) else "0" for index in range(30))
        self.assertEqual(
            hmac.pipeline_key,
            f"worker-targets:{flags}:ada:1023:ecmult-window:16:17:ada:1023:dot:3:der:1",
        )
        worker = by_name["worker_v16_0_2_compressed_bip32"]
        self.assertEqual(worker.function, "worker")
        self.assertEqual(worker.constants, hmac.constants)
        self.assertEqual(worker.pipeline_key, hmac.pipeline_key)

        expected_bip38 = {
            "workerBip38Grouped_v16_0_1_non_ec": 28,
            "workerBip38Grouped_v16_0_1_ec": 30,
        }
        for specialized_name, profile_value in expected_bip38.items():
            profile = by_name[specialized_name]
            self.assertEqual(profile.function, "workerBip38Grouped")
            self.assertEqual(
                {constant.index: constant.value for constant in profile.constants},
                {32: 1023, 33: 3, 34: 1, 90: 16, 91: 17, 92: profile_value},
            )
            self.assertEqual(
                profile.pipeline_key,
                f"browser-vault-profile:{profile_value}:ecmult-window:16:17:ada:1023:dot:3:der:1",
            )

    def test_translation_config_and_runtime_header_share_profile_names(self):
        config = self.builder.translation_config()
        specialized = config["libraries"]["specialized_functions"]
        pipelines = config["pipelines"]["compute_pipelines"]
        self.assertEqual(len(specialized), 4)
        self.assertEqual(len(pipelines), 4)
        header = self.builder.render_runtime_header()
        for profile, specialization, pipeline in zip(
            self.builder.PROFILES, specialized, pipelines
        ):
            self.assertEqual(
                specialization["label"],
                f"{profile.specialized_name}_library",
            )
            self.assertEqual(specialization["function"], profile.function)
            self.assertEqual(
                specialization["specialized_name"], profile.specialized_name
            )
            self.assertEqual(
                pipeline["compute_function"],
                f"alias:{profile.specialized_name}_library#{profile.specialized_name}",
            )
            self.assertIn(profile.function, header)
            self.assertIn(profile.pipeline_key, header)
            self.assertIn(profile.specialized_name, header)

    def test_archive_verification_accepts_metal_lipo_slice_order(self):
        with tempfile.TemporaryDirectory(prefix="metal-archive-verify-test.") as directory:
            archive = pathlib.Path(directory) / "archive.metallib"
            archive.touch()
            reordered = tuple(reversed(self.builder.APPLE_GPU_SLICES))
            with mock.patch.object(self.builder, "archive_slices", return_value=reordered):
                self.builder.verify_archive(archive)

    def test_archive_verification_rejects_missing_or_duplicate_slices(self):
        with tempfile.TemporaryDirectory(prefix="metal-archive-verify-test.") as directory:
            archive = pathlib.Path(directory) / "archive.metallib"
            archive.touch()
            malformed = self.builder.APPLE_GPU_SLICES[:-1] + (self.builder.APPLE_GPU_SLICES[0],)
            with mock.patch.object(self.builder, "archive_slices", return_value=malformed):
                with self.assertRaisesRegex(RuntimeError, "slices differ"):
                    self.builder.verify_archive(archive)


class Apple7TranslatorRegressionTests(unittest.TestCase):
    def test_mnemonic_worker_specialization_translates_for_applegpu_g13g(self):
        source = ROOT / "Kernels" / "worker.metal"
        with tempfile.TemporaryDirectory(prefix="metal-archive-worker-test.") as directory:
            temporary = pathlib.Path(directory)
            air = temporary / "worker.air"
            metallib = temporary / "worker.metallib"
            config = temporary / "worker.mtlp-json"
            archive = temporary / "worker.binary.metallib"
            compilation = subprocess.run(
                [
                    "xcrun",
                    "metal",
                    "-std=metal3.1",
                    "-mmacosx-version-min=14.0",
                    f"-I{ROOT}",
                    "-c",
                    str(source),
                    "-o",
                    str(air),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                compilation.returncode,
                0,
                msg=f"Metal worker source compilation failed:\n{compilation.stderr}",
            )
            library_link = subprocess.run(
                ["xcrun", "metallib", str(air), "-o", str(metallib)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                library_link.returncode,
                0,
                msg=f"Metal worker library link failed:\n{library_link.stderr}",
            )

            def constant(index, value_type, value):
                return {
                    "id_type": "FunctionConstantIndex",
                    "id": {"data": index},
                    "value_type": value_type,
                    "value": {"data": value},
                }

            constants = [
                constant(index, "ConstantBool", index in (0, 14))
                for index in range(27)
            ]
            constants.extend(
                (
                    constant(32, "ConstantUInt", 1023),
                    constant(33, "ConstantUInt", 3),
                    constant(34, "ConstantUInt", 1),
                    constant(66, "ConstantBool", False),
                    constant(67, "ConstantBool", False),
                    constant(68, "ConstantBool", False),
                    constant(90, "ConstantUInt", 16),
                    constant(91, "ConstantUInt", 17),
                )
            )
            specialized_name = "worker_test_compressed_bip32"
            config.write_text(
                json.dumps(
                    {
                        "libraries": {
                            "specialized_functions": [
                                {
                                    "label": "Worker",
                                    "function": "worker",
                                    "specialized_name": specialized_name,
                                    "constant_values": constants,
                                }
                            ]
                        },
                        "pipelines": {
                            "compute_pipelines": [
                                {
                                    "compute_function": (
                                        f"alias:Worker#{specialized_name}"
                                    )
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            translation = subprocess.run(
                [
                    "xcrun",
                    "metal-tt",
                    str(metallib),
                    str(config),
                    "-target",
                    "air64-apple-macos15.0",
                    "-arch",
                    "applegpu_g13g",
                    "-o",
                    str(archive),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                translation.returncode,
                0,
                msg=f"applegpu_g13g worker translation failed:\n{translation.stderr}",
            )
            self.assertEqual(load_builder().archive_slices(archive), ("applegpu_g13g",))

    def test_result_counter_translates_for_applegpu_g13g(self):
        self.assert_translates_for_applegpu_g13g(
            "metal_binary_archive_atomic_counter.metal",
            "metal_archive_atomic_counter",
        )

    def test_wallet_counter_translates_for_applegpu_g13g(self):
        self.assert_translates_for_applegpu_g13g(
            "metal_binary_archive_wallet_counter.metal",
            "metal_archive_wallet_counter",
        )

    def assert_translates_for_applegpu_g13g(self, source_name, function_name):
        source = ROOT / "tests" / source_name
        with tempfile.TemporaryDirectory(prefix="metal-archive-atomic-test.") as directory:
            temporary = pathlib.Path(directory)
            air = temporary / "atomic.air"
            metallib = temporary / "atomic.metallib"
            config = temporary / "atomic.mtlp-json"
            archive = temporary / "atomic.binary.metallib"
            compilation = subprocess.run(
                [
                    "xcrun",
                    "metal",
                    "-std=metal3.1",
                    "-mmacosx-version-min=14.0",
                    f"-I{ROOT}",
                    "-c",
                    str(source),
                    "-o",
                    str(air),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                compilation.returncode,
                0,
                msg=f"Metal source compilation failed:\n{compilation.stderr}",
            )
            library_link = subprocess.run(
                ["xcrun", "metallib", str(air), "-o", str(metallib)],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                library_link.returncode,
                0,
                msg=f"Metal library link failed:\n{library_link.stderr}",
            )
            config.write_text(
                json.dumps(
                    {
                        "libraries": {
                            "paths": [
                                {"label": "Counter", "path": str(metallib)}
                            ]
                        },
                        "pipelines": {
                            "compute_pipelines": [
                                {
                                    "compute_function": f"alias:Counter#{function_name}"
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            translation = subprocess.run(
                [
                    "xcrun",
                    "metal-tt",
                    str(metallib),
                    str(config),
                    "-target",
                    load_builder().TRANSLATOR_TARGETS[0],
                    "-arch",
                    "applegpu_g13g",
                    "-o",
                    str(archive),
                ],
                text=True,
                capture_output=True,
            )
            self.assertEqual(
                translation.returncode,
                0,
                msg=f"applegpu_g13g translation failed:\n{translation.stderr}",
            )
            self.assertEqual(load_builder().archive_slices(archive), ("applegpu_g13g",))


if __name__ == "__main__":
    unittest.main()
