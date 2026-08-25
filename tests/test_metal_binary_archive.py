import importlib.util
import pathlib
import unittest


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
        self.assertEqual(len(profiles), 3)
        self.assertEqual(len({profile.specialized_name for profile in profiles}), 3)
        self.assertEqual(len({profile.pipeline_key for profile in profiles}), 3)

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
        self.assertEqual(len(specialized), 3)
        self.assertEqual(len(pipelines), 3)
        header = self.builder.render_runtime_header()
        for profile in self.builder.PROFILES:
            self.assertIn(profile.function, header)
            self.assertIn(profile.pipeline_key, header)
            self.assertIn(profile.specialized_name, header)


if __name__ == "__main__":
    unittest.main()
