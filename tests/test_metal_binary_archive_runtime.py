import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(
    os.environ.get(
        "METAL_ARCHIVE_TEST_BINARY",
        str(ROOT / "bin" / "METAL_CRYPTO_TOOLKIT"),
    )
).resolve()
HMAC_POINT = (
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000000"
)


class MetalBinaryArchiveRuntimeTests(unittest.TestCase):
    def run_strict(self, arguments, timeout=180):
        environment = os.environ.copy()
        environment["METAL_REQUIRE_BINARY_ARCHIVE"] = "1"
        return subprocess.run(
            [str(BINARY), *arguments],
            cwd=BINARY.parent,
            env=environment,
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    def test_hmac_issue_profile_hits_embedded_archive_in_strict_mode(self):
        self.assertTrue(BINARY.is_file(), "build bin/METAL_CRYPTO_TOOLKIT first")
        with tempfile.TemporaryDirectory(prefix="metal-archive-runtime-test.") as directory:
            derivations = pathlib.Path(directory) / "derivations.txt"
            derivations.write_text("m/44'/0'/0'/0/0\n", encoding="utf-8")
            result = self.run_strict(
                [
                    "-hmac",
                    "-start",
                    HMAC_POINT,
                    "-end",
                    HMAC_POINT,
                    "-d",
                    str(derivations),
                    "-c",
                    "c",
                    "-hash",
                    "00112233445566778899aabbccddeeff00112233",
                ],
            )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=output)
        self.assertNotIn("XPC_ERROR_CONNECTION_INTERRUPTED", output)
        self.assertIn(
            "Metal binary archive hit: workerHmac_seq "
            "(workerHmac_seq_v16_0_1_compressed_bip32)",
            output,
        )

    def test_mnemonic_bip32_worker_hits_embedded_archive_in_strict_mode(self):
        self.assertTrue(BINARY.is_file(), "build bin/METAL_CRYPTO_TOOLKIT first")
        with tempfile.TemporaryDirectory(prefix="metal-archive-mnemonic-test.") as directory:
            derivations = pathlib.Path(directory) / "derivations.txt"
            derivations.write_text(
                "".join(f"m/44'/0'/0'/0/{index}\n" for index in range(8192)),
                encoding="utf-8",
            )
            result = self.run_strict(
                [
                    "-mnemonic",
                    "-i",
                    str(ROOT / "tests" / "fixtures" / "chia" / "mnemonics.txt"),
                    "-d",
                    str(derivations),
                    "-d-type",
                    "bip32",
                    "-c",
                    "c",
                    "-hash",
                    "6e3fe756cb32053a9f1096ae82f17b0a5a3ab3ad",
                    "-save",
                ],
                timeout=600,
            )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=output)
        self.assertNotIn("XPC_ERROR_CONNECTION_INTERRUPTED", output)
        self.assertNotIn("metalErrorUnknown", output)
        self.assertIn("Loaded 8192 derivations from the file", output)
        self.assertIn("Metal binary archive selected: __metarc26", output)
        self.assertIn(
            "Metal binary archive hit: worker "
            "(worker_v16_0_2_compressed_bip32)",
            output,
        )

    def test_bip38_non_ec_profile_hits_embedded_archive_in_strict_mode(self):
        self.assert_bip38_archive_hit(
            ROOT / "tests" / "fixtures" / "bip38" / "non-ec.txt",
            "TestingOneTwoThree",
            "workerBip38Grouped_v16_0_1_non_ec",
        )

    def test_bip38_ec_profile_hits_embedded_archive_in_strict_mode(self):
        self.assert_bip38_archive_hit(
            ROOT
            / "tests"
            / "fixtures"
            / "bip38"
            / "ec-multiply-lot-sequence.txt",
            "MOLON LABE",
            "workerBip38Grouped_v16_0_1_ec",
        )

    def assert_bip38_archive_hit(self, targets, password, specialized_name):
        self.assertTrue(BINARY.is_file(), "build bin/METAL_CRYPTO_TOOLKIT first")
        with tempfile.TemporaryDirectory(prefix="metal-archive-runtime-test.") as directory:
            passwords = pathlib.Path(directory) / "passwords.txt"
            passwords.write_text(password + "\n", encoding="utf-8")
            result = self.run_strict(
                [
                    "-bip38",
                    str(targets),
                    "-i",
                    str(passwords),
                    "-wallet-scrypt-mem",
                    "64",
                    "-n",
                    "1",
                ],
                timeout=600,
            )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, msg=output)
        self.assertNotIn("XPC_ERROR_CONNECTION_INTERRUPTED", output)
        self.assertIn(
            f"Metal binary archive hit: workerBip38Grouped ({specialized_name})",
            output,
        )


if __name__ == "__main__":
    unittest.main()
