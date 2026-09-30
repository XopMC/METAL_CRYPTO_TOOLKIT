import collections
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(os.environ.get("METAL_ARCHIVE_TEST_BINARY", ROOT / "bin/METAL_CRYPTO_TOOLKIT")).resolve()
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Public BIP39/BIP44 vector: m/44'/0'/0'/0/0 -> 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA.
HASH160 = "d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa"


class SmallBatchRuntimeTests(unittest.TestCase):
    def run_cli(self, args, directory, small_batch=True, extra_env=None):
        environment = os.environ.copy()
        environment.pop("METAL_REQUIRE_BINARY_ARCHIVE", None)
        environment["METAL_SMALL_BATCH"] = "1" if small_batch else "0"
        if extra_env:
            environment.update(extra_env)
        result = subprocess.run([str(BINARY), *map(str, args)], cwd=directory,
                                env=environment, text=True, capture_output=True, timeout=600)
        return result, result.stdout + result.stderr

    def inputs(self, directory):
        phrases = directory / "mnemonics.txt"
        paths = directory / "derivations.txt"
        phrases.write_text((MNEMONIC + "\n") * 65, encoding="utf-8")
        paths.write_text("".join(f"m/44'/0'/0'/0/{i}\n" for i in range(100)), encoding="utf-8")
        return ["-mnemonic", "-i", phrases, "-d", paths, "-d-type", "bip32"]

    def assert_success(self, result, output):
        self.assertEqual(result.returncode, 0, output)
        self.assertNotIn("Metal runtime error", output)
        self.assertNotIn("metalErrorUnknown", output)

    def test_mnemonic_results_survive_batch_boundaries_and_explicit_overrides(self):
        with tempfile.TemporaryDirectory(prefix="metal-small-batch.") as temporary:
            directory = pathlib.Path(temporary)
            args = self.inputs(directory) + ["-c", "c", "-hash", HASH160, "-save", "-b", "1"]
            results = []
            for threads in (None, 4):
                output_file = directory / f"found-{threads}.txt"
                command = args + ["-o", output_file]
                if threads is not None:
                    command += ["-t", str(threads)]
                result, output = self.run_cli(command, directory)
                self.assert_success(result, output)
                self.assertIn(f"1 threadgroups x {threads or 32} threads", output)
                self.assertIn("Processed 65 lines.", output)
                matches = [line for line in output_file.read_text().splitlines()
                           if ":COMPRESSED:1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA" in line]
                self.assertEqual(len(matches), 65, output)
                results.append(collections.Counter(matches))
            self.assertEqual(results[0], results[1])

    def test_issue3_bloom_command_finishes_multiple_small_batches(self):
        with tempfile.TemporaryDirectory(prefix="metal-small-batch-bloom.") as temporary:
            directory = pathlib.Path(temporary)
            bloom = directory / "filter.blf"
            with bloom.open("wb") as stream:
                stream.truncate(536870912)
            result, output = self.run_cli(
                self.inputs(directory) + ["-bf", bloom, "-b", "1"], directory)
            self.assert_success(result, output)
            self.assertIn("Loaded bloom filters on GPU 0: 1", output)
            self.assertIn("Processed 65 lines. Found: 0.", output)

    def test_mnemonic_launch_failure_returns_nonzero(self):
        with tempfile.TemporaryDirectory(prefix="metal-launch-error.") as temporary:
            directory = pathlib.Path(temporary)
            result, output = self.run_cli(
                self.inputs(directory) + ["-c", "c", "-hash", HASH160, "-b", "1", "-t", "2048"], directory)
            self.assertEqual(result.returncode, 1, output)
            self.assertIn("Metal launch requested 2048 threads", output)

    def test_archive_failure_returns_nonzero_for_mnemonic(self):
        with tempfile.TemporaryDirectory(prefix="metal-archive-error.") as temporary:
            directory = pathlib.Path(temporary)
            result, output = self.run_cli(
                self.inputs(directory) + ["-c", "c", "-hash", HASH160], directory,
                extra_env={"METAL_DISABLE_BINARY_ARCHIVE": "1", "METAL_REQUIRE_BINARY_ARCHIVE": "1"})
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn("Metal binary archive is required but disabled", output)

    def test_priv_random_uses_small_batch_and_makes_progress(self):
        with tempfile.TemporaryDirectory(prefix="metal-small-batch-priv.") as temporary:
            directory = pathlib.Path(temporary)
            environment = os.environ.copy()
            environment["METAL_SMALL_BATCH"] = "1"
            process = subprocess.Popen(
                [str(BINARY), "-priv", "-random", "-start", "1", "-end", "ff", "-n", "128",
                 "-c", "c", "-hash", "00112233445566778899aabbccddeeff00112233", "-bit", "16"],
                cwd=directory, env=environment, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = process.communicate(timeout=20)
                self.fail(f"Continuous random mode exited unexpectedly: {process.returncode}\n{stdout}{stderr}")
            except subprocess.TimeoutExpired:
                # -n bounds each random walk, not the continuous outer loop.
                process.terminate()
                stdout, stderr = process.communicate(timeout=30)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            output = stdout + stderr
            self.assertNotIn("Metal runtime error", output)
            self.assertNotIn("metalErrorUnknown", output)
            self.assertIn("Metal small-batch compatibility profile", output)
            self.assertRegex(output, r"T:\[[1-9][0-9]*\]")


if __name__ == "__main__":
    unittest.main()
