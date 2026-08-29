# METAL_CRYPTO_TOOLKIT v16.0.2

v16 is the largest functional update to the Metal toolkit so far. It adds a
shared checked scheduler and memory/progress infrastructure, completes several
existing wallet formats, introduces new GPU search and recovery modes, and
retains the optimized BSGS and Kangaroo engines from v15.

## v16.0.2 M1/Sequoia worker hot-fix

- The Apple7 translator/runtime compiler failed while lowering the generic
  mnemonic-file `worker`: it attempted to legalize a 32-bit atomic result-count
  load directly as 64-bit and ended with `Compiler encountered an internal
  error` / `metalErrorUnknown`.
- The result counter still uses two atomic 32-bit words, but now packs them with
  an exact bit-cast. This preserves the full 64-bit value and avoids the failing
  compiler transformation.
- The compressed-BIP32 `worker` specialization is now precompiled together with
  the existing HMAC and two BIP38 profiles for all 11 Apple Silicon GPU slices.
  Separate embedded archives target macOS 15 and macOS 26, and the runtime
  selects the matching one so Sequoia compatibility does not regress Tahoe.
- Search logic and steady-state throughput are unchanged. The counter code runs
  only when a result is stored; the native archive avoids first-run pipeline
  JIT. The failing Apple7 translation and the fixed 11-slice archive were
  reproduced locally, and runtime tests passed on M4 Max. Direct M1 validation
  remains pending from the issue reporter because no M1 host is available
  locally.

## v16.0.1 Tahoe/M1 pipeline hot-fix

- Three affected pipeline specializations are precompiled into a Tahoe 26
  Metal binary archive: compressed-BIP32 `workerHmac_seq`, BIP38 non-EC
  `workerBip38Grouped`, and BIP38 EC-multiply `workerBip38Grouped`.
- The executable embeds native payloads for all 11 Apple Silicon GPU slices
  supported by the translator, including the M1/Apple7 `applegpu_g13*`
  variants. Exact matches use `MTLComputePipelineDescriptor.binaryArchives`
  and avoid the failing first-run pipeline JIT path.
- The existing AIR 2.6/macOS 14 metallib remains the fallback for every other
  pipeline and for archive misses on a different Metal runtime.
- Steady-state kernel work and dispatch are unchanged. The archive adds about
  48 MB to the executable; all three strict archive hits passed on M4 Max.
  Direct M1 confirmation remains pending from the issue reporter.

## v16 AIR compatibility change

- The embedded Metal library now targets macOS 14 and AIR 2.6 while the host
  executable continues to require macOS 15.0 or newer.
- This addresses `MTLCompilerService` terminating with
  `XPC_ERROR_CONNECTION_INTERRUPTED` during first-time pipeline compilation on
  M1/Apple7 GPUs. CLI behavior and kernel logic are unchanged.

## Highlights

- New GPU modes: `-keyrepair`, `-nonce`, `-vanity`, `-create2`, `-hdpath`,
  `-warpwallet`, `-substratewallet`, `-copaywallet`, `-terrawallet`,
  `-bitshareswallet`, `-yoroiwallet`, `-monero`, `-monerowallet`,
  `-algorand`, `-stronghold`, `-chia`.
- Completed modes and extensions: exact BIP38 non-EC/EC-multiply recovery,
  `-priv -hamming`, `-mnemonic -scramble`, historical `-brain` profiles,
  SLIP-39, aezeed and ETH2 validator recovery.
- A shared Apple-arm64 BLS12-381 backend is used by ETH2 and Chia.
- BIP38 non-EC and EC-multiply use an isolated grouped Metal kernel, avoiding
  resource interference from the larger shared Substrate/Cardano wallet path.
- Independent BIP38 KDF groups share a memory-bounded launch so available
  scrypt lanes execute concurrently instead of as serial command buffers.
- New wallet modes use checked U256/mixed-radix scheduling, bounded unified
  memory, streaming targets/artifacts and full independent result
  verification.
- `SpeedThreadFunc` remains the only live statistics writer. Target count is
  never used as an artificial throughput multiplier.
- The main executable embeds its Metal library and requires Apple Silicon and
  macOS 15.0 or newer.

## Wave acceptance summary

Every production wave passed exact CPU/reference versus Metal checks, malformed
and boundary cases, its mode-specific controls, and the existing private-key
and P2WSH controls. M3 validation was intentionally skipped by project
direction.

| Wave | Production result | Performance disposition |
|---:|---|---|
| 0 | Shared progress, memory and checked scheduling | Infrastructure regression passed |
| 1 | Exact BIP38 non-EC and EC-multiply | Memory-derived resident tuning accepted |
| 2 | Checksum-first key repair | Host Base58 prefix-state optimization accepted |
| 3 | ECDSA and BIP340 nonce recovery | Group-8 point batching accepted |
| 4 | Multi-network vanity generation | Intra-thread walk and depth 8 accepted |
| 5 | Ethereum CREATE2 | Correct 128-thread baseline retained; tested rewrites rejected |
| 6 | BIP32 HD path search | Root-public reuse and 256-thread grid accepted |
| 7 | Exact Hamming private-key search | Correct baseline retained; tested rewrites rejected |
| 8 | BIP39 mnemonic scramble | Three-limb hardware small-division path accepted |
| 9 | WarpWallet profile engine | Exact streamed baseline accepted |
| 10 | Brainwallet profiles, rules and combinators | Exact streamed baseline accepted |
| 11 | Substrate keyring recovery | Exact authenticated baseline accepted |
| 12 | Copay/BitPay SJCL recovery | Shared AES round-key path accepted |
| 13 | Terra Station legacy export recovery | Exact authenticated baseline accepted |
| 14 | BitShares 0.x exported-key recovery | Exact authenticated baseline accepted |
| 15 | Yoroi/EMIP-3 recovery | Exact authenticated baseline accepted |
| 16 | Monero mnemonic and Polyseed recovery | Exact target-verified baseline accepted |
| 17 | Monero `.keys` recovery | Exact CryptoNight/ChaCha baseline accepted |
| 18 | Algorand mnemonic recovery | Fused resident-target path accepted |
| 19 | SLIP-39 recovery | Fused path: +9.14%/+9.57% |
| 20 | LND aezeed recovery | Memory-derived residency: +38.39%/+38.17% |
| 21 | Stronghold v2 recovery | Argon2 address-block reuse: about +100%/+97.8% |
| 22 | Shared BLS12-381 backend | arm64 assembly: +535.54%/+536.49% |
| 23 | ETH2 validator recovery | Metal KDF pipeline: +3214.38%/+3212.28% |
| 24 | Chia recovery | Metal plus parallel BLS: +72.87%/+72.71% |
| 25 | v16 regression, BIP38 isolation and packaging | BIP38 grouped concurrency: +93.84%/+93.70% |

The percentages compare each accepted candidate with both surrounding A1/A2
baselines under the project's symmetric benchmark gate. New-mode baselines
without an older production entry point were compared with an independent
reference implementation.

Wave 25's BIP38 gate used 11 exact runs per A1/B/A2 group. Median wall times
were 9.948247 s, 5.132319 s and 9.941461 s; population CV was 0.044%, 0.123%
and 0.106%. All 33 runs recovered both official non-EC vectors with the same
SHA-256 output.

## Compatibility and limitations

- CLI compatibility for existing modes is preserved.
- BSGS and Kangaroo keep their `GStep/s`/`EqKey/s` and
  `Jump/s`/`EqKey/s` meanings.
- Full 256-bit arithmetic support does not make exhaustive 256-bit searches
  practically feasible.
- Recovery modes report a result only after full cryptographic verification.
- Use the toolkit only with keys, wallets and data that you own or are
  explicitly authorized to recover.

## Release files

- `METAL_CRYPTO_TOOLKIT-v16.0.2-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-v16.0.2-macos-arm64.tar.gz.sha256`
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz.sha256`

The tools archives are unchanged from v16 and are not republished in the
v16.0.2 release.

Verify each archive with `shasum -a 256 -c FILE.sha256` before extraction.
