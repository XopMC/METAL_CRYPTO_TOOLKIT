# <img src="assets/apple.svg" alt="Apple" width="32" height="32"> METAL_CRYPTO_TOOLKIT <img src="assets/apple.svg" alt="Apple" width="32" height="32">

<p align="center">
  <a href="#english"><strong>English</strong></a> |
  <a href="#russian"><strong>Русский</strong></a>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS%2015%2B-111827?style=for-the-badge">
  <img alt="Architecture" src="https://img.shields.io/badge/architecture-Apple%20Silicon-0f766e?style=for-the-badge">
  <img alt="GPU API" src="https://img.shields.io/badge/GPU-Metal%203-2563eb?style=for-the-badge">
  <img alt="Version" src="https://img.shields.io/badge/version-v16-b45309?style=for-the-badge">
  <a href="#support-the-project"><img alt="Sponsor" src="https://img.shields.io/badge/Sponsor-Support%20development-EA4AAA?style=for-the-badge&amp;logo=githubsponsors&amp;logoColor=white"></a>
</p>

Author: Mikhail Khoroshavin, also known as **XopMC**

<a id="english"></a>

## English

### Changelog

#### v16

Wave 0 establishes the shared infrastructure used by the new GPU modes:

- `ModeProgress` feeds the existing `SpeedThreadFunc`, which remains the only
  statistics printer;
- checked U256 scheduling and a unified-memory budget helper cover `auto`,
  `all`, percentages, MiB/GiB sizes, selected-device replicas, and Metal
  working-set limits;
- device reporting now includes recommended/current working set,
  `maxBufferLength`, and unified-memory capability.

Wave 1 activates exact BIP38 recovery:

- independent non-EC and EC-multiply Metal verification paths implement both
  scrypt stages, AES-256-ECB, lot/sequence handling, secp256k1 derivation, and
  complete P2PKH address-hash verification;
- dictionaries use UTF-8 NFC normalization, while `-hex`, mask, and raw-range
  sources retain exact byte semantics;
- multi-target scheduling is scratch-safe even when the requested active-job
  count is smaller than the number of KDF groups, and result overflow is
  replayed without double-counting completed work;
- `-wallet-mem` provides the common unified-memory ceiling and explicit
  `-wallet-scrypt-mem` values are strict caps.

Wave 2 adds checksum-first GPU key repair:

- `-keyrepair` restores limited unknown Base58 or hexadecimal positions in
  WIF, xprv/xpub, raw secp256k1 private/public keys, and Base58Check address
  payloads;
- the Metal kernels generate candidates, reject invalid structures and
  checksums first, and emit only bounded hits for mandatory host verification;
- mixed-radix U256 scheduling supports the complete advertised 15-position
  domain, and selected Metal devices receive exact non-overlapping shards;
- raw-private repair requires a related public key, while an address repair is
  always reported only as an address payload, never as recovered key material.

Wave 3 adds exact ECDSA/BIP340 nonce recovery:

- `-nonce` accepts repeated signature records or line-oriented files and
  searches bounded intervals, fixed/unknown-bit masks, or exact candidate
  lists produced by an external lattice solver;
- the Metal kernel reconstructs `R=kG` with explicit precompute-window
  parameters and checks ECDSA `r` (including the valid `r+n` lift) or the
  BIP340 even-Y nonce point;
- reused, mirrored, additive, multiplicative, and affine-related ECDSA nonces
  are solved algebraically before brute-force search;
- every hit is independently checked against the signature equation and full
  public key on the host, while only `SpeedThreadFunc` prints `Nonce/s` and
  `Verify/s`.

Wave 4 adds native Metal vanity-address generation:

- `-vanity` supports BTC compressed/uncompressed P2PKH, nested P2SH-P2WPKH,
  native Bech32 P2WPKH, lowercase Ethereum, and TRON addresses;
- repeatable `-pattern` and streaming `-pattern-file` inputs accept prefixes,
  suffixes, `*` wildcards, and single-character `?` wildcards;
- exact checked U256 intervals, non-repeating random rotation, multi-device
  scheduling, and split-key generation cover the complete requested domain
  without overlap;
- GPU hits are recomputed from the scalar and fully encoded on the host before
  output, while the common `SpeedThreadFunc` remains the only `Key/s` printer.

Wave 5 adds deterministic Ethereum CREATE2 salt search:

- `-create2` evaluates the exact EIP-1014 preimage
  `0xff || deployer || salt || init_code_hash` in a dedicated Metal kernel;
- repeatable patterns and pattern files support lowercase hexadecimal
  prefixes, suffixes, `*`, and single-character `?` matching;
- direct U256 salt intervals and 64-nibble templates enumerate without gaps,
  while finite random mode changes only the cyclic starting point;
- every hit is recomputed with an independent host Keccak implementation, and
  only the shared `SpeedThreadFunc` reports completed `Addr/s`.

The Wave 5 optimization sweep keeps 128 threads per Metal threadgroup as the
production setting. Fixed-state packing, raw-nibble matching, two salts per
thread, and 64/256-thread grids all retained exact output but failed the
required stable gain against both surrounding baselines; none was integrated.

Wave 6 adds checked GPU BIP32 derivation-path search:

- `-hdpath` accepts a BIP39 mnemonic, raw seed, xprv/xpub, or a descriptor
  containing one extended key;
- fixed indexes, inclusive ranges, explicit lists, and finite wildcards are
  combined into one checked U256 mixed-radix domain without materializing the
  paths on the host;
- CKDpriv and non-hardened CKDpub run in a dedicated Metal kernel, while
  hardened descendants from xpub are rejected before launch;
- repeated full-public-key targets and target files are normalized and
  deduplicated, and every Metal hit is independently re-derived on the host;
- the shared `SpeedThreadFunc` remains the only statistics printer and reports
  credited `Path/s`, primitive child derivations, exact verifications, targets,
  working set, and readback time.

The Wave 6 optimization sweep accepted two sequential improvements. Reusing
the already available root public key for the first non-hardened CKDpriv edge
reduced median wall time by **39.26%/39.20%** against the surrounding
baselines. The following measured grid tune selected 256 threads per Metal
threadgroup, reducing the accepted baseline from 1.4452/1.4399 s to 0.23679 s
on the 16,777,216-path workload (**83.62%/83.55%**, 1.168% CV, 0.368%
baseline drift). Boundary targets around both 128- and 256-thread group edges
were recovered with full host re-derivation before integration.

Wave 7 adds exact Hamming-distance private-key search:

- `-priv -hamming BASE:DISTANCE[:MUTABLE_MASK]` enumerates the exact
  combinatorial sphere around one 256-bit base scalar; mask zeroes keep fixed
  bits and mask ones select the positions eligible for toggling;
- a checked U256 combinadic rank/unrank mapping assigns every candidate once,
  without materializing combinations or introducing duplicates;
- `-start/-end` select an exact ordinal subrange and selected Metal devices
  receive consecutive non-overlapping windows;
- repeated full secp256k1 public-key targets and target files are canonicalized
  and deduplicated, while every GPU hit is independently unranked, re-derived,
  and verified on the host;
- the common `SpeedThreadFunc` is the only live printer and reports credited
  `Key/s`, primitive scalar multiplications, exact verifications, targets,
  working set, and readback time.

Wave 8 adds checksum-first BIP39 permutation search:

- `-mnemonic -scramble` accepts inline phrases or streaming phrase files and
  enumerates unique multiset permutations without materializing them;
- fixed positional words reduce the permutation domain, while `*` and
  `{word|word}` patterns provide unrestricted and restricted positions;
- a checked U256 scheduler, exact multi-device interval splitting, adaptive
  overflow replay, and `-wallet-mem` cover large domains and unified memory;
- Metal performs multiset rank/unrank and BIP39 checksum pruning before the
  established seed/derivation/target pipeline;
- `SpeedThreadFunc` remains the only live printer and reports credited
  `Candidate/s`, exact verifications, working set, and readback time.

Wave 9 adds historical memory-hard brainwallet profiles:

- `-warpwallet` implements exact WarpWallet, brainwallet.io, Brainv2, and
  RushWallet derivation pipelines in Metal rather than approximating them
  with the ordinary `-brain` hash modes;
- dictionaries are consumed in bounded streaming windows, while repeated
  hash160/P2PKH targets are normalized, deduplicated, sorted, and uploaded in
  shards smaller than both the selected memory budget and `maxBufferLength`;
- the expensive KDF and secp256k1/hash160 calculation run once per password;
  target shards perform only exact lookup, so target count never multiplies
  the reported KDF work;
- Brainv2 uses separate first, parallel middle, last, and finalize kernels.
  RushWallet accepts either the prefix through `!` or the complete fragment
  with its ten-hex-character early-rejection checksum;
- every Metal hit receives independent host secp256k1/hash160 verification,
  overflowed hit batches are replayed without double credit, and the common
  `SpeedThreadFunc` remains the only live `KDF/s` printer.

Wave 10 extends the ordinary fast `-brain` path:

- `-brain-profile` gives stable names to historical SHA-256 aliases and to
  binary/hex double-hash, SHA3-256, Keccak-256, BLAKE2b-256, and raw profiles;
- `-brain-rules FILE` compiles the commonly used hashcat rule core once,
  removes duplicate rules, and applies the resulting bounded transformations
  before the existing Metal hash/secp256k1 pipeline;
- `-brain-combine FILE` adds `lr`, `rl`, or `both` dictionary concatenation,
  with optional `-space`; the logical cross-product is produced through
  backpressured streaming rather than materialized as a second dictionary;
- right dictionaries up to 64 MiB are resident and larger files are replayed
  as bounded streams, while candidate overflow or invalid rule positions are
  explicitly counted instead of silently truncated;
- expanded candidates retain the established exact target filters, found
  format, multi-device dispatch, and the single common `SpeedThreadFunc`.

Wave 11 adds authenticated Substrate keyring recovery:

- `-substratewallet` loads version 2/3 Polkadot/Substrate keyring JSON and
  validates its PKCS8, curve, SS58/hex identity, encoded layout, and scrypt
  parameters before launching Metal;
- version 3 uses grouped scrypt followed by XSalsa20-Poly1305; version 2 uses
  the exact legacy 32-byte password-key rule;
- authenticated plaintext is accepted only after PKCS8 header/divider checks,
  an exact stored-public-key match, and independent secret-to-public
  regeneration for sr25519, ed25519, or secp256k1 ECDSA;
- targets sharing curve-independent KDF parameters reuse one scrypt result,
  ciphertexts are kept in a compact pool, and `-wallet-mem`/`-wallet-scrypt-mem`
  bound the actual unified-memory working set;
- only the common `SpeedThreadFunc` prints live `KDF/s` and `Verify/s`.
  `KDF/s` counts completed password/KDF-group jobs, never target count.

Wave 12 adds authenticated Copay/BitPay backup recovery:

- `-copaywallet` loads one or more versioned SJCL JSON backups directly or
  scans a directory, rejecting unsupported parameters before Metal work;
- the supported production profile is the Copay/BitPay SJCL default:
  PBKDF2-HMAC-SHA256 with 10,000 iterations, AES-128-CCM, a 64-bit tag,
  empty associated data, and the exact SJCL 13-byte nonce clamp;
- backups with identical salt and iteration count share one KDF result, while
  compact ciphertext storage and target windows keep large artifact sets
  within `-wallet-mem`;
- every reported password has passed the complete AES-CCM authentication tag
  comparison on Metal; malformed or merely decryptable plaintext is never
  accepted;
- only the common `SpeedThreadFunc` prints live `KDF/s` and `Verify/s`, and
  neither rate is inflated by the number of artifacts.

Wave 13 adds strict legacy Terra Station export recovery:

- `-terrawallet` accepts the historical mobile exported-key JSON either
  directly or wrapped in the original outer Base64 representation;
- the loader requires `name`, a checksum-valid `terra1...` address with a
  20-byte payload, and the exact `encrypted_key` salt/IV/ciphertext layout;
- Metal performs PBKDF2-HMAC-SHA1 with 100 iterations, AES-256-CBC/PKCS7,
  strict 64-character private-key decoding, secp256k1 public-key regeneration,
  and an exact address HASH160 comparison;
- targets sharing the same salt reuse one KDF result, compact ciphertext
  pooling remains bounded by `-wallet-mem`, and only the common
  `SpeedThreadFunc` prints completed `KDF/s` and actual `Verify/s`;
- unknown Terra formats, mnemonics, hardware-wallet records, malformed
  checksums, and unauthenticated plaintext heuristics are rejected.

Wave 14 adds exact BitShares 0.x exported-key recovery:

- `-bitshareswallet` loads the official `exported_keys` JSON schema with its
  password checksum and parallel encrypted-private/public-key arrays;
- the loader validates every BTS/BTSX Base58 public-key payload and its
  RIPEMD-160 checksum before Metal work, and deduplicates repeated key records;
- Metal computes `SHA512(password)` once per checksum group, verifies the
  stored `SHA512(password_key)`, decrypts AES-256-CBC/PKCS7 with the derived
  key and IV, validates the private scalar, and regenerates the exact
  compressed secp256k1 public key;
- keys sharing one `password_checksum` reuse the same SHA-512 result, compact
  target/ciphertext storage remains inside `-wallet-mem`, and only the common
  `SpeedThreadFunc` prints completed `KDF/s` and actual `Verify/s`;
- arbitrary wallet-database records, watch-only entries, invalid key
  checksums, malformed arrays, and unknown future containers are rejected.

Wave 15 adds authenticated Yoroi IndexedDB / EMIP-3 recovery:

- `-yoroiwallet` loads the actual Yoroi `Key` and `KeyDerivation` IndexedDB
  tables and follows only the exact root -> `1852'` -> `1815'` -> `account'`
  chain to its stored BIP32-Ed25519 account xpub;
- the loader requires an encrypted 156-byte EMIP-3 root record, a 64-byte
  account xpub, and the exact salt32/nonce12/tag16/ciphertext96 layout;
- Metal performs PBKDF2-HMAC-SHA512 with 19162 iterations, verifies the
  ChaCha20-Poly1305 tag, decrypts the 96-byte root xprv, and regenerates both
  the account public key and chain code through hardened CIP-1852 derivation;
- roots sharing the same salt reuse one grouped KDF result, compact metadata
  and pooled ciphertext stay inside `-wallet-mem`, and only the common
  `SpeedThreadFunc` prints completed `KDF/s` and actual `Verify/s`;
- mnemonic recovery, hardware signers, watch-only roots, malformed tables,
  unauthenticated plaintext, and unknown future containers are rejected.

Wave 16 adds checksum-first Monero mnemonic recovery:

- `-monero` accepts repeatable 25-word legacy and 16-word Polyseed phrases or
  line-oriented files; a standalone `?` marks one unknown whole word;
- all official Monero legacy and Polyseed language lists are embedded, with
  exact prefix matching, legacy CRC32 checksum pruning, and Polyseed
  GF(2^11) checksum decoding before expensive derivation;
- Metal derives the recovery key, canonical private spend/view scalars, and
  both Ed25519 public keys once per candidate, then streams sorted target
  tiles for exact lookup without multiplying KDF work by target count;
- standard, integrated, and subaddress targets are checksum-validated, while
  repeated targets retain every source occurrence and each hit is
  independently re-derived with the official Monero ref10 host code;
- `-wallet-mem` bounds the unified-memory working set, overflowed hit batches
  replay without double credit, and only the common `SpeedThreadFunc` prints
  completed `Candidate/s`, primitive work, and actual `Verify/s`;
- encrypted Polyseed features, malformed phrases, unsupported address
  prefixes, and merely checksum-valid phrases without an exact target match
  are never reported as recovered wallets.

Wave 17 adds version-aware Monero `.keys` password recovery:

- `-monerowallet` accepts repeatable modern or legacy software-wallet `.keys`
  containers and password literals/files through `-pass` or `-i`;
- Metal executes the full CryptoNight-v0 slow hash with one 2 MiB scratchpad
  per active lane, including the Keccak/AES mixing pipeline and exact
  Blake/Groestl/JH/Skein final selector;
- modern ChaCha20 JSON and legacy ChaCha8 portable-account payloads are parsed
  independently, while encrypted spend/view secrets receive the required
  `CryptoNight(base_key || 'k')` memory key;
- every result requires canonical private scalars and exact spend/view public
  keys regenerated with Monero ref10 arithmetic; malformed, unknown, hardware,
  and custom-background-password profiles are not guessed;
- `-wallet-mem` bounds all CryptoNight scratch, automatic concurrency backs
  off after allocation failure, explicit `-n` remains strict, and the common
  `SpeedThreadFunc` alone reports completed `KDF/s` and real verification work.

Wave 18 adds checksum-first Algorand mnemonic recovery:

- `-algorand` accepts repeatable standard 25-word English phrases, inline
  templates, or line-oriented files; a standalone `?` or `*` marks an unknown
  whole word, and `-scramble` enumerates unique multiset permutations;
- the checked U256 scheduler maps every unknown-word or permutation ordinal
  exactly once, enforces the restricted final data word, and derives the
  SHA-512/256 checksum word before the expensive Ed25519 operation;
- repeatable 58-character Algorand addresses, raw 32-byte public keys, and
  target files are checksum-validated, normalized, and deduplicated while
  retaining every source occurrence;
- a fused Metal derive/lookup path is selected when the complete target tile
  is resident; larger target sets use split derivation and bounded target
  tiles so Ed25519 work is reused rather than multiplied by target count;
- every hit is independently reconstructed and checked with host
  SHA-512/256, Ed25519, and canonical address encoding before output;
- `-wallet-mem` bounds the unified-memory working set, overflowed hit batches
  replay without double credit, and only the common `SpeedThreadFunc` reports
  completed `Candidate/s`, primitive work, real `Verify/s`, target residency,
  readback, and allocated memory.

The Wave 18 fused pipeline passed the symmetric 4,194,304-candidate gate at
0.466967 s median versus 0.524247/0.525286 s for the surrounding split
baselines: **+12.27%/+12.49%**, with 0.906% population CV. The split path
remains automatic for target sets larger than the resident tile.

Wave 19 completes exact SLIP-0039 recovery:

- `-slip39` parses the official English share format, checks RS1024, enforces
  common/group/member metadata, and reconstructs both Shamir levels with the
  required digest shares;
- `?` and `*` repair up to two damaged words per share without materializing
  the complete word-product; checksum-valid alternatives are combined under a
  strict one-million-combination safety ceiling;
- Metal searches printable-ASCII passphrases with the exact four-round
  Feistel construction and PBKDF2-HMAC-SHA256 iteration exponent, then matches
  `SHA256(master-secret)` targets;
- resident target sets use fused decrypt/lookup, while larger sets decrypt
  once and reuse the derived secret/digest across bounded target tiles;
- every GPU hit is independently decrypted and hashed with CommonCrypto
  before output; `-wallet-mem` bounds unified memory and only the shared
  `SpeedThreadFunc` reports completed `Pwd/s`, primitive work, and `Verify/s`.

Wave 20 adds exact LND aezeed recovery:

- `-aezeed` decodes the standard 24-word English cipherseed, validates its
  external version and CRC32C before launching Metal, and can repair up to two
  unknown whole words marked with `?` or `*`;
- the Metal worker performs the exact v0 scrypt parameters
  `N=32768,r=8,p=1`, the AEZ-v5 fixed 23-byte decipher operation, tag check,
  and known internal-version/birthday extraction;
- recovery can be verified by exact entropy, `SHA256(entropy)`, or the
  compressed/uncompressed secp256k1 public key of the BIP32 master derived
  from the 16-byte LND entropy;
- every hit is independently AEZ-deciphered again and receives full BIP32
  root-public verification on the host before output;
- `-wallet-mem` and `-wallet-scrypt-mem` bound resident 32 MiB ROMix lanes,
  multi-device batches do not overlap, and only the common
  `SpeedThreadFunc` reports completed `KDF/s`, real verification, readback,
  and allocated working set.

Wave 21 adds version-aware IOTA/Tauri Stronghold snapshot recovery:

- `-stronghold` strictly accepts the public `PARTI` snapshot header and version
  `02 00`; unknown versions and malformed files are rejected before Metal;
- the named `blake2b`, Stronghold/rust-argon2 default `argon2id`, and published
  Tauri example `tauri-argon2id` profiles are explicit because a snapshot does
  not encode its application KDF or external salt;
- Metal implements Blake2b-256 and exact Argon2id v19, including multi-lane
  filling; one generated address block is reused across its 128 references;
- every candidate key is independently checked through host X25519,
  XChaCha20-Poly1305 authentication, exact Stronghold LZ4 decompression, and an
  optional `SHA256(plaintext)` target before output;
- salt files are always treated as raw bytes, while an inline salt is hex;
  `-wallet-mem` bounds sharded unified-memory scratch and only the common
  `SpeedThreadFunc` reports completed `KDF/s`, verification, readback, and the
  actual working set.

Wave 22 adds the shared BLS12-381 backend:

- portable scalar arithmetic, EIP-2333 key generation, compressed G1 public
  keys and strict subgroup validation are shared by validator and Chia modes;
- the arm64 assembly backend is selected automatically when available, while
  the portable C implementation remains the correctness reference;
- official vectors cover EIP-2333/EIP-2334, compressed-key parsing, infinity
  rejection and CPU backend parity. This is an infrastructure wave and does
  not add a standalone CLI route.

Wave 23 adds exact Ethereum validator recovery:

- `-eth2validator` recovers EIP-2335 v4 passwords for PBKDF2 and scrypt
  keystores, including AES-128-CTR decryption and complete BLS public-key
  verification;
- its derivation contour checks checksum-valid English BIP39 mnemonics or raw
  seeds through EIP-2333 and exact EIP-2334 paths;
- target files are deduplicated without losing source identity, candidate
  domains are streamed inside `-wallet-mem`, and only the common
  `SpeedThreadFunc` reports completed `KDF/s`, verification and readback.

Wave 24 adds exact Chia key recovery:

- `-chia` checks English BIP39 mnemonic/passphrase candidates or raw seeds
  against compressed BLS keys, 32-byte puzzle hashes and checksum-valid
  `xch`/`txch` addresses;
- farmer, pool, wallet, observer, local, backup, singleton and pool-auth path
  profiles use Chia's historical BLS KeyGen v3 and exact hardened/unhardened
  child derivation;
- standard-wallet puzzle hashes reproduce
  `p2_delegated_puzzle_or_hidden_puzzle`, including the signed synthetic-key
  offset and canonical default hidden puzzle;
- PBKDF2-HMAC-SHA512 runs in bounded Metal batches, exact host BLS verification
  is distributed across available CPU cores, and only the common
  `SpeedThreadFunc` reports completed `KDF/s`, primitive work, targets,
  readback and actual working set.

Wave 25 closes the v16 release candidate and full regression:

- the production binary is arm64-only, declares macOS 15.0, embeds its
  `metallib`, and is packaged reproducibly with bilingual release notes,
  companion tools and separate SHA-256 files;
- detailed help is symmetric in both argument orders, and the release
  regression covers BSGS, Kangaroo `compact170`/`wide256`, wallet modes,
  BLS12-381, Ill Bloom PRNG, default auto-grid and P2WSH;
- BIP38 now uses an isolated grouped Metal kernel. This restores exact non-EC
  and EC-multiply recovery after the larger shared wallet kernel gained
  Substrate/Cardano paths, without changing the other wallet pipelines;
- independent BIP38 groups now share one memory-bounded launch and occupy the
  available scrypt lanes concurrently. The exact two-target non-EC regression
  improved from 9.948/9.941 s (A1/A2) to 5.132 s median on M4 Max
  (+93.835%/+93.703% throughput, 0.123% CV).

A cross-wave PRNG compatibility update tracks the current CUDA catalog:

- `-prng` now includes Ill Bloom generators `332..489` and modes `247..762`,
  covering source/runtime variants plus exhaustive chain/output sign masks;
- `-prng64` generators `221..223` expose compact, non-overlapping packed
  ordinal spaces for fixed signs, runtime profiles, and raw byte lanes;
- mode `218` emits direct source bytes, packed bounds are validated on the
  host, and Metal golden tests compare the CUDA vectors and all 32-byte masks.

#### v15

The July 25 update extends both interval-DLP modes for very large target
families:

- BSGS now streams bounded target tiles instead of keeping the complete input
  resident, and `-random` uses a seeded, non-repeating permutation of all giant
  groups. `-bsgs-random-seed` reproduces the traversal exactly.
- `-bsgs-shifts START:COUNT[:STEP]` represents up to 64-bit-sized arithmetic
  families `Q-(START+i*STEP)G` without expanding millions of public keys in
  memory.
- Two or more Kangaroo targets automatically select the shared-tame
  multi-target contour. `-kangaroo-mem auto|all|NN%|SIZE` controls its actual
  working-set ceiling without a fixed 16 GiB cap, while resident target windows
  keep physical memory bounded.
- `-kangaroo-shifts START:COUNT[:STEP]` provides the same compact shifted-target
  source for Kangaroo. Shift-derived searches stop after the first fully
  verified hit, and the standard speed thread reports completed work plus
  overlap-aware unique equivalent coverage.

The final shifted first-hit BSGS candidate was accepted on Apple M4 Max with a
median wall-time reduction of **82.96–83.18%** against both surrounding
baseline groups (0.3145 s versus 1.8458/1.8701 s, 2.180% CV). Its sealed
correctness suite covered BSGS and Kangaroo shifted first-hit recovery,
independent multi-target searches, non-repeating randomized BSGS, cyclic
overlap accounting, `compact170`, `wide256`, private 1:1, and P2WSH controls.

The July 24 `-bsgs` update adds a native deterministic Metal BSGS mode:

- one or many compressed/uncompressed secp256k1 public-key targets are accepted
  directly or from files, with the same exact/list/bit-range grammar as
  Kangaroo;
- the negation-map engine combines shared-inversion `P+J`/`P-J` point
  generation, compact exact `fingerprint64 + j` buckets, GPU lookup/resolve,
  full public-point verification, target batching, and overlap-free dynamic
  multi-GPU work claiming;
- `-bsgs-mem` and `-bsgs-table` control unified-memory use and the exact baby
  table size, while versioned checksummed table caching remains explicitly
  opt-in;
- all live statistics are emitted through the standard `SpeedThreadFunc`.
  Search uses names `GStep/s` and `EqKey/s`; the Metal
  negation-map walk reports effective unique coverage as
  `EqKey/s = GStep/s × 2M`.

On Apple M4 Max, the accepted final exact pipeline reduced the width-44,
16-target, `M=2^22` median wall time from 1.100 s to 0.370 s versus the
internal textbook baseline (**66.37% less wall time**, 2.019% CV). A width-56,
one-target control sustained a median **1.130 billion GStep/s** and
**9.476 quadrillion EqKey/s** with no reporting-path throughput regression.

The July 24 `-kangaroo` update adds two independently optimized Metal engines:

- `compact170` is selected automatically for effective interval widths from 32
  through 170 bits. It uses an affine point-only hot walk, a 16-bit hop
  metadata ring, three-limb signed distance replay, and the full SOTA+
  `P+J`/`P-J` selection with eight kangaroos per Metal thread.
- `wide256` is selected for widths from 171 through 256 bits. It keeps the
  split point-walk/replay pipeline while preserving complete signed-256
  distance arithmetic and uses 16 kangaroos per Metal thread.
- Allocation failures select the explicit legacy fallback. The command-line
  syntax, result format, multi-GPU routing, tame cache, and PSWDP2/3/4 readers
  remain compatible.

The following additional gains over the original v15 build were verified on
Apple M4 Max with the default automatic grid,
`METAL_VANITY_GROUP_SIZE=1024`, two warm-ups, and symmetric A1/B/A2 phases
containing 11 measured runs each:

- puzzle-135-shaped `[2^134, 2^135)` with DP44:
  **11.024–11.101% faster** at **380.368 million jumps/s**;
- the full 256-bit control with DP60:
  **4.064–4.065% faster** at **356.467 million jumps/s**.

All primary coefficients of variation remained below 0.3%. A known small
private key was recovered exactly by `compact170`, while `wide256` completed
1,966,080,000 full-range transitions without a replay overflow or mismatch.

The initial v15 release had already verified these gains over its preceding
Kangaroo implementation:

- the true 256-bit-range walk path is **30.654–30.753% faster**;
- the 128-bit-range control is **31.091–31.231% faster**.

#### v14.1

The following performance gains were verified on Apple M4 Max with the default
automatic grid, `METAL_VANITY_GROUP_SIZE=1024`, and paired A1/B/A2 median
measurements. Each range compares the optimized build with both surrounding
baseline measurements:

- `mnemonic`: bounded passphrase fanout for seekable mnemonic inputs is **89.922–89.935% faster**;
- `entropy`: batched `entropy × passphrase` fanout is **92.314–92.317% faster**;
- `minikeys`: the sequential Base58 unit-increment path is **9.530–10.379% faster**;
- `profanity`: reverse recovery with GPU-side hit prefiltering is **10.512–11.779% faster**;
- `poetry`: finite-grid capping and identical-template batching are **20.735–21.324% faster** together;
- `armory`: round-0 compressed public-key emission that reuses the derived child key is **10.170–10.361% faster**.
- `keystore`: adaptive scrypt concurrency on the r=8/256-password profile is **49.499–49.646% faster**;
- `walletdat`: the 4,096-password uniform KDF dictionary profile is **63.039–63.131% faster**;
- `stellarwallet`: AES-GCM verification for 64 KiB payloads is **20.397–20.399% faster**;
- `blockchainwallet`: PBKDF2-SHA1 with reusable HMAC states is **36.971–37.964% faster**;
- `bisqwallet`: the N=1024/r=1 4,096-password scrypt profile is **48.986–49.203% faster**;
- `dogechainwallet`: the 10,000-iteration PBKDF2 profile is **2.111–2.693% faster**;
- `ethpresale`: grouped verification of 608-byte encrypted seeds is **34.941–35.576% faster**;
- `walletscan`: mnemonic-heavy scanning of a 2 GiB text corpus is **14.131–14.187% faster**.

### What this program is

`METAL_CRYPTO_TOOLKIT` is a command-line toolkit for authorized cryptocurrency wallet recovery and key-generation research on Apple Silicon. The computational work runs on the Apple GPU through Metal.

The program can:

- process BIP-39 mnemonics, Poetry brainwallet phrases, entropy, seed bytes, BIP32 master material, derivation paths, BIP-39 passphrases, and several legacy seed formats;
- check secp256k1, ed25519, and sr25519 results for Bitcoin, Ethereum, TON, Solana, Polkadot/Substrate, Cardano, Filecoin, IOTA, Aptos, Sui, XRP, ICP, and Tezos;
- search direct values or large target collections stored in Bloom and XOR filters;
- examine raw private-key ranges, incomplete hexadecimal templates, Casascius minikeys, and known historical generator families;
- recover a secp256k1 private key with `-bsgs` or `-kangaroo` when the complete public key and a bounded scalar interval are known, including multi-target and compact shifted-target searches;
- verify password candidates against supported wallet containers and extracted wallet hashes;
- transfer found records to the output writer without stopping the compute loop for every disk write.

This is not a wallet application and it does not connect to a blockchain. It generates or reads candidates, derives the requested key material, compares the resulting binary values with targets, and records matching values.

### Responsible use

Use this software only with wallets, backups, keys, hashes, and files that belong to you or that you are explicitly authorized to examine. A recovered mnemonic, password, seed, or private key gives access to funds and must be handled as a secret.

Recommended precautions:

- work on an offline or otherwise trusted Mac;
- use copies of wallet files, never the only existing backup;
- keep dictionaries, output files, terminal history, and shell scripts private;
- do not upload real mnemonics, private keys, or recovered passwords to online services;
- test a complicated command on a small known fixture before starting a long search;
- do not run two processes with the same output file unless mixed records are acceptable.

### Licensing

The original toolkit sources retain the MIT license notice in `LICENSE`.
The native Metal `-kangaroo` implementation is adapted from RCKangaroo and is
covered by GNU GPLv3. Builds that include this mode are therefore distributed
under GPLv3. See `COPYING.GPLv3.txt` and `THIRD_PARTY_NOTICES.md`.

### Requirements

#### Ready-to-run v16 release

- Apple Silicon Mac (`arm64`);
- macOS 15.0 or newer;
- a Metal-capable Apple GPU;
- about 425 MB for the unpacked executable;
- additional unified memory according to filters, result capacity, and wallet KDF settings.

The release contains one executable. The Metal library is embedded in its Mach-O data section, so an external `.metallib`, Python, Homebrew package, or source tree is not needed at runtime.

#### Source build

- macOS 15.0 or newer;
- full Xcode;
- the Metal Toolchain component;
- `make`.

### Download, verify, and run

Download these two files from the [v16 release](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v16):

- `METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz.sha256`

The same release also contains the optional address-conversion package:

- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz.sha256`

It is needed only when printable cryptocurrency addresses must be converted into the homogeneous hexadecimal lists accepted by filter builders. It does not contain or replace the main Toolkit executable.

Then run:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz
chmod +x METAL_CRYPTO_TOOLKIT
./METAL_CRYPTO_TOOLKIT -help
```

To install the optional converter package:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz
chmod +x tools/*
tools/cardano_address_to_hex -h
```

The checksum detects a damaged or incomplete download. Because the checksum is distributed with the archive, it is not an independent signature of the publisher. Download both files from the expected private repository and verify the repository account before running the executable.

If macOS blocks the file, remove quarantine only after you have verified where the archive came from:

```bash
xattr -d com.apple.quarantine METAL_CRYPTO_TOOLKIT
```

### Build from source

Select the full Xcode installation and install the Metal compiler if necessary:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -downloadComponent MetalToolchain
```

Build:

```bash
make clean
make -j"$(sysctl -n hw.ncpu)"
```

The final executable is available at both paths:

```text
./METAL_CRYPTO_TOOLKIT
./bin/METAL_CRYPTO_TOOLKIT
```

`build/default.metallib` is an intermediate build product. The Makefile embeds it into the final executable. The default deployment target is macOS 15.0.

The address converters are separate command-line programs. Build all of them without rebuilding the main Toolkit:

```bash
make tools -j"$(sysctl -n hw.ncpu)"
```

Build or clean one converter, or clean the whole set:

```bash
make -C tools/cardano_address_to_hex
make -C tools/cardano_address_to_hex clean
make tools-clean
```

A plain `make` continues to build only `METAL_CRYPTO_TOOLKIT`.

### Help system

Show the main mode list:

```bash
./METAL_CRYPTO_TOOLKIT -h
./METAL_CRYPTO_TOOLKIT -help
```

Show the detailed help for a mode:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -help
./METAL_CRYPTO_TOOLKIT -poetry -help
./METAL_CRYPTO_TOOLKIT -priv -help
./METAL_CRYPTO_TOOLKIT -walletdat -help
./METAL_CRYPTO_TOOLKIT -xp -help
```

Use one main mode per command. If a help command contains several modes, the first recognized one wins.

## Understanding a command

Most key-search commands contain the program name followed by five logical groups:

```text
PROGRAM  MODE  CANDIDATE_SOURCE  TRANSFORMATION_OR_PATH  TARGET  OUTPUT
```

Example:

```bash
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end 1000 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save -o found.txt
```

This command means:

- `-priv`: work with raw private keys;
- `-start 01 -end 1000`: examine the finite hexadecimal range from `0x01` through `0x1000`;
- `-c c`: build the Bitcoin compressed-public-key HASH160 value;
- `-hash ...`: compare all 20 bytes of that HASH160 with the specified fixed value;
- `-save`: convert the matching Bitcoin HASH160 payload to its printable address forms;
- `-o found.txt`: use `found.txt` instead of the default `result.txt`.

In this key-search command, a found record is appended to the output file even without `-save`. Without the flag, the payload remains raw hexadecimal data. With the flag, the same match is printed and written in the address representation supported by its `-c` type. For `-c c`, that includes the Bitcoin P2PKH and P2WPKH forms.

The hexadecimal sequence in this example only demonstrates the command format. Replace it with the actual target value or with the known leading bytes you want to match.

### Three rules that prevent most mistakes

1. `-hash` and the regular Metal filters are global to the command; they are not assigned to individual `-c` letters. Every selected branch checks the same direct prefix and the same OR-combined filter set. Use separate commands when one target set is not meaningful for every selected branch.
2. Filters contain binary values, not human-readable addresses. A Bitcoin address, an Ethereum string beginning with `0x`, a public key, and a HASH160 are different inputs.
3. Number bases are option-specific. In particular, `-step`, `-endstep`, Profanity `-offset`, and many seed/time boundaries are hexadecimal, while `-plusstep`, `-addplusstep`, buffer sizes, and job counts are decimal.

## Candidate sources

### Files, directories, and standard input

| Argument | Exact behavior |
| --- | --- |
| `-i FILE` | Adds a candidate/input file. It can be repeated in modes that accept multiple files. One logical candidate is normally read per line. |
| `-f DIR` | Recursively scans a directory. In ordinary text modes it selects `.txt` files unless `-all` is present. In wallet modes it selects format-specific artifacts. |
| `-all` | With the generic `-f` input wrapper, includes files beyond the normal `.txt` selection. It is not a wallet-artifact switch. |
| standard input | Used only by modes whose dedicated section documents stdin input. Other modes may require artifact files or start an internal range generator. |
| `-hex` | Requests mode-specific hexadecimal candidate handling. Depending on the mode, bytes can be decoded, padded, normalized, or ignored; wallet artifact files themselves are not changed. |
| `-delete` | Deletes each processed input file after that file wrapper completes. This is irreversible and should be used only on disposable copies. |
| `-comb LIST` | Treats each number/range as a candidate word count and emits ordered selections of that many whitespace-separated words from each input file. |
| `-space` | Joins words generated by `-comb` with spaces. |
| `-rep` | Allows the same word position to be selected more than once by `-comb`. |

`-comb`, `-space`, and `-rep` belong to the generic file wrapper. They do not modify standard input, PRNG, sequential, or wallet-mask generators.

### Sequential and random ranges

| Argument | Meaning |
| --- | --- |
| `-start VALUE` | First point. The expected width and encoding depend on the active mode. |
| `-end VALUE` | Last point. If omitted, the mode substitutes its maximum boundary; the resulting search is finite but can be practically inexhaustible. |
| `-step HEX` | Hexadecimal step, default `1`. Thus `-step 10` means decimal 16. |
| `-back` | Walk backward from `-start`. |
| `-both` | Walk in both directions. With two bounds, the positive side starts at `-start` and the negative side at `-end`. |
| `-random` | Select random windows or points inside the mode's domain. |
| `-n N` | Mode-specific work span, launch window, or number of rounds. Its unit is defined by the selected mode. |

`-back` and `-both` should not be combined. If both occur, the last parsed direction switch controls the run.

Private-key sequential mode also accepts a step schedule:

| Argument | Base | Meaning |
| --- | --- | --- |
| `-endstep HEX` | hexadecimal | Final step before the schedule wraps. |
| `-plusstep N` | decimal | Amount added to the current step on the next schedule round. |
| `-addplusstep N` | decimal | Amount added to `plusstep` after an `endstep` wrap. |

These three switches apply only to `-priv`.

### Hexadecimal alphabet and incomplete templates

`-hexset CHARS` defines an ordered alphabet of 1 to 16 unique hexadecimal nibbles. Two distinct uses exist:

1. **Bounded enumeration**: `-start` is required and must have an even number of hex characters. Optional `-end` must also have even length. Each position is generated from the supplied alphabet.
2. **Template recovery**: `-recovery TEMPLATE` uses `*` for one unknown nibble. Every `*` is replaced from `-hexset` in the exact user-supplied order.

Raw private-key recovery is a separate workflow: it reads 64-position templates from `-i FILE` or standard input, allows no more than 32 `*` positions, and always tries `0..f` for every `*`. It does not use `-hexset`.

Example:

```bash
printf '%s\n' \
  '00000000000000000000000000000000000000000000000000000000000000**' | \
  ./METAL_CRYPTO_TOOLKIT -priv -recovery -c c \
    -hash 00112233445566778899aabbccddeeff00112233
```

The template is exactly 64 positions long. The command checks all 256 endings from `00` through `ff`.

`-hexset` is incompatible with `-size`, `-sizes`, step schedules, direction flags, random enumeration, `-n`, PRNG generation, `-pass_thread`, and `-der_thread`. Mode-scoped template recovery is available for mnemonic, entropy, seed, HMAC, BIP32, brainwallet, old Electrum, old Electrum seed, Armory Easy16, and Armory root. Raw private-key template recovery has its own exact 64-nibble form.

### Password masks

Masks are candidate sources for wallet-password modes and WalletJS password profiles. A mask and a raw `-start/-end` range cannot be used together.

| Token | Characters |
| --- | --- |
| `?l` | lowercase ASCII letters |
| `?u` | uppercase ASCII letters |
| `?d` | decimal digits |
| `?h` | lowercase hexadecimal digits |
| `?H` | uppercase hexadecimal digits |
| `?s` | ASCII symbols |
| `?a` | printable ASCII |
| `??` | a literal question mark |
| `?1` ... `?4` | custom set from `-cs1` ... `-cs4` |

Example:

```bash
./METAL_CRYPTO_TOOLKIT -keystore wallet.json \
  -mask '?u?l?l?l?l?d?d' -save -o keystore_found.txt
```

This checks seven-character passwords with one uppercase letter, four lowercase letters, and two digits. Quote masks so the shell does not interpret special characters.

### Internal PRNG catalogs

`-prng` and `-prng64` reproduce selected generator and byte-extraction combinations. They are research/recovery tools for a known generation process, not a recommendation for creating new keys.

| Argument | 32-bit catalog | 64-bit catalog |
| --- | --- | --- |
| seed domain | `0..FFFFFFFF` | `0..FFFFFFFFFFFFFFFF` |
| `-gen` | IDs `1..489` | IDs `1..223` |
| `-mode` | IDs `1..762` | IDs `1..218` |
| `-byte LIST` | generated byte lengths | generated byte lengths |
| `-shift LIST` | skipped outputs, default `0` | skipped outputs, default `0` |
| `-s/-e` | hexadecimal seed bounds | hexadecimal seed bounds |
| `-random` | random seed windows | random seed windows |
| `-log FILE` | progress log | progress log |

If `-gen` or `-mode` is omitted, every allowed value in that catalog is considered. This can multiply the workload dramatically. Generic PRNG runs should specify at least one `-byte` value; without a generated-byte size, a generic route can have no candidate work to dispatch. Print the exact catalogs before building a command:

```bash
./METAL_CRYPTO_TOOLKIT -prng_help
./METAL_CRYPTO_TOOLKIT -prng64_help
```

The appended Ill Bloom compatibility surface covers source profiles, runtime/phase variants, raw chain-sign masks, and every output-sign mask from the corresponding CUDA implementation. For 16/20/24/28/32-byte entropy, the exhaustive BE ranges contain 128/512/2,048/8,192/32,768 unique sign streams; add 256 to the mode range for LE packing. `-prng64` generators `221..223` pack a 32-bit seed and a profile selector into one non-overlapping ordinal space; mode `218` emits the direct source bytes. Gen 221 stores the 7-bit chain mask, 8-bit output mask, and endian bit above the seed; gen 222 selects one of 120 runtime profiles; gen 223 selects one of 256 raw-byte profiles. Their maximum indices are `0000FFFFFFFFFFFF`, `00000077FFFFFFFF`, and `000000FFFFFFFFFF` respectively. An omitted or oversized `-e` is clamped to the selected packed family.

```bash
./METAL_CRYPTO_TOOLKIT -entropy -prng -gen 332 -mode 247 \
  -byte 16 -s 0 -e FFFFFFFF

./METAL_CRYPTO_TOOLKIT -entropy -prng64 -gen 221 -mode 218 \
  -byte 16 -s 0 -e 0000FFFFFFFFFFFF
```

## Derivation paths and BIP-39 passphrases

### Derivation files

`-d FILE` reads one path per line:

```text
m/44'/0'/0'/0/0
m/49'/0'/0'/0/0
m/84'/0'/0'/0/0
```

`-d-type` selects the derivation engine. Numeric and named forms are accepted:

| Value | Names | Engine |
| --- | --- | --- |
| `1` | `bip32` | BIP32 on secp256k1 |
| `2` | `slip0010`, `slip10`, `ed25519` | SLIP-0010 on ed25519 |
| `3` | `bip32-ed25519`, `cardano`, `ada` | Cardano BIP32-ed25519 |

Values may be comma-separated or repeated. When `-d-type` is omitted, the program infers the required engine from the selected `-c` targets where possible.

`-d-dot FILE` reads Substrate SURI paths used by Polkadot/Kusama/Substrate. It is separate from BIP path syntax and can be used for DOT flows without `-d`.

### BIP-39 passphrase controls

The BIP-39 passphrase is the optional text added to the mnemonic-to-seed calculation. It is not a wallet-file password.

| Argument | Meaning |
| --- | --- |
| `-pass FILE` | If the value names an existing file, read one passphrase per line. |
| `-pass TEXT` | If no file exists at that path, use the argument itself as one literal passphrase. |
| `-passbrute HEX_START:HEX_END` | Enumerate a hexadecimal byte range as passphrases. |
| `-pass_thread` | Hold one mnemonic/entropy source and distribute many passphrases across GPU threads/devices. |
| `-der_thread` | Hold one source and distribute many derivation paths across GPU threads/devices. |
| `-pbkdf N` | Override the PBKDF2 iteration count; default is `2048`. |

`-pass_thread` and `-der_thread` describe mutually exclusive workflows. The parser does not reject every such combination; if both reach mnemonic or entropy dispatch, `-pass_thread` is checked first and `-der_thread` does not run. They are also unsupported with template/hexset and incompatible sequential/random branches. Read their dedicated sections before using them.

## Target families

`-c TYPES` chooses what is built from each valid key. Letters are case-sensitive. The same global `-hash` prefix and the same OR-combined Metal filter set are applied to every selected branch, so combine letters only when that shared target set is intentional. The default is `cus`.

| Letter | Key family | Value checked |
| --- | --- | --- |
| `c` | secp256k1 | Bitcoin HASH160 of the compressed public key |
| `u` | secp256k1 | Bitcoin HASH160 of the uncompressed public key |
| `s` | secp256k1 | HASH160 used by the P2SH-wrapped SegWit branch |
| `p` | secp256k1 | P2WSH branch; the found record carries the 32-byte witness program |
| `r` | secp256k1 | Bitcoin Taproot output key; matching uses RIPEMD-160 of that 32-byte key |
| `e` | secp256k1 | 20-byte Ethereum address value |
| `x` | secp256k1 | 32-byte public-key X coordinate |
| `T` | ed25519 | TON wallet address variants |
| `S` | ed25519 | Solana public key/address |
| `d` | ed25519/sr25519 | Polkadot/Substrate |
| `f` | secp256k1 | Filecoin f1/f4 |
| `i` | secp256k1/ed25519 | IOTA |
| `a` | ed25519 | Cardano Byron/Shelley families |
| `A` | ed25519/secp256k1 | Aptos |
| `U` | secp256k1/ed25519 | Sui |
| `X` | secp256k1/ed25519 | XRP |
| `I` | ed25519/secp256k1 | Internet Computer |
| `Z` | secp256k1/ed25519 | Tezos |

The `p` filter matcher uses RIPEMD160 of the 32-byte P2WSH witness program. A found record contains the full 32-byte program, and `-save` prints it in Bech32 address form. Build P2WSH filters from the matcher values expected by this program, not by mixing raw addresses or unrelated 32-byte values.

The `r` branch follows the same separation between the saved value and the matcher: a found record contains the 32-byte Taproot output key, but `-hash` and filters compare its 20-byte RIPEMD-160. The multicurrency converter performs this RIPEMD-160 step automatically when its input is a Taproot Bech32m address. If the starting input is instead a raw 32-byte output key, calculate the matcher separately or provide an already calculated 20-byte hex value.

### Network and address variants

Lists accept commas and ranges, for example `-ton-type 1,4-10`. If a subtype option is omitted, all variants for that family are enabled.

| Argument | Values |
| --- | --- |
| `-ton-type` | `1=v1r1`, `2=v1r2`, `3=v1r3`, `4=v2r1`, `5=v2r2`, `6=v3r1`, `7=v3r2`, `8=v4r1`, `9=v4r2`, `10=v5r1`, `11=highload v1`, `12=highload v2`, `13=highload v3` |
| `-dot-type` | `1=ed25519`, `2=sr25519` |
| `-fil-type` | `1=f1`, `2=f4` |
| `-iota-type` | `1=secp256k1`, `2=ed25519` |
| `-ada-type` | `1=Byron Icarus`, `2=Shelley Base`, `3=Shelley Enterprise`, `4=Byron Daedalus`, `5=Shelley Reward`, `6=Shelley Pointer`, `7=Shelley Exodus`, `8=Byron Ledger`, `9=Shelley Ledger`, `10=Byron Legacy` |
| `-ada-pointer slot:tx:cert` | Metadata for Cardano type 6; without it, that branch is silently skipped even if type 6 is selected |
| `-aptos-type` | `1=legacy ed25519`, `2=generalized ed25519`, `3=generalized secp256k1` |
| `-sui-type` | `1=secp256k1`, `2=ed25519` |
| `-xrp-type` | `1=secp256k1`, `2=ed25519` |
| `-icp-type` | `1=ed25519`, `2=secp256k1` |
| `-xtz-type` | `1=secp256k1`, `2=ed25519` |

Target support and validation are mode-specific. Some unsupported source/target combinations are rejected, while others are accepted and later skipped or cannot produce a match; use the selected mode's detailed help and a known fixture before a large run.

## Direct targets and filters

### Direct comparison

| Argument | Meaning |
| --- | --- |
| `-hash HEX` | In direct target-matching modes, parse one fixed binary prefix target of 2 to 32 bytes. The ordinary comparison path accepts at most 20 bytes. Bytes 21 to 32 work only in modes that explicitly compare a longer binary value, and never beyond that value's actual length. Wallet artifact password modes do not use it; WalletJS does. |
| `-target HEX` | Alias for `-hash` in ordinary target-matching modes. In `-profanity -recovery`, both names instead require one complete public key as described in that mode's section. |
| `-pubkey` | Deprecated and rejected. Use `-target` or `-hash`. |
| `-full` | Make the Metal matcher return every generated value before the normal direct-target and Metal-filter checks. This diagnostic switch can fill memory/disk extremely quickly. |

After an optional `0x` prefix, `-hash` must contain an even number of hexadecimal characters. The parser accepts exactly 2 to 32 bytes, or 4 to 64 hex characters. The active kernel determines how many of those bytes can actually be compared: the ordinary path stops at 20 bytes, while kernels with an explicit longer-value comparison stop at that value's real length or 32 bytes, whichever is smaller. Consequently, the width of a selected `-c` output alone does not guarantee support for a 21-to-32-byte direct target.

- `-c c -hash 00112233` compares the first 4 bytes of the compressed-public-key HASH160;
- `-c c -hash 00112233445566778899aabbccddeeff00112233` compares all 20 bytes of that HASH160;
- the ordinary 20-byte path cannot match a `-hash` longer than 40 hex characters;
- a longer-value comparison accepts 21 to 32 bytes only when that mode explicitly provides enough bytes for comparison.

In v14, the raw `-priv` and private Vanity-walk kernels use the ordinary 20-byte comparison even for a 32-byte output such as `-c x`. In those private-key paths, a direct `-hash` longer than 20 bytes cannot match. Some other modes explicitly compare longer values and can use up to 32 bytes.

This option expects decoded binary bytes written in hex, not a Base58, Bech32, SS58, or other printable address. For example, the `-c p` P2WSH branch compares a 20-byte RIPEMD160 matcher even though its found record carries the complete 32-byte witness program.

The repeated `001122...` sequences in command examples show the required hex syntax and width. They are not built-in targets. Replace them with the fixed full value or known leading-byte prefix required for your authorized search.

If `-hash` and one or more regular Metal filters are supplied together, a candidate must match the direct prefix **and** at least one active Metal filter. `-full` bypasses those Metal-side checks; an explicitly requested `-xx` or `-xb` CPU post-check can still reject a preliminary result before it is written.

### Bloom and XOR filters

| Argument | Filter |
| --- | --- |
| `-bf PATH` | Bloom filter |
| `-xu PATH` | uncompressed XOR filter |
| `-xc PATH` | compressed XOR filter |
| `-xuc PATH` | ultra-compressed XOR filter |
| `-xh PATH` | hyper-compressed XOR filter |

Use the companion [XorFilter](https://github.com/XopMC/XorFilter) project to build and validate Binary Fuse 4-wise filters from hexadecimal target lists.

| XorFilter result | Builder switch | Search switch |
| --- | --- | --- |
| `.xor_u` | no compression switch | `-xu` |
| `.xor_c` | `-compress` | `-xc` |
| `.xor_uc` | `-ultra` | `-xuc` |
| `.xor_hc` | `-hyper` | `-xh` |

Example:

```bash
mkdir -p filters
(cd filters && XorFilter -i ../btc_compressed_hash160.txt -compress -check)
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff \
  -c c -xc filters/btc_compressed_hash160_0.xor_c -save -o found.txt
```

The input file must contain one binary target value in hexadecimal per line. A filter must be homogeneous: one value width and one binary representation. Filter files are not assigned to individual `-c` letters: every selected branch is checked against every active filter, and a hit in any regular Metal filter is accepted. Do not mix addresses, public keys, HASH160 values, Ethereum values, P2WSH matchers, or multiple network families in one filter.

Compressed filters trade memory for a higher chance of a candidate reaching the result stage. The uncompressed XOR format also uses a finite fingerprint and should not be described as mathematical proof; always confirm a recovered secret independently.

### Optional CPU post-check: `-xx` and `-xb`

These two arguments are optional. A normal search needs only `-hash`/`-target` or one of the regular Metal filters above. Use a CPU post-check only when a small compressed filter is desirable in the hot Metal kernel but its preliminary matches need to be checked against a larger, more selective target set.

| Argument | What it does | Typical use |
| --- | --- | --- |
| `-xx PATH` | Loads an uncompressed `.xor_u` filter for CPU verification | Check preliminary matches from `-xc`, `-xuc`, or `-xh` against the corresponding uncompressed XOR set |
| `-xb PATH` | Loads a Bloom filter for CPU verification | Check preliminary matches from a compressed XOR filter when the corresponding Bloom target set is available |

The work is split into two stages:

```text
Metal kernel -> compact GPU filter -> rare preliminary match -> CPU post-check -> result output
```

In ordinary search modes, the post-check runs in the asynchronous result-processing path, so the CPU does not test every generated candidate. In `-profanity -recovery`, `-xx` has an additional practical purpose: it rejects basepoint-X false positives before the much more expensive seed-resolution stage.

Apple Silicon uses unified memory, so `-xx` and `-xb` do **not** provide a separate pool of "CPU RAM" in addition to "GPU VRAM". Their benefit is a smaller filter and smaller random-read working set inside the hot Metal kernel, while the CPU touches the larger verifier only for rare preliminary matches. Both filters still consume the Mac's same unified-memory capacity.

Useful combinations:

```bash
# Smallest Metal-side filter, followed by a less-compressed XOR post-check.
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff -c c \
  -xh btc_targets.xor_hc -xx btc_targets.xor_u -save

# Compressed Metal-side XOR filter, followed by a CPU Bloom check.
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff -c c \
  -xuc btc_targets.xor_uc -xb btc_targets.blf -save
```

Rules that matter:

- the Metal prefilter and CPU verifier must describe the same target representation, and the CPU verifier must contain every target you intend to accept; normally both are built from the same source list;
- `-xx`/`-xb` are second-stage checks, not standalone target sources;
- `-xu targets.xor_u -xx targets.xor_u` is normally redundant because the same uncompressed set is checked twice;
- `-bf targets.blf -xb targets.blf` is also redundant;
- when both `-xx` and `-xb` are supplied, a CPU match in either loaded CPU filter is accepted; do not use unrelated target collections together;
- CPU verification is most useful with `-xc`, `-xuc`, or `-xh`; if the regular `-xu` filter already fits comfortably and performs well, an additional CPU filter is usually unnecessary.

## Address conversion tools

The `tools/` directory contains 14 small address converters plus the separate `profanity_basepoint_generator`. The converters validate printable cryptocurrency addresses or encoded values and derive the binary comparison value required by the selected target branch. They write that value as lowercase hex. They do not search for keys and do not create Bloom or XOR filters. Their only job is to prepare a clean, homogeneous source list for a filter builder.

All converters use the same interface:

```text
TOOL <input.txt> [output.txt] [-t N]
TOOL -h
```

- `input.txt` contains one address or encoded value per line;
- `output.txt` is optional; without it, `name.txt` produces `name-hex.txt` in the same directory;
- `-t N` selects from 1 to 256 worker threads; the default is the Mac's logical processor count;
- leading/trailing whitespace and CRLF line endings are accepted, while empty lines are ignored;
- valid values are written in their original order, one lowercase hex value per line;
- rejected source lines are written to `name-invalid.txt` after leading and trailing whitespace is removed; that file is created only when at least one line is rejected;
- individual invalid lines do not make the whole command fail, but CLI, file, and internal errors return exit code `1`.

The first valid result fixes the byte width of the output file. Any later valid address that decodes to another width is moved to `-invalid.txt`. This prevents a 20-byte target and a 32-byte target from being mixed accidentally.

When built from source, a binary is placed at `tools/<project>/bin/<tool>`. In the release archive, the 14 converters and the Profanity basepoint generator are directly inside the unpacked `tools/` directory.

| Tool | Accepted input | Hex result | Compatible Toolkit branch |
| --- | --- | --- | --- |
| `cardano_address_to_hex` | Cardano Shelley Bech32 or Byron Base58 with CBOR/CRC validation | SHA-256 of the decoded address, 32 bytes / 64 hex characters | `-c a` with the matching `-ada-type` |
| `algorand_address_to_hex` | 58-character Algorand Base32 address with SHA-512/256 checksum | raw ed25519 public key, 32 bytes / 64 hex characters | `-c S` |
| `multicoin_base58_bech32_address_to_hex` | Bitcoin-like Base58Check, SegWit Bech32/Bech32m, CashAddr, or raw 20/32-byte hex | 20-byte matcher for decoded addresses; raw hex keeps its 20/32-byte width | `-c c`, `u`, `s`, `p`, or `r`, depending on the address construction |
| `base64_data_to_hex` | Strict Base64 or Base64URL, padded or unpadded | decoded bytes; one width per file | determined by what the decoded bytes represent |
| `cosmos_bnb_address_to_hex` | Bech32 with a 20-byte payload or raw 20-byte hex | 20-byte payload / 40 hex characters | `-c c` for ordinary secp256k1 account addresses |
| `polkadot_kusama_address_to_hex` | SS58 containing a 32-byte account ID and a one- or two-byte network prefix | 32-byte account ID / 64 hex characters | `-c d`, with `-dot-type 1` or `2` |
| `filecoin_address_to_hex` | Filecoin `f1`, `t1`, `f410`, or `t410` with Blake2b checksum | 20-byte payload / 40 hex characters | `-c f -fil-type 1/2`; delegated `f410/t410` also match `-c e` |
| `solana_address_to_hex` | Base58 public key, exactly 32 decoded bytes | raw ed25519 public key, 32 bytes / 64 hex characters | `-c S` |
| `stellar_address_to_hex` | Stellar `G...` account or muxed `M...` StrKey with CRC16 | underlying raw ed25519 public key, 32 bytes / 64 hex characters | `-c S` |
| `stacks_address_to_hex` | Stacks `SP`, `ST`, `SM`, or `SN` C32Check address | 20-byte HASH160 / 40 hex characters | `SP/ST`: `-c c` or `u`; `SM/SN`: no generic single-key branch |
| `ton_address_to_hex` | TON friendly Base64/Base64URL, `workchain:hex`, or raw 32-byte hex | 32-byte account ID / 64 hex characters | `-c T` with the matching `-ton-type` |
| `tron_address_to_hex` | Tron Base58Check address beginning with `T`, or raw 20-byte hex | Ethereum-compatible account ID, 20 bytes / 40 hex characters | `-c e` |
| `xrp_address_to_hex` | XRP Classic Base58Check or raw 20-byte hex | 20-byte account ID / 40 hex characters | `-c X` with `-xrp-type 1` or `2` |
| `tezos_address_to_hex` | Tezos `tz1` or `tz2` Base58Check address | 20-byte key hash / 40 hex characters | `-c Z`; `tz1` uses `-xtz-type 2`, `tz2` uses `1` |

`profanity_basepoint_generator` is not an address converter. It creates the complete fixed-width basepoint source list required by `-profanity -recovery`; its format and workflow are documented separately below.

### Binary compatibility and result formatting

The table describes compatible comparison bytes, not a promise that the Toolkit will print the original network's address format. Several networks intentionally share the same cryptographic payload:

- `-c S` compares a raw 32-byte ed25519 public key. Solana, Algorand, and Stellar target files can therefore use this branch, but `-save` labels and encodes the result as Solana;
- `-c c` compares HASH160 of a compressed secp256k1 public key. The same 20-byte value is used by ordinary secp256k1 Cosmos/BNB accounts and Stacks P2PKH accounts, but `-save` produces Bitcoin address forms;
- `-c e` compares the 20-byte Keccak-derived EVM account value. Tron and Filecoin delegated `f410/t410` addresses contain that same value, but `-save` produces the Ethereum representation;
- selecting a compatible `-c` branch does not select a wallet derivation algorithm. The input mode, seed interpretation, derivation path, curve, and subtype must still reproduce the key that created the source address.

### Each converter in detail

#### `cardano_address_to_hex` - Cardano

Accepts Shelley `addr...`/`stake...` Bech32 addresses and Byron Base58 addresses. It validates the Bech32 network and address layout, pointer encoding where present, or Byron CBOR and CRC. The result is SHA-256 of the decoded address bytes, which is the value compared by `-c a`.

Choose the matching `-ada-type`: Byron and the key-controlled Shelley Base, Enterprise, Reward, and Pointer forms are separate Toolkit subtypes. The converter also validates Shelley addresses whose payment or stake credential is a script hash. Such an address can be decoded, but a normal private-key search cannot generate its script credential, so decoding it does not make it a key-derived target.

```bash
tools/cardano_address_to_hex cardano-addresses.txt cardano-targets.txt -t 8
```

#### `algorand_address_to_hex` - Algorand

Accepts a canonical 58-character uppercase Algorand address, verifies its Base32 alphabet and SHA-512/256 checksum, and returns the underlying 32-byte ed25519 public key described by the [Algorand address format](https://developer.algorand.org/docs/get-details/encoding/). That binary value is compatible with `-c S`, because the `S` branch compares the raw ed25519 public key. The source mode must still generate the same Algorand key; `-save` formats a match as Solana rather than recreating the Algorand address.

```bash
tools/algorand_address_to_hex algorand-addresses.txt algorand-public-keys.txt
XorFilter -i algorand-public-keys.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c S -xu algorand-public-keys_0.xor_u
```

#### `multicoin_base58_bech32_address_to_hex` - multicurrency Bitcoin-like networks

This is the general converter for Bitcoin-like currencies, not a Bitcoin-only program. It accepts checksum-valid Base58Check addresses with a one- to four-byte prefix and a 20-byte payload, witness v0 Bech32, Taproot v1 Bech32m, CashAddr with a 20-byte payload, and ready 20- or 32-byte hex. It validates the encoding, but it does not maintain a whitelist of coin network prefixes or Bech32 HRPs and therefore cannot identify the original currency from the payload alone.

P2PKH made from a compressed key and P2WPKH both use `-c c`; P2PKH made from an uncompressed key uses `-c u`. A Base58Check or CashAddr P2SH payload does not reveal the redeem script: use `-c s` only when the source is known to be the exact P2SH-wrapped SegWit construction generated by the Toolkit. Generic multisig or other P2SH scripts are not automatically compatible. A P2WSH or Taproot 32-byte witness program decoded from an address is immediately reduced to the 20-byte RIPEMD-160 matcher expected by `-c p` or `-c r`. Raw 32-byte hex remains unchanged because it has no address version from which a branch can be inferred.

The rules are format-based, so compatible Bitcoin-derived networks such as Litecoin, Dogecoin, Dash, and others can be decoded. Keep every currency, address construction, and target branch in a separate source file and filter.

```bash
tools/multicoin_base58_bech32_address_to_hex bitcoin-addresses.txt bitcoin-targets.txt
```

#### `base64_data_to_hex` - Base64 and Base64URL data

Decodes strict padded or unpadded Base64/Base64URL. Unknown characters, mixed alphabets, misplaced padding, and non-zero unused bits are rejected. Base64 has no checksum and says nothing about the meaning of the bytes. Choose `-c` only after identifying whether the decoded value is an account ID, public key, HASH160, or another supported matcher. All values in one file must have the same byte length and meaning.

```bash
tools/base64_data_to_hex encoded-values.txt decoded-values.txt
```

#### `cosmos_bnb_address_to_hex` - Cosmos-family and BNB

Accepts Bech32 with a 20-byte payload, including ordinary Cosmos Hub and BNB account addresses, or ready 20-byte hex. It verifies Bech32 but does not whitelist HRPs; a valid checksum and 20-byte payload do not prove that the address belongs to a particular chain.

For a normal secp256k1 account, the payload is RIPEMD-160(SHA-256(compressed public key)), exactly the value compared by `-c c`; the construction is documented in the [Cosmos SDK address reference](https://docs.cosmos.network/sdk/latest/guides/reference/bech32). Do not apply this mapping to legacy multisig, validator consensus addresses, secp256r1, or another key scheme. `-save` formats a match as Bitcoin, so compare the found 20-byte payload with the converter output when working with Cosmos/BNB.

```bash
tools/cosmos_bnb_address_to_hex cosmos-addresses.txt cosmos-payloads.txt
XorFilter -i cosmos-payloads.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c c -xu cosmos-payloads_0.xor_u
```

#### `polkadot_kusama_address_to_hex` - Polkadot, Kusama, and Substrate

Accepts the full SS58 form containing a 32-byte account ID and a canonical one- or two-byte network prefix. It verifies the Blake2b `SS58PRE` checksum and returns only the account ID. Use `-c d -dot-type 1` for ed25519 or `-c d -dot-type 2` for sr25519. The SS58 prefix does not identify the curve and is not part of the matcher; other SS58 payload lengths and key schemes are rejected.

```bash
tools/polkadot_kusama_address_to_hex substrate-addresses.txt substrate-account-ids.txt
```

#### `filecoin_address_to_hex` - Filecoin

Accepts mainnet/testnet `f1`/`t1` and delegated `f410`/`t410` addresses. It checks the lowercase Base32 representation, protocol or namespace, exact payload length, and Blake2b checksum. Keep the two forms in separate files:

- `f1/t1` is the Filecoin secp256k1 Blake2b-160 payload used by `-c f -fil-type 1`;
- `f410/t410` namespace 10 contains the 20-byte Ethereum address, as defined by the [Filecoin Ethereum Address Manager](https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/address-types), and can use either `-c f -fil-type 2` for Filecoin-formatted `-save` output or `-c e` for Ethereum-formatted output.

```bash
tools/filecoin_address_to_hex filecoin-addresses.txt filecoin-targets.txt
XorFilter -i filecoin-f1-targets.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c f -fil-type 1 -xu filecoin-f1-targets_0.xor_u
```

#### `solana_address_to_hex` - Solana

Decodes the Solana Base58 public key and requires exactly 32 bytes. A Solana address does not include a checksum, so a valid-looking but mistyped Base58 string can only be rejected when its alphabet or decoded length is wrong. Use the result with target `-c S`.

```bash
tools/solana_address_to_hex solana-addresses.txt solana-public-keys.txt
```

#### `stellar_address_to_hex` - Stellar

Accepts Stellar account StrKeys beginning with `G` and muxed accounts beginning with `M`. It verifies the version byte and CRC16-XMODEM checksum. For `M...`, the output is the underlying 32-byte ed25519 public key without the muxed ID; the [Stellar muxed-account format](https://developers.stellar.org/docs/build/guides/transactions/pooled-accounts-muxed-accounts-memos) therefore makes different muxed IDs for the same account produce the same hex value. The raw public key is compatible with `-c S`, but the source mode must reproduce the Stellar key derivation and `-save` formats the match as Solana.

```bash
tools/stellar_address_to_hex stellar-addresses.txt stellar-public-keys.txt
XorFilter -i stellar-public-keys.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c S -xu stellar-public-keys_0.xor_u
```

#### `stacks_address_to_hex` - Stacks

Accepts the four standard [Stacks C32Check](https://docs.stacks.co/more-guides/c32check) versions and returns their 20-byte HASH160 after validating the alphabet, version, payload length, and checksum. Keep the address classes separate:

- `SP` mainnet and `ST` testnet are P2PKH. Their HASH160 is compatible with `-c c` for the normal compressed public key or `-c u` if the address was deliberately created from an uncompressed key;
- `SM` mainnet and `SN` testnet are P2SH. The payload does not describe the redeem script, so it is not a generic single-key target and must not automatically be searched with `-c s`.

`-save` on `c` or `u` produces a Bitcoin address. Compare the found HASH160 with the converter output when searching Stacks P2PKH.

```bash
tools/stacks_address_to_hex stacks-addresses.txt stacks-hash160.txt
XorFilter -i stacks-p2pkh-hash160.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c c -xu stacks-p2pkh-hash160_0.xor_u
```

#### `ton_address_to_hex` - TON

Accepts a friendly Base64/Base64URL TON address, `workchain:64-hex`, or a raw 32-byte account ID. Friendly addresses are checked for a supported tag, exact length, and CRC16. Workchain, bounceable/test flags, and presentation are discarded, so friendly forms of the same account produce the same hex. Use `-c T` with the `-ton-type` that generated the source wallet contract.

```bash
tools/ton_address_to_hex ton-addresses.txt ton-account-ids.txt
```

#### `tron_address_to_hex` - Tron

Accepts a Tron Base58Check address with the required `0x41` network byte, or a ready 20-byte hex account ID. It verifies the checksum and strips only the Tron network byte. The remaining 20 bytes are the same Keccak-derived account value used by the Ethereum-style target `-c e`; the converter does not hash the printable `T...` text.

```bash
tools/tron_address_to_hex tron-addresses.txt ethereum-style-account-ids.txt
```

#### `xrp_address_to_hex` - XRP Ledger

Accepts an XRP Classic address or ready 20-byte account ID. It uses the XRP Base58 alphabet, verifies Base58Check and the Classic account version, and writes the account ID used by `-c X`. A Classic address does not identify the source curve: use `-xrp-type 1` for secp256k1 or `-xrp-type 2` for ed25519 according to the source wallet. X-addresses are not accepted.

```bash
tools/xrp_address_to_hex xrp-addresses.txt xrp-account-ids.txt
XorFilter -i xrp-account-ids.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c X -xrp-type 1 -xu xrp-account-ids_0.xor_u
```

#### `tezos_address_to_hex` - Tezos

Accepts `tz1` ed25519 and `tz2` secp256k1 implicit accounts, validates their Base58Check prefix and checksum, and writes the 20-byte key hash used by `-c Z`. Search `tz1` with `-xtz-type 2` and `tz2` with `-xtz-type 1`. Keep them in separate filters. `tz3`, `KT1`, and other Tezos address classes are intentionally rejected.

```bash
tools/tezos_address_to_hex tezos-addresses.txt tezos-key-hashes.txt
XorFilter -i tezos-tz1-key-hashes.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c Z -xtz-type 2 -xu tezos-tz1-key-hashes_0.xor_u
```

#### `profanity_basepoint_generator` - Profanity recovery basepoints

This is a generator, not an address converter. For every selected 32-bit Profanity seed it recreates the vulnerable MT19937-64 state, calculates the seed's secp256k1 base public point, and writes the first 20 bytes of its canonical affine X coordinate. The output is exactly one 40-character lowercase hex value plus `\n` per seed, in ascending seed order. That is the source format required by the `-profanity -recovery` XOR filters.

The implementation uses a shared 14-bit secp256k1 precompute table tuned for Apple Silicon CPUs, multithreaded scalar multiplication, batch field inversion, bounded ordered output, and 256 MiB flush checkpoints. It does not create an XOR filter itself.

```text
profanity_basepoint_generator [output.txt] [-s HEX32] [-e HEX32] [-t N] [--resume]
```

- without an output name it writes `PROFANITY_BASEPOINT.txt`;
- `-s` and `-e` are inclusive seed32 bounds, defaulting to `00000000..ffffffff`;
- `-t` selects `1..256` CPU workers and defaults to the Mac's logical processor count;
- `--resume` derives the next seed from the existing file size. Resume is accepted only when the size is divisible by the fixed 41-byte line length, does not exceed the selected range, and the first/last existing lines match that range;
- `SIGINT`/`SIGTERM` stops after already assigned blocks are written, leaving a contiguous file that can be resumed.

Build and make a small verification range first:

```bash
make -C tools/profanity_basepoint_generator
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  profanity-test.txt -s 0 -e ffff -t 8
```

Generate the complete source on a local SSD with at least 200 GB free:

```bash
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  PROFANITY_BASEPOINT.txt -t "$(sysctl -n hw.logicalcpu)"

# Continue the same range after a controlled interruption:
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  PROFANITY_BASEPOINT.txt -t "$(sysctl -n hw.logicalcpu)" --resume
```

The full `2^32` source is exactly `176,093,659,136` bytes: 176.09 GB in decimal units or 164 GiB. Generate it on fast local storage and move it afterward; direct output to SMB/network storage can make the writer the bottleneck. See the dedicated `-profanity -recovery` section for filter construction and memory requirements.

For `multicoin_base58_bech32_address_to_hex`, the resulting P2WSH and Taproot files can be passed directly to XorFilter; no additional OpenSSL conversion is required. A raw 32-byte line is preserved intentionally. If it is a full Taproot output key rather than an already prepared matcher, provide the Bech32m address or calculate the required 20-byte RIPEMD-160 before building the filter.

### How 20-byte and 32-byte lists are filtered

The converter output and the filter key are related but not identical concepts:

- converters write the complete target value they derive, without silently truncating it: 40 hex characters for a 20-byte result or 64 for a 32-byte result;
- the current [XorFilter](https://github.com/XopMC/XorFilter) format derives its key from the first 20 bytes of each input line, and the Toolkit's Bloom/XOR lookup checks those same first 20 bytes;
- a filter built from 32-byte targets is therefore a 160-bit prefilter. A match still stores the complete candidate payload, but every Binary Fuse filter is probabilistic; each output profile has its documented false-positive rate;
- verify every reported result against the original complete converter output. For alternate-network mappings such as Algorand/Stellar through `S` or Cosmos/Stacks through `c`, compare the raw payload because `-save` uses the branch's native Solana or Bitcoin formatting.

Do not mix currencies, key algorithms, address constructions, or 20/32-byte widths in one converter input. Even when two families share the same byte width, separate filters prevent an accepted match from being attributed to the wrong branch.

The complete filter-preparation path is:

```text
addresses.txt -> address converter -> targets-hex.txt -> XorFilter -> .xor_* -> METAL_CRYPTO_TOOLKIT
```

For example:

```bash
tools/cardano_address_to_hex cardano-addresses.txt cardano-targets.txt -t 8
mkdir -p filters
(cd filters && XorFilter -i ../cardano-targets.txt -check)
./METAL_CRYPTO_TOOLKIT -mnemonic -i phrases.txt -d derivation.txt \
  -c a -xu filters/cardano-targets_0.xor_u -save -o found.txt
```

[XopMC/XorFilter](https://github.com/XopMC/XorFilter) creates the actual Binary Fuse filter; the converters only prepare its input list. Keep the converter's full output as the authoritative list used to verify findings.

## Output, buffers, and devices

### Result formatting and file output

| Argument | Meaning |
| --- | --- |
| `-save` | In key and derivation searches, format the matched binary payload as a cryptocurrency address where that target type has an address representation. In the specialized modes listed below, it also enables writing their result records to the output file. |
| `-o FILE` | Select the output file. Default: `result.txt`. |
| `-silent` | Suppress found lines on the terminal. It does not change the mode-specific file behavior described below. |
| `-fsize N` | Result slots per device. Default: `150000`. |

For `-mnemonic`, `-recovery`, `-poetry`, `-entropy`, `-seed`, `-hmac`, `-bip32`, `-der_thread`, `-pass_thread`, `-priv`, `-minikeys`, `-brain`, old Electrum, and Armory key-search flows, the result file is opened in append mode and every match is written even when `-save` is absent. The flag does not validate or confirm a candidate and it does not change target matching. It changes only the final representation:

- without `-save`, most matched hashes and fixed-width payloads are written as raw hexadecimal data;
- with `-save`, Bitcoin, TON, Solana, Polkadot/Substrate, Filecoin, IOTA, XRP, Tezos, and other supported target payloads are converted to their mode-specific printable address form;
- target types without a separate address encoder remain hexadecimal;
- Cardano branches already construct their defined address form as part of the normal result path and therefore do not depend on `-save` in the same way as an ordinary HASH160 target.

Wallet password modes, `-walletscan`, `-walletjs`, `-xp`, and Profanity search/recovery use specialized result writers. In those modes, `-save` is required to append the structured result line to `-o`; without it, a finding is printed to the terminal unless `-silent` suppresses it. In `-walletjs`, `-xp`, and Profanity, the flag also selects address formatting for target types that support it.

Whenever a mode writes a result file, it uses append mode: existing content is not replaced. GPU key/derivation snapshots are passed to per-device asynchronous output queues with up to 64 pending tasks per device. Specialized wallet writers emit their already verified records directly. Records retain their candidate, path, and mode-specific numbering, but the complete file is not globally sorted. With several devices, records can appear in completion order and may be prefixed with `GPU N:`.

`-full` should be used only with a tiny bounded command because it turns every checked value into a result.

### Metal devices and automatic grid

`-device` accepts one index, a comma-separated list, or a range:

```bash
-device 0
-device 0,1,3
-device 0-3
```

The program enumerates Metal devices and divides candidate ordinals without intentional overlap or gaps. On ordinary Apple Silicon systems, one unified GPU device is usually shown.

The default launch grid is automatically chosen for the device and workload. Start with it. Manual controls are advanced:

| Argument | Default | Scope |
| --- | --- | --- |
| `-b N` | automatic | threadgroups/blocks where the mode allows an override |
| `-t N` | automatic | threads per threadgroup where allowed |
| `-bit N` | auto: 18 for private/minikey paths, 10 for recovery, 16 otherwise | secp256k1 precompute-table profile |
| `-keys N` | `1024` | private sequential/vanity work; values are quantized in 1024-key units with a minimum of 1024 |
| `-chunk N` | `1` | private-key chunks per thread |
| `-em` | off | secp256k1 endomorphism in private sequential/random modes |
| `-legacy` | off | older private sequential/random schedule |

Manual grid values from another chip or another mode are not automatically optimal. They can reduce speed or increase memory pressure.

## Mode reference

Every subsection answers five questions: what the mode reads, what it computes, which arguments matter, what is saved, and how to run a small example.

### Mnemonic and derivation modes

#### `-mnemonic [SUBMODE]`

**Use it for:** BIP-39 mnemonic candidates or text that is transformed into mnemonic input before derivation. It is the default main mode when no other main mode is selected.

**One input line:** normally one mnemonic/text candidate. With `-hex`, one line contains hexadecimal bytes. Paths are read separately from `-d`; BIP-39 passphrases come from `-pass` or `-passbrute`.

**Ways to supply work:**

| Task | Arguments | What is enumerated |
| --- | --- | --- |
| Check known phrases or source text | `-i FILE` or standard input | One line at a time |
| Walk a byte range in order | `-start HEX -end HEX [-step HEX]` | The byte payload supplied to the selected mnemonic submode |
| Choose points from a bounded range | `-start HEX -end HEX -random [-n N]` | Random points between the two byte boundaries |
| Reproduce an internal generator family | `-prng` or `-prng64` with `-gen/-mode/-s/-e` | Payloads produced by the selected PRNG profile |
| Enumerate a restricted hex alphabet | `-hexset CHARS -start HEX [-end HEX]` | Fixed-width byte values made from the listed nibbles |
| Recover whole unknown BIP-39 words | standalone `-recovery` | Dictionary words replacing standalone `*` positions |
| Check many passphrases for one phrase | `-pass_thread` | BIP-39 passphrases, while the mnemonic remains fixed |
| Check many paths for one phrase | `-der_thread` | Derivation paths, while the mnemonic remains fixed |

The sequential branch increments the hexadecimal byte value; it does not move directly from one dictionary word to the next. The resulting bytes are then handled by the selected mnemonic submode exactly as file input would be. Preserve leading zeroes when the input width matters.

**Submodes:**

| Value | Pre-processing |
| --- | --- |
| omitted | normal mnemonic path |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | convert every input byte to two lowercase hexadecimal ASCII characters; the material length doubles, up to the 512-byte internal cap |

`-iter LIST` chooses transformation round counts; `-utf8` uses the UTF-8 hexadecimal-text rehash path between rounds; `-text` keeps compatible transformed material as text. `-electrum [seg]`, `-128`, and `-ton`/`-TON` select their documented mnemonic transformations. `-ton` and `-TON` are aliases with the same effect. `-round N` checks plus/minus private-key rounds around each derived result.

Sequential example:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic 1 \
  -start 00000000 -end 0000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

This checks the four-byte payload range in order, applies mnemonic submode `1` (SHA-256), and sends every resulting candidate through the requested BIP-39 and derivation path. Run `./METAL_CRYPTO_TOOLKIT -mnemonic -help` to see the complete live option list.

**Found record:** the source text, optional `bip39_pass(...)`, exact derivation path(s), private key/scalar material, target type, and matched value/address.

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -i mnemonics.txt -d derivations.txt \
  -d-type bip32 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

This reads one phrase per line, derives every path in `derivations.txt` through BIP32/secp256k1, and checks only compressed Bitcoin HASH160.

##### `-mnemonic -scramble`

Use this submode when all BIP-39 words are known but their order, or part of
their order, is unknown. The source is either an inline 12/15/18/21/24-word
phrase after `-scramble` or one phrase per line from repeatable `-i FILE`.
Words are treated as a multiset: repeated words do not create duplicate
permutations.

Metal maps a checked U256 ordinal directly to one unique permutation, checks
the BIP-39 checksum first, and sends only checksum-valid phrases into the
existing seed, derivation and exact target-verification pipeline. No list of
permutations is materialized. `SpeedThreadFunc` remains the only statistics
printer and reports completed `Candidate/s`.

`-pattern` has exactly one token per output position:

- `*` accepts any remaining source word;
- a plain word fixes that word at the position;
- `{word|word}` restricts the position to the listed source words.

`-pattern-file FILE` reads one non-comment pattern. `-start N` and exclusive
`-end N` select a checked U256 ordinal interval; without them the complete
unique-permutation domain is used. `-n N` controls a completed GPU window.
`-wallet-mem auto|all|NN%|SIZE` accepts MiB/GiB sizes and limits the unified
Metal working set. Multi-GPU intervals are disjoint. If the checksum-hit buffer
overflows, the uncredited window is halved and repeated without losing work.

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -scramble \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  -pattern "* * * * * * * * * * * *" \
  -d derivations.txt -c c -hash 00112233445566778899aabbccddeeff00112233
```

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -scramble -i phrases.txt \
  -pattern-file positions.txt -start 0 -end 0x100000 \
  -wallet-mem all -device 0 -d derivations.txt -c p \
  -hash 00112233445566778899aabbccddeeff00112233
```

The U256 scheduler makes large domains representable, not practically
searchable. Restrictive fixed positions can reduce the actual permutation
domain; brace restrictions currently filter the exact multiset domain on GPU.

#### `-recovery`

**Use it for:** a BIP-39 phrase with one or more unknown words.

**Input:** an inline template or a file of templates. Each unknown word is written as a standalone `*`. `-wordlist FILE` forces a wordlist; otherwise `-lang` selects an embedded language.

Language values are `EN` (English), `SA` (Spanish), `JA` (Japanese), `IT` (Italian), `FR` (French), `CZ` (Czech), `PT` (Portuguese), `KO` (Korean), `CS` (Simplified Chinese), and `CT` (Traditional Chinese); English is the default. An unknown language code currently falls back to English, so check the startup log rather than assuming a typo will stop the run.

```bash
./METAL_CRYPTO_TOOLKIT -recovery \
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon *' \
  -lang EN -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

The example replaces the final word with valid English BIP-39 words, validates each completed phrase, derives the requested paths, and emits a result only when the derived value matches the target. Here `-save` controls address formatting, not whether the candidate is accepted.

Do not use the hexadecimal-template rules from `-priv -recovery` here. A mnemonic `*` represents one whole word.

For predictable recovery, provide an exact BIP-39 word count and mark every unknown position explicitly. The current parser can pad a short template with additional wildcards until its word count is at least three and divisible by three, and it can map an unknown written word to the nearest dictionary entry. Do not rely on either convenience behavior in an evidence-sensitive search.

#### `-poetry`

**Use it for:** restoring a Poetry brainwallet phrase when all words are known or when one or more whole words are missing. Poetry is a separate phrase format, not BIP-39: it does not use a BIP-39 checksum, PBKDF2 passphrase, mnemonic seed, or derivation path.

**Ways to supply templates:**

| Source | Command form | Behavior |
| --- | --- | --- |
| Inline | `-poetry "TEMPLATE"` | Adds one template written directly in the command. Repeat `-poetry "..."` to add several finite tasks. |
| File | `-poetry -i FILE` | Reads one non-empty template from each non-empty line. The option can be repeated for more files. |
| Standard input | `-poetry` | Reads one non-empty template per line from stdin. Standard input can be selected only once. |

A template must contain exactly `3`, `6`, `9`, `12`, `15`, `18`, `21`, or `24` whitespace-separated words. Write a standalone `*` for every unknown word. The program never adds missing wildcards automatically, so `just just *` has one unknown position and `* * *` has three.

The mode uses its embedded 1626-word Poetry dictionary. Fixed words are converted to lowercase. If a written word is absent from the dictionary, the closest dictionary word is selected and a `Recovery replace` message is printed. Check those messages before a long search: a spelling correction changes the fixed phrase being tested.

**How the phrase becomes a key:** every dictionary word has a numeric position. Each consecutive group of three positions is decoded into four bytes according to the Poetry format. A 3-word phrase therefore contributes 4 significant bytes, a 6-word phrase contributes 8, and a 24-word phrase contributes all 32. Shorter results are left-padded with zero bytes to form one 32-byte key. That key is checked directly; there is no intermediate mnemonic seed or child-key derivation.

The resulting key is sent through the target families selected by `-c`. Direct `-hash`/`-target` prefixes and Bloom/XOR filters work as described in the target sections above. Use secp256k1 targets such as `c`, `u`, `s`, `p`, `r`, `e`, or `x` for an ordinary private-key interpretation; ed25519/sr25519 and network-specific targets use the corresponding key interpretation implemented by that branch.

**Finite and random enumeration:**

| Mode | Behavior |
| --- | --- |
| Finite, default | Enumerates all `1626^N` combinations for `N` wildcards. The rightmost `*` changes fastest. A template without `*` is checked once. The exact combination count is printed before the task. Multiple templates run sequentially, while selected Metal devices divide each task without intentionally overlapping candidate ordinals. |
| `-random` | Replaces wildcard positions indefinitely with randomly generated dictionary words. Without `-n`, it requires exactly one template and at least one `*`; there is no natural completion point. Fixed words never change. |
| `-random -n N` | Accepts one or more templates. For each template, exactly `N` random wildcard combinations are generated in total across all selected Metal devices. The program then switches to the next template; after the last template it starts a new numbered cycle from the first. Every template must contain at least one `*`. |

Useful key-processing controls are `-round N` for plus/minus keys around every decoded value and `-em` for secp256k1 endomorphism. For ed25519-oriented checks, `-scalar` treats the decoded bytes as a scalar, `-LE` selects little-endian scalar input together with `-scalar`, and `-shash` treats the decoded bytes as pre-clamp ed25519 hash material.

Poetry owns its candidate source. Do not combine it with another main mode; generic file or directory controls such as `-f`, `-all`, or `-delete`; range and direction controls such as `-start`, `-end`, `-step`, `-back`, or `-both`; `-hex`, `-hexset`, `-size`, `-sizes`, `-recovery`, `-wordlist`, `-prng`, `-prng64`, `-comb`, `-mutation`, BIP-39 passphrase options, `-d`, `-d-type`, `-d-dot`, `-pass_thread`, or `-der_thread`. Use `-poetry -i FILE`, not a standalone generic `-i FILE`.

**Found record:** the completed phrase is prepended to the ordinary key result. The saved form is:

```text
phrase:private:currency:payload
```

Without `-save`, `payload` normally remains the matched hash or fixed-width value in hexadecimal form. With `-save`, supported target families write their printable address representation. Matches are appended to `-o FILE` (default `result.txt`), so the essential relationship is always `phrase:<result>` and the exact completed phrase can be recovered from every line.

Finite inline example:

```bash
./METAL_CRYPTO_TOOLKIT -poetry "just just *" -c c \
  -hash 00112233445566778899aabbccddeeff00112233 \
  -save -o poetry-found.txt
```

File and standard-input examples:

```bash
./METAL_CRYPTO_TOOLKIT -poetry -i poetry-templates.txt \
  -device 0 -c cus -xc btc-targets.xor_c -o poetry-found.txt

./METAL_CRYPTO_TOOLKIT -poetry < poetry-templates.txt
```

Infinite random example:

```bash
./METAL_CRYPTO_TOOLKIT -poetry "* * *" -random \
  -c e -xc ethereum-targets.xor_c -o poetry-found.txt
```

Cyclic random batches for several templates:

```bash
./METAL_CRYPTO_TOOLKIT \
  -poetry "just * * * * *" \
  -poetry "love * * * * *" \
  -random -n 1000000000 \
  -c e -xc ethereum-targets.xor_c -o poetry-found.txt
```

Here each template receives exactly one billion candidates per cycle. With several devices, that billion is divided between them; it is not repeated independently on every device.

#### `-der_thread`

**Use it for:** one source candidate and a very large path list. It is available with mnemonic, entropy, seed, HMAC, and BIP32 sources.

The source remains fixed for a round while paths from `-d`, `-d-type`, and `-d-dot` are distributed across GPU threads and selected devices. Cardano BIP32-ed25519 roots and DOT SURI paths are included when their source and target family require them.

```bash
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' | \
  ./METAL_CRYPTO_TOOLKIT -mnemonic -der_thread -d many_paths.txt \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

Do not combine `-der_thread` with `-pass_thread`, template recovery, `-hexset`, or unsupported sequential/random branches.

#### `-pass_thread`

**Use it for:** one mnemonic or entropy value and many possible BIP-39 passphrases.

Provide one source through standard input or a file and passphrases through `-pass FILE` or `-passbrute START:END`. The output retains both the source and the matching passphrase.

```bash
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' | \
  ./METAL_CRYPTO_TOOLKIT -mnemonic -pass_thread -pass passphrases.txt \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

This is an inversion of the ordinary loop, not a different BIP-39 algorithm. It cannot be combined with `-der_thread`, PRNG, sequential/random, hexset, or recovery flows.

#### `-entropy [SUBMODE]`

**Use it for:** entropy bytes that are converted into the mnemonic/seed/derivation pipeline.

**One input line:** hexadecimal entropy when `-hex` is present; otherwise mode-specific text/raw bytes. `-size N` selects one final entropy size in bytes and `-sizes LIST` selects several. `-w N` supplies the word-count helper used by compatible random generation.

| Value | Transformation |
| --- | --- |
| omitted | normal entropy path |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | convert every input byte to two lowercase hexadecimal ASCII characters; the material length doubles, up to the 512-byte internal cap |

**Ways to supply entropy:**

| Task | Arguments | Practical meaning |
| --- | --- | --- |
| Read known entropy values | `-i FILE -hex` or hex lines on standard input | One entropy value per line |
| Enumerate entropy in order | `-start HEX -end HEX [-step HEX]` | Add `-step` to the current entropy until `-end` |
| Examine random points in a range | `-start HEX -end HEX -random [-n N]` | Select bounded entropy windows instead of walking every value |
| Use generator profiles | `-prng`/`-prng64` plus their controls | Build entropy from the selected historical or generic generator |
| Restrict each nibble | `-hexset CHARS -start HEX [-end HEX]` | Enumerate only values made from the chosen hex characters |
| Recover unknown entropy nibbles | mode-scoped `-recovery ... -hexset CHARS` | Replace each `*` with the selected hex alphabet |
| Fan out passphrases or paths | `-pass_thread` or `-der_thread` | Keep one entropy value fixed and distribute the other dimension |

For ordered BIP-39 entropy, keep both boundaries at the intended width. For example, 32 hex characters represent 16 bytes and therefore the usual 12-word BIP-39 entropy size. Leading zeroes are part of that width and should not be removed.

```bash
printf '%s\n' 000102030405060708090a0b0c0d0e0f | \
  ./METAL_CRYPTO_TOOLKIT -entropy -hex -size 16 -lang EN \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

The example uses exactly 16 supplied bytes, builds the English mnemonic/seed path, and checks the selected derivations.

Ordered entropy example:

```bash
./METAL_CRYPTO_TOOLKIT -entropy \
  -start 00000000000000000000000000000000 \
  -end   0000000000000000000000000000ffff -step 1 \
  -size 16 -lang EN -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

The command walks all 65,536 values in the shown 128-bit entropy interval. Each value follows the same entropy-to-mnemonic, seed, path, and target checks as a line read from a file. Full help: `./METAL_CRYPTO_TOOLKIT -entropy -help`.

#### `-bip32 [SUBMODE]`

**Use it for:** the pre-master passphrase/payload flow associated with the BIP32 mode, not for a ready 64-byte master HMAC.

The default profile is the HMAC-SHA256 bip32.org-style path with 50,000 iterations in the basic flow. Numbered pre-transforms are `1=SHA-256`, `2=SHA-512`, `3=Keccak-256`, `4=SHA3-256`, `5=MD5`, and `6=passthrough`. `-iter LIST` controls the selected transform's rounds.

Candidates can be read from `-i`/standard input, enumerated as hexadecimal bytes with `-start/-end/-step`, selected randomly inside a bounded range, generated with `-prng`/`-prng64`, or restricted with `-hexset`. Use `-der_thread` only for the opposite workload: one fixed BIP32 payload with many derivation paths.

```bash
./METAL_CRYPTO_TOOLKIT -bip32 2 -iter 1 -i bip32_inputs.txt -hex \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

The result includes the original payload, iteration value, derivation path, private key, target type, and matched value.

Sequential payload example:

```bash
./METAL_CRYPTO_TOOLKIT -bip32 6 \
  -start 00000000 -end 0000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

This increments the four-byte pre-master payload, not a ready chain code. Submode `6` passes those bytes to the BIP32 mode without an additional numbered pre-transform. Full help: `./METAL_CRYPTO_TOOLKIT -bip32 -help`.

#### `-seed`

**Use it for:** seed bytes that are already past the mnemonic-to-seed stage.

One line is decoded as bytes with `-hex`, otherwise as raw/text input. The effective seed path accepts up to 64 bytes. Derive it with `-d`/`-d-type` or use `-der_thread` for a large path list.

The seed source can be a file, standard input, a sequential `-start/-end` range, a bounded random range, an internal PRNG profile, or a `-hexset` range/template. In sequential mode, the width of `-start` determines the meaningful seed width, up to 64 bytes; preserve leading zeroes when testing a fixed-width seed format.

```bash
printf '%s\n' 000102030405060708090a0b0c0d0e0f | \
  ./METAL_CRYPTO_TOOLKIT -seed -hex -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

The found source is labeled `seed:` and includes the path and matched key result.

Sequential seed example:

```bash
./METAL_CRYPTO_TOOLKIT -seed \
  -start 00000000000000000000000000000000 \
  -end   0000000000000000000000000000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

This walks 16-byte seed values in order. It does not run BIP-39 PBKDF2 because the selected mode treats every candidate as an already prepared seed. Full help: `./METAL_CRYPTO_TOOLKIT -seed -help`.

#### `-hmac`

**Use it for:** ready BIP32 master material `I_L || I_R`: 32 bytes of master private/scalar material followed by a 32-byte chain code.

For file or standard-input work, the mode builds a zero-initialized 64-byte master buffer. With `-hex`, it decodes at most the first 128 hex characters into that buffer; without `-hex`, it copies at most the first 64 input bytes. A shorter value is therefore right-padded with zero bytes. Use exactly 128 valid hex characters when an exact `I_L || I_R` value is required. This mode does not run the mnemonic PBKDF2 step again.

HMAC master values can be read from a file/standard input, enumerated in a 64-byte `-start/-end` range, selected randomly inside that range, produced by a PRNG profile, or generated from a restricted `-hexset`. This is a specialized mode: the sequential counter changes the complete `I_L || I_R` value, including the chain-code half.

```bash
printf '%0128d\n' 0 | ./METAL_CRYPTO_TOOLKIT -hmac -hex \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

The all-zero value is only a format demonstration. Invalid master values are rejected by the active derivation logic.

Sequential HMAC example:

```bash
./METAL_CRYPTO_TOOLKIT -hmac \
  -start 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 \
  -end   0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000ffff \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Both boundaries contain 128 hex characters: 64 bytes of master material. Full help: `./METAL_CRYPTO_TOOLKIT -hmac -help`.

### Private keys and historical key-generation modes

#### `-priv [SUBMODE]`

**Use it for:** raw private keys, bounded scalar ranges, or one of the explicit mutation strategies.

With `-hex`, file/stdin input is normalized in 64-character chunks: a shorter final chunk is left-padded with zeroes, up to two chunks can be taken from the first 128 characters, and later characters are ignored. Without `-hex`, the equivalent unit is a 32-byte raw chunk with zero-byte left padding. For predictable one-key-per-line input, use exactly 64 valid hex characters or exactly 32 raw bytes. A derivation file is not required.

**Main ways to run `-priv`:**

| Workflow | Arguments | What happens |
| --- | --- | --- |
| Private keys from a file | `-priv -hex -i keys.txt` | Prefer one exact 64-hex-character key per line; shorter and longer lines are normalized as described above |
| Private keys from a pipe | `producer | ./METAL_CRYPTO_TOOLKIT -priv -hex ...` | The same line format is read from standard input |
| **Priv Seq: ordered range** | `-priv -start HEX -end HEX [-step HEX]` | Private keys are checked in numerical order between the boundaries |
| Backward or two-sided walk | add `-back` or `-both` | Walk down from the start or process positive and negative directions |
| Random points in a range | add `-random [-n N]` | Select windows inside the bounded private-key interval |
| Internal generator families | `-prng`/`-prng64` and their controls | Produce private-key bytes from a selected generator profile |
| Restricted hex alphabet | `-hexset CHARS -start HEX [-end HEX]` | Enumerate only private keys made from the selected nibbles |
| Incomplete private key | `-priv -recovery -i templates.txt` or stdin | Fill each unknown nibble marked with `*` from the complete `0..f` alphabet |
| Mutations of supplied keys | `-priv 0` through `-priv 6` | Apply one explicitly selected transformation from the table below |

**Fast Priv Seq path.**

For an ordered `-start/-end` walk whose selected targets consist only of the secp256k1 families `c`, `u`, `s`, `p`, `r`, `e`, and `x`, the program automatically selects specialized Vanity-walk kernels. They calculate the starting curve point and then advance through adjacent private keys with repeated elliptic-curve point additions instead of performing a complete scalar multiplication for every key.

This path is especially important for direct Bitcoin compressed/uncompressed/P2WPKH/P2WSH/Taproot checks, Ethereum, and public-key X-coordinate searches. On suitable Apple Silicon hardware, a simple single-target-family run can exceed one billion checks per second. This is not a fixed guarantee: combining target families, adding large filters, enabling extra checks, changing the step, or selecting ed25519/sr25519 and other network families changes the kernel and its speed.

The fast path is automatic. Start with the default automatic grid, `-keys 1024`, and `-chunk 1`; these arguments normally should not be added to the command. The program falls back to the general private-key kernel whenever the selected targets require other curves or network-specific processing.

| Submode | Operation |
| --- | --- |
| omitted | basic private-key mode |
| `0` | 256-bit circular-left-rotation combinations |
| `1` | brute-force `00..FF` in selected byte positions |
| `2` | random byte-change combinations |
| `3` | 16 SHA-256 plus 16 Keccak variants per key |
| `4` | increment each next-byte pattern |
| `5` | increment over all bytes |
| `6` | repeat the first N hex symbols across the 64-nibble key |

For submode 1, `-pb 1,2,3-10` selects byte positions; the default is 1 through 32. In submode 6, `-pb` selects pattern lengths and `-last` cycles the last hex nibble through `0..f`.

`-scalar` interprets the 32-byte input as an ed25519 scalar; `-LE` makes that scalar little-endian. `-shash` interprets it as an ed25519 seed hash before clamping. These switches matter for ed25519 target families, not ordinary secp256k1 keys.

```bash
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end 100000 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 \
  -save -o priv_found.txt
```

This is Priv Seq: it checks every private key from `0x01` through `0x100000` in order and automatically uses the compressed-Bitcoin Vanity-walk kernel. To read ready private keys instead, use `./METAL_CRYPTO_TOOLKIT -priv -hex -i keys.txt ...`. Full help: `./METAL_CRYPTO_TOOLKIT -priv -help`.

#### `-priv -recovery`

**Use it for:** a 64-nibble hexadecimal private key with known and unknown positions.

Templates are read one per line from `-i FILE` or standard input; no inline template follows `-recovery`. Each line must contain exactly 64 positions and no more than 32 `*` characters. Every `*` always tries the complete hexadecimal alphabet `0..f`; `-hexset` is not supported in this workflow.

```bash
printf '%s\n' \
  '00000000000000000000000000000000000000000000000000000000000000**' | \
  ./METAL_CRYPTO_TOOLKIT -priv -recovery -c c \
    -hash 00112233445566778899aabbccddeeff00112233 -save
```

The result contains the completed private key and the target value that matched.

#### `-kangaroo`

**Use it for:** recovering a secp256k1 private scalar `k` from its complete
public key `Q = kG` when `k` is known to lie inside a bounded interval.

This is a native Metal implementation of the RCKangaroo collision search. It is
not a linear private-key scan. Work grows approximately with the square root of
the interval width, so range width matters far more than the number of
hexadecimal digits in its endpoints.

Every target must be a complete 33-byte compressed or 65-byte uncompressed
secp256k1 public key. `-target` can be repeated and can also name a text file
containing one key per line; blank lines and `#` comments are ignored, and text
after the first token is allowed. Duplicate curve points are computed once.
An address, HASH160, Ethereum address, x-only public key, Bloom filter, or XOR
filter is not enough because the algorithm needs the complete curve point.
Kangaroo writes verified results directly through `-o`; ordinary target-family
switches such as `-c`, `-save`, and `-i` do not belong to this mode.

One unique target keeps the independently tuned single-target contour. Two or
more unique targets automatically select the real multi-target contour: all
targets share one tame herd and receive target-indexed positive and negative
wild herds. This avoids rebuilding or repeating the tame third for every
target. Targets are processed in bounded resident windows, while tame DPs are
retained and wild DPs are discarded between windows. Consequently, the
resident GPU allocation does not grow with the complete target count.

`-kangaroo-mem` controls the working-set ceiling. `auto` uses at most 25% of
the currently free recommended Metal working set. `all` permits everything
except a 512 MiB runtime reserve; there is no fixed 16 GiB ceiling. A
percentage or an exact MiB/GiB size can also be supplied. This value is a
ceiling, not a command to waste memory: the tuned single-target contour and a
small target window keep only the walkers that can do useful work. On Apple
Silicon, CPU and GPU use the same physical memory, and a multi-device request
is divided between the selected device replicas.

For very large arithmetic target families, use the compact
`-kangaroo-shifts START:COUNT[:STEP]` source instead of writing millions of
public keys to a file. It represents
`Q_i = Q - (START + i*STEP)G` without materialising those points. `START` and
`STEP` are hexadecimal scalars; `COUNT` is decimal, `0xHEX`, or `2^EXP`.
Overlapping shifted intervals are exactly collapsed into their scalar-range
union. Sparse intervals are generated incrementally and processed through the
same bounded target windows. A derived-key hit is converted back to the base
private scalar and both public points are verified before output.

**Range formats:**

| Form | Interval searched |
| --- | --- |
| `-range 64` | `[2^63, 2^64)` |
| `-range 65-72` | each complete bit interval from 65 through 72 bits, in order |
| `-range 64,67,70-72` | the listed complete bit intervals, in order |
| `-range START:END` | one exact hexadecimal interval `[START, END)` |

`START` is inclusive and `END` is exclusive. An exact `START:END` interval
cannot be combined with another `-range`. The accepted scalar domain is
`0 <= START < END <=`
`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`,
the secp256k1 group order. A 256-bit bit range starts at `2^255` and ends at
that group order.

**Main arguments:**

| Argument | Meaning |
| --- | --- |
| `-target HEX\|FILE` / `-hash HEX` | repeat a complete public key, or load a target file; two or more unique points enable the multi-target contour |
| `-range VALUE` | one or more bit ranges, or one exact hexadecimal interval |
| `-kangaroo-shifts START:COUNT[:STEP]` | compact arithmetic family `Q-(START+i*STEP)G`; no expanded target file |
| `-kangaroo-mem auto\|all\|NN%\|SIZE` | walker and resident-target budget; bare sizes are MiB, and `MiB`/`GiB` are accepted |
| `-device LIST` | Metal devices such as `0`, `0,1,3`, or `0-3`; all available devices are used when omitted |
| `-dpbits N` | distinguished-point bits, `14..60`; selected automatically when omitted |
| `-lim N` | maximum operation factor; selected automatically when omitted |
| `-jumps N` | power-of-two jump-table size from 8 through 512; default `512` |
| `-kangsteps N` | steps per Metal launch, `256..8192`; default `1000` |
| `-exp LIST` | explicit exponent chain, for example `255,192,128` |
| `-first N -last N [-prob P]` | repeatedly generate a descending random exponent chain; `P` defaults to `0.5` |
| `-kangaroo-dp-dir DIR` | tame distinguished-point cache directory |
| `-kangaroo-dp-rebuild` | ignore and rebuild the selected tame cache |
| `-no-kangaroo-dp-cache` | disable tame-cache loading and saving |
| `-o FILE` | append verified results; default `result.txt` |
| `-log` | append range diagnostics to `_local_artifacts/kangaroo.log` |

Start with automatic `-dpbits` and `-lim`, the default jump table, and the
default automatic Metal grid. Increase `-dpbits` if the program reports DP
output overflow; higher values make distinguished points rarer. Increasing
`-kangsteps` reduces host synchronization but makes each launch longer. A very
small `-lim` can stop a valid search before a collision is found.

**Example 1 — known scalar in an exact interval.**

The public key below belongs to scalar `0x2a`. This example searches the
exclusive-end interval `[0x1, 0x100)`:

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af \
  -range 1:100 \
  -no-kangaroo-dp-cache \
  -o kangaroo-known-key.txt
```

The final `priv:` field is:

```text
000000000000000000000000000000000000000000000000000000000000002a
```

**Example 2 — a complete 64-bit interval on one GPU.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_33_OR_65_BYTE_PUBLIC_KEY_HEX \
  -range 64 \
  -device 0 \
  -o kangaroo-64.txt
```

This searches `[0x8000000000000000, 0x10000000000000000)`. Replace the
placeholder with the full public key, not an address derived from it.

**Example 3 — several bit intervals and two Metal devices.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 65-68 \
  -device 0,1 \
  -kangaroo-dp-dir ./kangaroo-cache \
  -o kangaroo-multigpu.txt
```

The first run builds reusable tame-point caches. A later run with the same
range, DP settings, and jump count can reuse them. Use
`-kangaroo-dp-rebuild` after intentionally changing or replacing cache
material.

**Example 4 — explicit RCKangaroo-style exponent decomposition.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 64 \
  -exp 255,192,128 \
  -device 0 \
  -o kangaroo-exp.txt
```

The mode subtracts the sum of the selected powers of two from the public point,
solves the bounded remainder, then verifies the reconstructed full private key.
Use `-exp` only when that decomposition is intentional. Alternatively,
`-first 255 -last 128 -prob 0.5` generates descending random chains until a
solution is found; `-exp` and `-first/-last` are mutually exclusive.

**Example 5 — shared-tame multi-target search.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02FIRST_COMPLETE_PUBLIC_KEY \
  -target 03SECOND_COMPLETE_PUBLIC_KEY \
  -target ./kangaroo-targets.txt \
  -range 64 \
  -device 0 \
  -o kangaroo-multi.txt
```

The file may contain more targets and labels after each key. All unique points
share the same ranges and tame DP cache. Resident target windows prevent the
complete list from becoming one unbounded Metal allocation. The status lines
report `multi-target shared-tame`, logical and resident target counts, walker
count, and actual allocated/selected ceiling/free working-set bytes.

**Example 6 — allow Kangaroo to use the remaining Metal working set.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target ./kangaroo-targets.txt \
  -range 135 \
  -kangaroo-mem all \
  -device 0 \
  -o kangaroo-large-target-set.txt
```

Use `-kangaroo-mem 50%`, `-kangaroo-mem 32GiB`, or a bare MiB value such as
`-kangaroo-mem 32768` for an explicit ceiling. An impossible exact request
fails clearly instead of silently allocating less.

**Example 7 — 100 million shifted puzzle-135 targets without expanding them.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 \
  -kangaroo-shifts 0:100000000:1 \
  -range 135 \
  -kangaroo-mem all \
  -device 0 \
  -o puzzle135-shifted.txt
```

For this dense `STEP=1` family, neighbouring intervals overlap, so the engine
searches their exact union against the original public key. This needs
constant target memory, but it does not create free cryptographic coverage:
the union is only wider than the original interval. Sparse shifts can avoid
overlap, but then each interval contributes real additional search work.

The result block contains `Pub`, `Exps`, `Pub after subtract`, `k_low`, and
`priv`. A sparse compact-source hit additionally contains `Logical target`,
`Shift`, `Base pub`, and the verified `Base priv`. `priv` is the derived
target's scalar; `Base priv` is the reconstructed original scalar. Cache
formats PSWDP2 and PSWDP3 remain compatible with CUDA/RCKangaroo through
170-bit distances.
Wider distances use the PSWDP4 Metal extension with signed 256-bit GPU state.
This makes genuine 256-bit endpoints representable; it does not make a full
256-bit-width search practical on present hardware.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo -help
```

#### `-bsgs`

**Use it for:** deterministic recovery of one or many secp256k1 private
scalars when every complete public key and the bounded scalar interval are
known.

BSGS builds a reusable baby-step table, then searches giant steps for all
still-active targets. Unlike Kangaroo, its table can deliberately consume a
large memory budget to reduce search time. Choose BSGS when the interval is
small enough for a useful table, several targets share the same ranges, or a
cached table will be reused. Choose Kangaroo when memory is limited or a
single wider interval makes a large BSGS table unattractive.

`-target` is repeatable. Its value may be a compressed 33-byte key, an
uncompressed 65-byte key, or a file path. Target files use the first token on
each line; blank lines and lines beginning with `#` are ignored. Compressed
and uncompressed forms of the same point are deduplicated for computation,
while every original target number and source is retained in the result.

For very large arithmetic target families, use
`-bsgs-shifts START:COUNT[:STEP]`. For every base target `Q`, it searches the
logical targets `Q - (START + i × STEP)G`, `0 <= i < COUNT`. `START` and
`STEP` are hexadecimal scalars; `COUNT` is a decimal, `0xHEX`, or `2^EXP`
64-bit count. The sequence must stay below the secp256k1 order. Only each base
point and a bounded work window are resident: even hundreds of millions of
logical targets are not expanded into public-key objects or per-target Metal
buffers. A hit reports the derived target private key, its shift, and the
separately verified private key of the base point.

The `-range` grammar and exclusive upper bound are identical to Kangaroo:

| Form | Interval searched |
| --- | --- |
| `-range 48` | `[2^47, 2^48)` |
| `-range 48-52` | every complete bit interval from 48 through 52 |
| `-range 40,48-52` | the listed bit intervals, in order |
| `-range START:END` | one exact hexadecimal interval `[START, END)` |

An exact interval cannot be mixed with another `-range`. Solved targets are
removed before the next range.

**Memory, table, and cache arguments:**

| Argument | Meaning |
| --- | --- |
| `-bsgs-mem auto` | at most 50% of the currently free recommended Metal working set |
| `-bsgs-mem all` | all remaining recommended working set except a 512 MiB runtime reserve |
| `-bsgs-mem NN%` | a percentage of the currently free recommended working set |
| `-bsgs-mem SIZE` | hard byte budget; a bare number is MiB, or use `MiB`/`GiB` |
| `-bsgs-shifts START:COUNT[:STEP]` | compact arithmetic targets `Q-(START+i×STEP)G` |
| `-bsgs-table N` | exact baby-step count in decimal, `0xHEX`, or `2^EXP` form |
| `-bsgs-table-cache` | opt in to `_local_artifacts/bsgs_tables` |
| `-bsgs-table-dir DIR` | opt in to a cache at `DIR` |
| `-bsgs-table-rebuild` | rebuild the enabled cache |
| `-random` | visit every giant group once in pseudorandom order |
| `-bsgs-random-seed N` | reproducible 64-bit decimal or hexadecimal seed; also enables `-random` |
| `-device LIST` | one or more Metal devices, for example `0` or `0,1` |
| `-o FILE` | append fully verified results; default `result.txt` |

Automatic table sizing balances construction cost against the total remaining
`target × range` giant work using the measured relative throughput of the
baby-build and giant-search pipelines. The model is refined after a complete
range. A compatible ready cache participates with zero table-construction
cost. An explicit `-bsgs-table` is a hard request: the command fails clearly
if it cannot fit inside `-bsgs-mem`. Tables are sharded below the device
`maxBufferLength`, checksummed, and written atomically. Cache use is opt-in; a
corrupt or incompatible shard is never accepted silently.

Random mode does not repeatedly sample arbitrary points and therefore does not
lose exhaustive-search correctness. It applies an O(1)-memory bijective
permutation to the giant-group index. Each round walks 1024 consecutive giant
centers from a pseudorandomly selected group; the next round moves to another
group, and every group is visited exactly once before the range finishes.
All GPUs claim the same logical permutation without overlaps. The selected
seed is printed at startup; use `-bsgs-random-seed` to reproduce an order.

The production backend stores every compact `fingerprint64 + j` candidate,
sorts it once, and adds an adaptive exact bucket index. Fingerprint collisions
can add verification work but cannot hide a match: every candidate is resolved
on the GPU and checked against the complete public point on the CPU. Hit-buffer
overflow is retried by narrowing the giant batch and paging a single collision
chain, without silently dropping hits.

Apple Silicon uses unified memory. CPU table storage, Metal buffers, and every
multi-GPU replica therefore count against the same working set. All selected
devices use the largest common table size that safely fits, and giant groups
are dynamically claimed without overlap, so faster devices naturally take a
larger share. Live rates are reported only by the toolkit's standard
`SpeedThreadFunc`. Search uses the same names as CUDA BSGS: `GStep/s` is the
number of completed giant-center probes per second and `EqKey/s` is effective
unique scalar coverage per second. CUDA's current M-spaced walker reports
`EqKey/s = GStep/s × M`; this Metal negation-map walker advances by `2M`, so it
reports `EqKey/s = GStep/s × 2M`.

**Example 1 — automatic memory and one key.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af \
  -range 1:100 \
  -bsgs-mem auto \
  -o bsgs-known-key.txt
```

**Example 2 — repeated targets and a target file.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -target YOUR_OTHER_FULL_PUBLIC_KEY_HEX \
  -range 40,48-52 \
  -bsgs-mem 16GiB \
  -device 0
```

**Example 3 — an exact expert table with opt-in cache.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -range 1000:2000 \
  -bsgs-table 2^12 \
  -bsgs-mem 4GiB \
  -bsgs-table-cache
```

**Example 4 — maximum safe working-set use and a custom cache.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 64 \
  -bsgs-mem all \
  -bsgs-table-dir /Volumes/Fast/bsgs
```

**Example 5 — complete search in randomized rounds.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -range 56 \
  -random \
  -bsgs-random-seed 0x1234 \
  -bsgs-mem 16GiB
```

**Example 6 — 100 million shifted targets without a 100-million-key file.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 \
  -bsgs-shifts 0:100000000:1 \
  -range 135 \
  -bsgs-mem all
```

This is mathematically a search over the union of the scalar intervals shifted
by the listed offsets. Dense adjacent shifts create heavily overlapping
intervals, so they do not multiply unique coverage for free. The compact mode
removes the memory/loading bottleneck and lets the hypothesis be measured
honestly; it does not change the amount of unique interval work.

Every candidate is checked against the complete target point before it is
printed. Full 256-bit counters and endpoints prevent truncation, but they do
not make an exhaustive 256-bit discrete-log search practical on current
hardware.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -bsgs -help
```

#### `-vanity`

**Use it for:** generating a new secp256k1 key whose address matches a human
chosen prefix, suffix, or wildcard pattern. This mode searches newly generated
keys; it does not recover an existing wallet from an address.

Supported families are BTC compressed and uncompressed P2PKH, nested
P2SH-P2WPKH, native Bech32 P2WPKH, lowercase Ethereum, and TRON. Prefix a
pattern with `p2pkh:`, `p2pkh-u:`, `p2sh:`, `bech32:`, `eth:`, or `tron:`.
The family is also inferred from an initial `1`, `3`, `bc1q`, `0x`, or `T`.
A pattern with no wildcard is treated as a prefix. `*suffix` searches a suffix,
and `?` matches exactly one address character.

`-pattern` is repeatable. `-pattern-file` reads one pattern per line, ignores
blank lines and `#` comments, and deduplicates identical family/pattern pairs.
The search stops when every unique pattern has one verified result or the
interval is exhausted.

| Argument | Meaning |
| --- | --- |
| `-pattern VALUE` | add one typed or auto-detected pattern |
| `-pattern-file FILE` | load line-oriented patterns |
| `-start N -end N` | exact private-key interval `[START,END)`; decimal or `0x` hex |
| `-random` | cover the same interval once from a random cyclic rotation |
| `-n N` | candidates per Metal launch |
| `-device LIST` | selected Metal device indexes |
| `-split-key PUBKEY` | search `k_partial*G + PUBKEY` and output only the partial private key |
| `-o FILE` | append fully verified results |
| `-save` | use `VANITY_FOUND.txt` when `-o` is absent |
| `-silent` | suppress found lines on stdout, without disabling output |

Random mode is still exhaustive: it rotates the checked interval rather than
sampling with replacement. Split-key mode never knows the owner's secret
scalar. Its result is labelled `PARTIAL_PRIVATE`; the owner combines it with
the secret share modulo the secp256k1 order. Every Metal hit is independently
re-derived and fully address-encoded on the host before it is printed.

```bash
./METAL_CRYPTO_TOOLKIT -vanity \
  -pattern 1Metal \
  -pattern 'eth:0xdead*' \
  -random \
  -save
```

```bash
./METAL_CRYPTO_TOOLKIT -vanity \
  -pattern-file vanity-patterns.txt \
  -split-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -start 1 -end 0x100000000 \
  -device 0 \
  -o partial-vanity.txt
```

Search difficulty grows exponentially with the number of constrained address
characters. Mixed-case Ethereum checksum patterns are not generated by this
mode; Ethereum matching is lowercase hexadecimal. Statistics are emitted only
by the standard `SpeedThreadFunc` as completed `Key/s`.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -vanity -help
```

#### `-create2`

**Use it for:** finding a CREATE2 salt that makes one fixed deployer and one
fixed initialization-code hash produce an Ethereum address matching a chosen
hexadecimal pattern. This mode searches salts, not private keys.

CREATE2 uses the exact EIP-1014 expression
`keccak256(0xff || deployer || salt || init_code_hash)[12:]`.
`-deployer` therefore takes exactly 20 bytes and `-init-code-hash` exactly
32 bytes. The latter is already `keccak256(init_code)`, not raw bytecode.
Patterns are lowercase, non-checksummed `0x` Ethereum addresses. `-pattern`
is repeatable, and `-pattern-file` ignores blank lines, comments, and
duplicates.

| Argument | Meaning |
| --- | --- |
| `-deployer 0xADDRESS` | fixed 20-byte deployer/factory |
| `-init-code-hash 0xHASH` | fixed 32-byte Keccak hash of initialization code |
| `-pattern VALUE` | add one prefix/suffix/wildcard address pattern |
| `-pattern-file FILE` | load one pattern per line |
| `-start N -end N` | exact salt or template-ordinal interval `[START,END)` |
| `-mask HEX/?` | 64 salt nibbles; each `?` is filled from the ordinal |
| `-random` | cover a finite interval once from a random cyclic rotation |
| `-n N` | salts per Metal launch |
| `-device LIST` | selected Metal device indexes |
| `-o FILE`, `-save`, `-silent` | verified-result output controls |

Without `-mask`, the 256-bit ordinal is the salt itself. With a mask, unknown
nibbles are filled from right to left in ordinary numeric order; fixed nibbles
stay unchanged. If `-end` is omitted, the complete template domain is used.
`-end 2^256` denotes the full remaining U256 domain, but cannot be combined
with `-random`. Hit-buffer overflow is retried before work is credited, and
every returned address is independently recomputed on the host.

Official EIP-1014 example 0 (`init_code = 0x00`):

```bash
./METAL_CRYPTO_TOOLKIT -create2 \
  -deployer 0x0000000000000000000000000000000000000000 \
  -init-code-hash 0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a \
  -pattern 0x4d1a \
  -start 0 -end 65536 \
  -save
```

Template search:

```bash
./METAL_CRYPTO_TOOLKIT -create2 \
  -deployer 0xdead00000000000000000000000000000000beef \
  -init-code-hash 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -pattern 'create2:0x0000*' \
  -mask '000000000000000000000000????????????????????????????????????????' \
  -random -device 0
```

The full U256 scheduler prevents truncation; it does not make exhaustive
256-bit salt search practical. Live statistics are emitted only by the common
`SpeedThreadFunc` as completed `Addr/s`.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -create2 -help
```

#### `-hdpath`

**Use it for:** recovering one or more unknown BIP32 child indexes when the
root seed or extended key and the final secp256k1 public key are known.

Select exactly one root with `-mnemonic`, `-seed`, `-xprv`, `-xpub`, or
`-descriptor`. A descriptor may contain origin metadata and a derivation
suffix. `-target` is repeatable and also accepts a file containing one
compressed or uncompressed public key per line.

Path templates start with `m/`. Fixed indexes, inclusive ranges, and lists may
be mixed:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath \
  -seed 000102030405060708090a0b0c0d0e0f \
  -path-template "m/{0-15}'" \
  -target 035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56
```

A wildcard uses one finite half-open interval:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath \
  -xpub xpub... \
  -path-template "m/0/*" \
  -start 0 -end 100000 \
  -target targets.txt \
  -wallet-mem auto -device 0 -save
```

The domain is scheduled as checked U256 mixed radix and windows are credited
only after Metal completion and successful readback. CKDpub cannot derive
hardened children and therefore rejects apostrophe or `h` components when the
root is public. A result from xpub contains the verified path and public key
but no private key.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath -help
```

#### `-priv -hamming`

**Use it for:** searching a bounded set of private keys that differ from one
known 256-bit base in exactly `k` selected bit positions.

The required value is `BASE:DISTANCE[:MUTABLE_MASK]`. `BASE` and the optional
mask are normal 64-character big-endian hexadecimal strings. A one in the mask
marks a mutable bit; a zero keeps it fixed. Without a mask all 256 bits are
mutable. Bit zero is the most-significant bit of the displayed scalar.

```bash
./METAL_CRYPTO_TOOLKIT -priv \
  -hamming 0000000000000000000000000000000000000000000000000000000000000001:2:00000000000000000000000000000000000000000000000000000000000000ff \
  -target 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 \
  -wallet-mem auto
```

The complete domain has `C(popcount(mask), distance)` candidates.
`-start/-end` select a half-open checked-U256 ordinal subrange in decimal,
`0xHEX`, or `2^EXP` form. `-target` is repeatable and also accepts a file with
one compressed or uncompressed secp256k1 public key per line. `-device` assigns
windows without overlap, large target sets are streamed through bounded Metal
tiles, `-n` controls only the resident launch, and an overflowed hit buffer is
retried before work is credited.

Every result contains the combinadic ordinal, base, distance, mask, verified
private/public key, and original target sources. Live `Key/s` comes only from
`SpeedThreadFunc`. Checked U256 arithmetic prevents truncation; it does not
make a huge Hamming sphere practical.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -priv -hamming -help
```

#### `-minikeys`

**Use it for:** Casascius minikey strings.

Accepted full lengths are 22, 26, and 30 characters and may begin with `S` or lowercase `s`; lowercase is normalized. The corresponding suffix-only forms have lengths 21, 25, and 29. Candidates may come from files/stdin or a Base58 `-start/-end` range. The minikey checksum condition is verified before a private key and targets are created.

```bash
./METAL_CRYPTO_TOOLKIT -minikeys -i minikeys.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

#### `-minikeys -seed`

**Use it for:** deterministic generation of minikey candidates from seed bytes.

`-hex` decodes the seed lines. `-size` or `-sizes` chooses minikey lengths; the default set is `22,26,30`.

```bash
./METAL_CRYPTO_TOOLKIT -minikeys -seed -hex -i seed_values.txt \
  -sizes 22,30 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-profanity`

**Use it for:** reproducing the historical Profanity seed and point-walk process.

| Argument | Meaning/default |
| --- | --- |
| `-s HEX`, `-e HEX` | 32-bit seed bounds |
| `-n N` | rounds per lane; default `2^32` |
| `-offset HEX` | first round; default `1` |
| `-random` | sample seed windows |
| `-random-seeds N` | random seeds per pick |
| `-gpu-split round|seed|foundid` | multi-device partition rule; default `round` |

The mode fixes `-t 256`; its default grid is 16384 by 256, default `-fsize` is 150000, and automatic precompute uses 16 bits. Results include seed, lane/found ID, round, private key, target type, and matched value.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -s 0 -e ff -n 1024 -offset 1 \
  -c e -hash 00112233445566778899aabbccddeeff00112233 -save
```

This is a deliberately small bounded demonstration. A production search domain must be chosen from evidence about the wallet being examined.

#### `-profanity -recovery`

**Use it for:** recovering the Profanity seed, lane/offset, and private key from a known secp256k1 public key produced by the vulnerable Profanity process.

This mode cannot work from an address, HASH160, or Ethereum account alone. `-target`/`-hash` must contain the complete 33-byte compressed or 65-byte uncompressed public key. The recovery process is:

1. The GPU reverse-walks the known public point `Q` through candidate Profanity rounds and lanes.
2. For each candidate basepoint it takes the first 20 bytes of the canonical 32-byte affine-X coordinate.
3. A mandatory GPU XOR filter checks whether that value belongs to a Profanity seed basepoint.
4. Filter hits are resolved through the selected seed32 range and then verified against the complete public key. Probabilistic filter hits therefore cannot become results without exact curve verification.

The filter is not bundled because its source contains one item for every Profanity seed32. With the default `-s 0 -e ffffffff`, it must cover all `4,294,967,296` basepoints. A partial source/filter is valid only when `-s` and `-e` deliberately restrict recovery to the identical seed range. Missing a seed from the filter makes keys from that seed unrecoverable.

Use `tools/profanity_basepoint_generator` to create `PROFANITY_BASEPOINT.txt`. Each line is 40 lowercase hex characters plus `\n`, so the complete text file is exactly `176,093,659,136` bytes (176.09 GB / 164 GiB). Users must build the required Binary Fuse filter themselves with [XopMC/XorFilter](https://github.com/XopMC/XorFilter).

Reference sizes measured for the complete `2^32` source and current filter format are:

| Source/filter | Toolkit switch | Exact bytes | Decimal size | Binary size |
| --- | --- | ---: | ---: | ---: |
| `PROFANITY_BASEPOINT.txt` | not loaded directly | `176,093,659,136` | 176.09 GB | 164.000 GiB |
| `.xor_u` | `-xu` | `36,939,235,376` | 36.94 GB | 34.402 GiB |
| `.xor_c` | `-xc` | `18,471,714,864` | 18.47 GB | 17.203 GiB |
| `.xor_uc` | `-xuc` | `9,235,857,456` | 9.24 GB | 8.602 GiB |
| `.xor_hc` | `-xh` | `4,617,928,752` | 4.62 GB | 4.301 GiB |

These are output sizes, not the RAM required while XorFilter builds them. `-mini` is the practical low-memory builder preset and produces several numbered shards for this `2^32` dataset. Put only one filter format in a directory and pass that directory to Toolkit; all matching shards are loaded. `-max` can produce one large filter file but the current XorFilter documentation warns that large builds can require more than 256 GB RAM.

The compressed `.xor_c` profile is the normal balance between size and false-positive work. `.xor_uc` and especially `.xor_hc` save unified memory but send more candidates to the expensive seed-resolution stage. `.xor_u` uses about 34.4 GiB by itself. `-xx` may additionally load the corresponding `.xor_u` into CPU-visible memory to reject compressed-filter false positives before seed resolution; it does not replace the mandatory GPU filter and adds its full memory cost to the selected GPU filter in Apple Silicon unified memory.

Example filter creation with memory-bounded shards:

```bash
mkdir -p profanity-xc
XorFilter -i PROFANITY_BASEPOINT.txt -compress -mini -check -o profanity-xc

./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 02... -xc profanity-xc -save -o profanity-found.txt
```

To build a different format, replace `-compress` with `-ultra` or `-hyper`, or omit the compression flag for `.xor_u`; then use `-xuc`, `-xh`, or `-xu` respectively. Do not mix formats or an incomplete set of shards in the same directory.

In file mode, `-i` accepts:

```text
<public_key_hex>
<public_key_hex>:<offset_hex>
<public_key_hex>:<offset_hex>:found
```

The third form marks a previously solved line for restartable batches. `-n` is the per-file round/window size (default 16384); single-target `-offset` defaults to 0. `-s` and `-e` select the seed-resolution range and default to the full 32-bit domain.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -xc profanity-xc -save
```

The public key is the well-known secp256k1 generator point and is used only to demonstrate the required 33-byte format. The filter directory must contain a complete, verified Profanity recovery filter for the selected seed domain.

#### `-xp PROFILE`

**Use it for:** explicit replay of a known historical random-generation profile. `PROFILE` is mandatory. This mode should be selected only when the application, runtime, state layout, and approximate time/seed domain are known.

Profile families include:

- OpenSSL and SSLeay state/reseed paths;
- Windows CryptGenRandom state, bridge, XOR, and chain variants;
- Android/Java LCG and runtime-specific random paths;
- MT, Python, NumPy, Go, Rust, PHP, and browser JavaScript families;
- Milk Sad, Trust Wallet, Cake Wallet, Coinpunk, BlueWallet, and related documented incident profiles;
- direct SHA-256, PID-hash, low-bit, timestamp, screen-state, and observed-output paths;
- ethers, React Native, Polkadot, AlphaWallet, SJCL, and other application-specific profiles exposed by the built-in catalog.

<details>
<summary><strong>Canonical XP profile names</strong></summary>

- Trace/input profiles: `cgr-state`, `cgr-bridge`, `cgr-xor`, `cgr-chain`, `cgr-chain-bridge`, `ssleay-stir`, `raw32`, `randbytes`.
- Experimental OpenSSL paths: `openssl`, `openssl:all`, versioned paths, `openssl:path0..path53`, and documented `unknown*` aliases. These are experimental candidate families, not a claim of complete state reconstruction.
- Milk Sad and application aliases: `milksad-bx128`, `milksad-bx192`, `milksad-bx256`, `milksad-bx256-seq`, `bip3x-mingw`, `bip3x-mingw160/224/288/320`, `milksad-bx-ecnew`, `trustwallet`, `trustwallet-ios`, `milksad-trustwallet128-seq`, `milksad-trustwallet-ecnew`, `milksad-minstd-direct`, `milksad-minstd0-direct`, `cakewallet`.
- Runtime/application profiles: `android-bitcoin-wallet`, `android-sha1prng`, `alphaweb3e-tinymt32`, `sjcl-bip32`, `ethers-weakrandom`, `rn-getrandomvalues-mathrandom32`, `polkadot-wasm-asmjs-zero`, `mvw-web3-mathrandom`, `tezosj-java-random`.
- Browser/Randstorm profiles: `walletgenerator-jsbn`, `randstorm`, `randstorm:jsbn`, `randstorm:all`, `randstorm:core-jsbn`, `randstorm:raw32`, `randstorm:pool32`, `randstorm-bytes`, `coinpunk-browserify-jsbn`, `randstorm-pymt`, `randstorm-mwc32`, `randstorm:v8-2011`, `randstorm:v8-2015`, `randstorm:spidermonkey-lcg48`, `randstorm:jsc-weakrandom`, `randstorm:v8-classic-mwc`, `randstorm:v8-alt-mwc`, `randstorm:v8-mwc1616`, `randstorm-v8init`, `randstorm-v8init-bytes`, `randstorm-v8init-pool32`.
- Direct and language-runtime profiles: `phpcoinaddress`, `elliptic-php-rand-hmacdrbg`, `bluewallet-isaac`, `time-lcg-direct`, `time-mt`, `java-lcg-direct`, `sha256-direct`, `pid-hash-direct`, `lowbits-direct`, `pybtc-mt`, `nano-java-random`, `pywallet-ts-weak`.
- Recognized but rejected because the exact layout is not enabled: `cgr-full`, `php-mt-seed`, `v8-xorshift128`, and `openssl-debian`.

Exact suffixes and `-v` values are shown by `-xp -help`; use only suffixes listed for the chosen canonical profile.

</details>

XP controls are profile-specific. Depending on the chosen profile, its help entry may allow `-s/-e`, `-n`, `-once`, `-i`, `-f`, `-v`, `-time-s/-time-e`, `-time-delta`, `-time-events`, `-time-events-repeat`, `-screen-seed X:Y`, `-screen-seed-zero`, `-time-mode state|seed-sec-ms|seed-ms-offset`, `-mileage`, or `-mileage-s/-mileage-e`. Do not assume that every option applies to every profile.

Variant selectors such as `-jsbn`, `-jsbn-lohi`, `-raw32`, `-raw32-lohi`, `-raw32-drop1`, `-raw32-drop1-lohi`, `-pool32`, `-pool32-lohi`, `-hilo`, `-lohi`, `-high-byte`, `-high8`, `-low-byte`, `-low8`, `-byte8`, `-byte8-low-byte`, `-byte8-low8`, `-low-byte-byte8`, and `-low8-byte8` are XP profile variants, not global key-search switches.

Because profiles have different input layouts, a single static example would be misleading. Print the catalog and copy the example belonging to the exact profile:

```bash
./METAL_CRYPTO_TOOLKIT -xp -help
```

A small bounded direct-profile example is:

```bash
./METAL_CRYPTO_TOOLKIT -xp sha256-direct:decimal \
  -s 0 -e ff -n 1 -c e \
  -hash 00112233445566778899aabbccddeeff00112233
```

It hashes decimal strings for the numeric domain `0x00..0xff`; it does not stand in for any other XP profile.

The result record begins with the selected profile and includes the replay state (seed, time, PID, observed value, or other profile fields), private key, target type, and matched value.

### Brainwallet and legacy seed modes

#### `-warpwallet`

**Use it for:** exact historical memory-hard password-to-key schemes. These
profiles are intentionally separate from `-brain`, because changing even one
scrypt/PBKDF2 parameter produces a different private key.

| Profile | Derivation |
| --- | --- |
| `warp:SALT` | WarpWallet scrypt `N=2^18,r=8,p=1` XOR PBKDF2-HMAC-SHA256 `c=2^16` |
| `brainwallet.io:SALT` | brainwallet.io scrypt followed by lowercase-hex SHA-256 |
| `brainv2:SALT` | exact three-stage Brainv2 scrypt construction |
| `rush:PREFIX!CHECKSUM10HEX` | RushWallet URL fragment; `rush:PREFIX!` is also accepted when the checksum is unavailable |

Supply one literal password or a line-oriented file with repeatable `-pass`
or `-i`. Supply repeated 20-byte hash160/P2PKH targets or target files with
`-target`. Password files and target tables are processed in bounded windows;
the KDF and secp256k1 point are calculated once per password even when the
target set spans many Metal shards.

```bash
./METAL_CRYPTO_TOOLKIT -warpwallet \
  -profile 'rush:rush!e61ae7a87d' \
  -pass 'correct horse battery staple' \
  -target 1895f1392560ed5467adf9bed7dd4c37443bdfba \
  -wallet-mem auto
```

`-wallet-mem auto|all|NN%|SIZE` is the total unified-memory ceiling.
`-wallet-scrypt-mem SIZE` can impose a stricter scrypt-scratch ceiling, and
`-n N` caps active password lanes. Brainv2 is exceptionally expensive: one
candidate contains 258 scrypt invocations. GPU execution improves throughput
but does not make a large unknown password space easy.

Results are written as `WARPWALLET_FOUND` records with profile, exact target,
password, private key, and target source. Every record is fully re-derived on
the host before output. Live statistics come only from `SpeedThreadFunc` and
use `KDF/s`.

#### `-brain [SUBMODE]`

**Use it for:** turning each text/byte candidate directly into private-key material through an explicit hash profile.

| Value | Operation |
| --- | --- |
| omitted | SHA-256 |
| `1` | SHA3-256 |
| `2` | Keccak-256 |
| `3` | BLAKE2b-256 |
| `4` | pass through bytes |

`-iter` repeats the selected transform. Sequential, PRNG, file-combination, and mode-scoped hexadecimal-template sources are available.

Named profiles use `-brain-profile sha256|brainflayer-sha256|brainwallet.org|bitaddress|bitcoinjs|sha256d|sha256-hex|sha3-256[d]|keccak256[d]|blake2b-256[d]|raw`. A named profile owns the transform, iteration count, and binary/hex chaining.

For streamed dictionary mutation, `-brain-rules FILE` accepts the documented hashcat-compatible core (`: l u c C t r d pN f q { } [ ] k K $X ^X TN DN 'N xNM sXY @X iNX oNX zN ZN`). `-brain-combine FILE` joins each left candidate with a right dictionary; `-brain-combine-mode lr|rl|both` selects the order and `-space` inserts one space. These options operate on text input and are intentionally rejected with `-hex` or internal seq/PRNG/template sources.

```bash
./METAL_CRYPTO_TOOLKIT -brain -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save

./METAL_CRYPTO_TOOLKIT -brain -brain-profile sha256d \
  -brain-rules best64.rule -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233

./METAL_CRYPTO_TOOLKIT -brain -brain-profile sha256 \
  -i left.txt -brain-combine right.txt -brain-combine-mode both -space \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

Found records contain the visible candidate, its hexadecimal bytes, iteration count, private key, target type, and match.

#### `-old`

**Use it for:** old Electrum v1 mnemonic phrases.

One line contains one phrase. `-deep N` controls the child-key depth and defaults to 20. `-valid` additionally classifies source lines into `Valid.txt` and `NotValid.txt`. PRNG and template sources are available when documented by the mode help.

```bash
./METAL_CRYPTO_TOOLKIT -old -i electrum_v1.txt -deep 20 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-old -seed` and `-old -entropy`

These aliases use old Electrum seed bytes instead of phrase words. With `-hex`, each line contains hexadecimal seed bytes. They support file/stdin, compatible ranges, PRNG, templates, and `-deep`.

```bash
./METAL_CRYPTO_TOOLKIT -old -seed -hex -i old_seeds.txt -deep 20 \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

#### `-armory`

**Use it for:** Armory Easy16 paper-backup text.

One input line contains the Easy16 blocks, either contiguous or separated with `%`. `-deep` controls child-key depth. This is not the same as password recovery for an encrypted `.wallet` file.

```bash
./METAL_CRYPTO_TOOLKIT -armory -i easy16_backups.txt -deep 30 \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

#### `-root [SUBMODE]` / `-armory -root`

**Use it for:** a 32-byte Armory root or a 64-byte root plus chain code.

| Value | Pre-processing |
| --- | --- |
| `0` or omitted | normal root path |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | the active kernel converts the input bytes to lowercase hexadecimal ASCII; the current CLI banner labels this profile `BLAKE2b-256`, so do not treat that label as the implemented transform |
| `7` | pass through |

```bash
./METAL_CRYPTO_TOOLKIT -root 0 -hex -i roots.txt -deep 30 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-walletjs PROFILE`

**Use it for:** a specific JavaScript/browser wallet generation process.

Accepted password profiles:

- `cryptojs-sha256`
- `bitaddress-sha256`
- `brain-sha256`

Accepted bounded JSBN/ARC4 profiles:

- `jsbn-arc4-v8-2011`
- `jsbn-arc4-v8-2015`
- `jsbn-arc4-spidermonkey-lcg48`
- `jsbn-arc4-jsc-weakrandom`
- each name above with the `-exact` suffix

SHA-256 profiles accept dictionaries, masks, and raw byte ranges. Browser-state profiles use hexadecimal `-s/-e`, optional `-random`, and `-n`. If bounds are omitted, the program uses the finite default domain `0x0000000000000000..0xffffffffffffffff`, which contains exactly `2^64` states and is normally impractical to exhaust.

Exact profiles additionally require `-time-s` and `-time-e`; `-time-delta N` checks the second time seed from `time0` through `time0 + N` milliseconds. The default delta is 0 and the maximum is 1024.

```bash
./METAL_CRYPTO_TOOLKIT -walletjs cryptojs-sha256 -i passwords.txt \
  -c e -hash 00112233445566778899aabbccddeeff00112233 -save
```

At least one secp256k1 target letter from `c,u,s,p,r,e,x` is required. Results use:

```text
WALLETJS:<profile>:SOURCE:<source>:PRIV:<64_hex>:<TYPE>:<value>
```

### Wallet password recovery

#### Common rules

Wallet modes are standalone: select exactly one artifact mode. `-walletscan` only inventories supported signatures and secret-like records. In a password-recovery mode, provide wallet artifacts and one of the three candidate sources below; `-wallet-load-only` is the exception because it stops after parsing and grouping the artifacts.

Candidate sources:

- one or more `-i FILE` dictionaries; `-hex` modifies dictionary parsing so each line represents password bytes in hexadecimal;
- `-mask` or `-mask-file`, optionally with `-cs1` through `-cs4`;
- a raw byte range `-start HEX [-end HEX]`.

Passwords are limited to 127 bytes and masks to 64 positions. Mask and raw-range sources are mutually exclusive. Generic `-all`, `-delete`, `-comb`, `-space`, and `-rep` are not wallet-artifact controls.

Add `-save` when a wallet-password, WalletJS, XP, Profanity, or inventory finding must be written to the file selected by `-o`. Without `-save`, these specialized modes report findings only on the terminal unless `-silent` is active.

Artifact controls:

| Argument | Meaning |
| --- | --- |
| files after the mode | explicit wallet/hash files; most modes accept several |
| `-f DIR` | recursively find extensions accepted by that wallet mode |
| `-wallet-load-only` | parse, validate, group, and report targets, then exit before checking passwords |
| `-wallet-dry-run` | alias for `-wallet-load-only` |
| `-wallet-mem auto\|all\|NN%\|SIZE` | unified wallet working-set budget for v16 modes that explicitly advertise it; enabled for BIP38, Substrate wallets, and mnemonic scramble |
| `-wallet-scrypt-mem MiB` | scratch-memory cap for modes that actually use scrypt/KdfRomix |

`-wallet-mem auto` uses at most half of the currently free recommended Metal working set. `all` uses the remaining recommended set minus a 512 MiB runtime reserve; percentages are relative to the current free set. On Apple Silicon, host-visible tables and every Metal-device replica consume the same unified-memory pool. The automatic scrypt scratch target starts at 16384 MiB; BIP38 uses a measured 32768 MiB target when no explicit scrypt cap is supplied. When the total input size of the regular GPU filters reaches 8 GiB, the target falls back to 4096 MiB. The final allocation is also bounded by `-wallet-mem`, available unified memory, and the scratch size of one job. An explicit `-wallet-scrypt-mem` is a strict cap and fails if one job cannot fit.

Do not pass `-hash` or `-target` to wallet-password modes. Their verification target comes from the wallet artifact itself.

#### `-keystore`

**Artifacts:** Ethereum JSON V3, compatible embedded JSON/LevelDB values, or:

```text
$ethereum$s*N*r*p*salt*ciphertext*mac
```

Supported paths are PBKDF2-HMAC-SHA256 or scrypt followed by AES-128-CTR and MAC verification. Directory scanning recognizes `.json`, `.key`, `.keystore`, `.txt`, `.hash`, `.log`, `.ldb`, extensionless files, and `UTC--*`/`UTC_*` names. One immediate file follows `-keystore`; use `-f` for collections. `-n` caps concurrent scrypt jobs, default 64. This mode does not accept `-wallet-scrypt-mem`.

```bash
./METAL_CRYPTO_TOOLKIT -keystore wallet.json -i passwords.txt \
  -save -o keystore_found.txt
```

Full recovery result:

```text
KEYSTORE:<source>:PASSWORD:<password>:PRIV:<64_hex>:ETH:<0x_address>
```

MAC-only imported records use:

```text
KEYSTORE:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:web3-secret-storage-mac
```

#### `-walletdat`

**Artifacts:** Bitcoin Core Berkeley DB/raw files containing method-0 `mkey` and `ckey`, or extracted lines:

```text
$bitcoin$<mkey_len>$<mkey_hex>$<salt_len>$<salt_hex>$<iterations>$<ckey_len>$<ckey_hex>$<pubkey_len>$<pubkey_hex>
```

Normal directory mode scans `.dat`; `-scan-all` inspects every file. The repeated SHA-512 KDF derives the AES key/IV, then the master key and ckey/public-key relation are checked.

| Argument | Default | Meaning |
| --- | --- | --- |
| `-walletdat-max-ckey N` | `8` | encrypted ckeys retained per wallet; `0` means unlimited |
| `-walletdat-kdf-work N` | `1000000` | staged KDF work per processing chunk |
| `-walletdat-max-iter N` | `0` | reject targets above N; `0` means no cap |
| `-walletdat-min-jobs N` | `0` | minimum grouped jobs; `0` means automatic |
| `-walletdat-kdf-loop N` | `16384` | iterations per staged KDF loop |

```bash
./METAL_CRYPTO_TOOLKIT -walletdat wallet1.dat wallet2.dat \
  -i passwords.txt -save -o walletdat_found.txt
```

Results contain either `PRIV/PUBKEY` or an `MKEY` fingerprint for a master-key-only record.

#### `-browservault`

**Artifacts:** browser extension data, LevelDB files, and exported JSON/text records. MetaMask records contain `data`, `iv`, and `salt`; Phantom records contain `encrypted`, `nonce`, `salt`, and `kdf`; Atomic records use a Base64 OpenSSL/CryptoJS `Salted__` value. Active profiles are:

- MetaMask browser-passworder: PBKDF2-HMAC-SHA256 plus AES-256-GCM;
- Phantom: PBKDF2 or scrypt plus XSalsa20-Poly1305 secretbox;
- Atomic: CryptoJS/OpenSSL MD5 EVP_BytesToKey plus AES-256-CBC.

`-wallet-scrypt-mem` affects only Phantom scrypt records.

```bash
./METAL_CRYPTO_TOOLKIT -browservault -f browser_data \
  -i passwords.txt -save -o browser_found.txt
```

Result:

```text
<WALLET_PREFIX>:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:<exact_profile>
```

`VAULT:<sha256>` is an artifact fingerprint, not decrypted vault content.

#### `-copaywallet`

This mode recovers passwords for encrypted Copay and BitPay wallet backups
created with the standard SJCL JSON format. Pass one or more files directly
after the mode, or use `-f DIR` to recursively scan `.json` and extensionless
files.

The loader requires explicit `v`, `iter`, `ks`, `ts`, `mode`, `cipher`,
`adata`, `salt`, `iv`, and `ct` fields. The supported profile is SJCL version
1 with PBKDF2-HMAC-SHA256, AES-128-CCM, a 64-bit authentication tag, empty
associated data, and the exact SJCL nonce clamp. Unknown versions, altered
key/tag sizes, non-empty associated data, malformed Base64, oversized
ciphertexts, and unsupported ciphers are rejected before GPU work.

Metal derives the key and verifies the complete CCM tag. Targets sharing the
same KDF parameters and salt reuse a single PBKDF2 result. `-wallet-mem`
controls the unified-memory working set, `-device` selects Metal devices, and
the common `SpeedThreadFunc` is the only live printer of completed `KDF/s` and
actual `Verify/s`.

```bash
./METAL_CRYPTO_TOOLKIT -copaywallet wallet-backup.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -copaywallet -f copay_backups \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o copay_found.txt
```

The result identifies the source, recovered password, authenticated backup
fingerprint, and exact profile. This mode does not parse arbitrary modern
BitPay application databases or non-SJCL exports.

#### `-terrawallet`

This mode recovers passwords for the historical Terra Station mobile
exported-key format. Pass raw JSON or its original outer-Base64 form directly,
or use `-f DIR` to scan `.json`, `.txt`, and extensionless files.

The strict loader requires `name`, `address`, and `encrypted_key`. The address
must be a checksum-valid Bech32 `terra1...` identity with exactly 20 payload
bytes. `encrypted_key` must contain a 16-byte hex salt, a 16-byte hex IV, and
an 80-byte Base64 ciphertext. Unknown or altered layouts are rejected before
GPU work.

Metal derives the AES key with PBKDF2-HMAC-SHA1 (100 iterations), decrypts
AES-256-CBC with exact PKCS7 padding, decodes the complete 64-character
private-key hex string, regenerates its compressed secp256k1 public key, and
compares the resulting HASH160 with the exported address. A plausible
plaintext alone is never accepted. Targets with the same salt share one KDF
result; `-wallet-mem` bounds the unified-memory working set.

```bash
./METAL_CRYPTO_TOOLKIT -terrawallet terra-export.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -terrawallet -f terra_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o terra_found.txt
```

Result:

```text
TERRAWALLET:<source>:PASSWORD:<password>:PRIV:<64hex>:ADDRESS:<terra1...>:PROFILE:terra-station-pbkdf2-sha1-aes-256-cbc
```

Only this legacy exported-key profile is supported. Terra mnemonics, hardware
wallets, modern WalletConnect records, and unknown future formats are not
password-recovery targets.

#### `-bitshareswallet`

This mode recovers passwords for the official BitShares 0.x `exported_keys`
JSON format. Pass one or more files directly after the mode, or use `-f DIR`
to scan `.json` and extensionless files.

The strict loader requires a 64-byte hexadecimal `password_checksum` and a
non-empty `account_keys` array. Each account must contain parallel non-empty
`encrypted_private_keys` and `public_keys` string arrays. Encrypted private
keys are exactly 48 AES-CBC bytes. Public keys must use the historical `BTS`
or `BTSX` prefix, decode to a compressed secp256k1 key, and carry the correct
four-byte RIPEMD-160 checksum.

Metal computes `password_key = SHA512(password)` and rejects candidates whose
`SHA512(password_key)` differs from the exported checksum. The first 32 bytes
of `password_key` are the AES-256 key and bytes 32 through 47 are the CBC IV.
After exact PKCS7 validation, the 32-byte plaintext scalar is converted back
to a compressed secp256k1 public key and compared byte-for-byte with the
exported identity. Keys with the same password checksum share one KDF job.
`-wallet-mem` bounds the unified-memory working set.

```bash
./METAL_CRYPTO_TOOLKIT -bitshareswallet exported-keys.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -bitshareswallet -f bitshares_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o bitshares_found.txt
```

Result:

```text
BITSHARESWALLET:<source#account/key>:PASSWORD:<password>:PRIV:<64hex>:PUBKEY:<compressed-hex>:PROFILE:bitshares-0x-exported-keys-sha512-aes-256-cbc
```

Full BitShares wallet databases, watch-only records and unknown containers
are intentionally not treated as this exported-key profile. The common
`SpeedThreadFunc` is the only live statistics printer; target count does not
artificially multiply `KDF/s` or `Verify/s`.

#### `-yoroiwallet`

This mode recovers passwords from Yoroi IndexedDB JSON snapshots containing an
EMIP-3-encrypted BIP32-Ed25519 root key. Pass one or more snapshots directly
after the mode, or use `-f DIR` to scan `.json` and extensionless files.

The strict loader reads the `Key` and `KeyDerivation` tables, accepts only
`BIP32ED25519` key records, and follows the exact encrypted root ->
`1852'` -> `1815'` -> `account'` chain to the stored 64-byte account xpub.
The encrypted root must be exactly 156 bytes:
`salt32 || nonce12 || tag16 || ciphertext96`.

Metal derives the 32-byte encryption key with
PBKDF2-HMAC-SHA512(password, salt, 19162), verifies ChaCha20-Poly1305 with
empty AAD, decrypts the 96-byte root xprv, and performs hardened CIP-1852
derivation. A candidate is reported only when both the derived account public
key and chain code match the IndexedDB identity. Roots sharing one salt reuse
the grouped PBKDF2 job. `-wallet-mem` bounds the unified-memory working set.

```bash
./METAL_CRYPTO_TOOLKIT -yoroiwallet yoroi-indexeddb.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -yoroiwallet -f yoroi_snapshots \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o yoroi_found.txt
```

Result:

```text
YOROIWALLET:<source#root/account>:PASSWORD:<password>:ROOT_XPRV:<192hex>:PROFILE:yoroi-emip3-pbkdf2-sha512-chacha20poly1305
```

Mnemonic recovery, hardware signers, watch-only roots and unknown future
containers are intentionally outside this profile. Authentication plus exact
account xpub regeneration is mandatory. The common `SpeedThreadFunc` is the
only live statistics printer; target count never inflates `KDF/s` or
`Verify/s`.

#### `-monero`

This mode recovers Monero wallets from 25-word legacy mnemonics and 16-word
Polyseed templates. Pass phrases directly through repeatable `-i`, or pass a
text file containing one phrase per line. Empty lines and `#` comments are
ignored. A standalone `?` represents one unknown complete word:

```bash
./METAL_CRYPTO_TOOLKIT -monero \
  -i "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed update vague zinger boxes ornament renting glass gained island nabbing afield calamity ?" \
  -target 4... -monero-lang English -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -monero -i polyseed-templates.txt \
  -target monero-targets.txt -wallet-mem all -device 0 \
  -save -o monero_found.txt
```

`-target` is repeatable and accepts a standard, integrated, or subaddress
string, a target file, or the expert exact form
`SPEND_PUBLIC_HEX:VIEW_PUBLIC_HEX`. Addresses are decoded only after their
network/type prefix and Keccak checksum pass. Duplicate public pairs are
derived once, but every original source occurrence is retained in the result.

The mode embeds all official Monero legacy and Polyseed language lists.
`-monero-lang auto` selects an unambiguous list; use an explicit language for
an all-unknown or otherwise ambiguous template. Legacy CRC32 and Polyseed
GF(2^11) checksums reject candidates before GPU derivation. Encrypted Polyseed
feature phrases are intentionally rejected by this recovery profile.

Metal performs Polyseed PBKDF2-HMAC-SHA256 when required, scalar reduction,
Keccak view-key derivation, and both Ed25519 base-point multiplications once
per checksum-valid candidate. Large target sets are sorted and streamed as
bounded exact-lookup tiles, so target count does not multiply the expensive
derivation or the reported throughput. `-wallet-mem
auto|all|NN%|SIZE` controls the complete unified-memory working set and `-n`
sets an optional candidate-batch cap.

Every GPU hit is reconstructed from its checked U256 ordinal and re-derived
with the official Monero ref10 arithmetic on the host before output:

```text
MONERO_FOUND SCHEME:<legacy|polyseed> LANGUAGE:<name> TARGET:<source> MNEMONIC:<phrase> SPEND_PRIVATE:<64hex> VIEW_PRIVATE:<64hex> SPEND_PUBLIC:<64hex> VIEW_PUBLIC:<64hex>
```

The common `SpeedThreadFunc` is the only live statistics printer and reports
credited `Candidate/s`, primitive operations, exact `Verify/s`, resident and
logical targets, readback time, and the allocated working set. Search size is
exponential in the number of unknown words; checksum pruning and GPU
acceleration do not make arbitrary large unknown-word domains practical.

#### `-monerowallet`

This mode recovers passwords for official Monero software-wallet `.keys`
containers. Provide one or more files with repeatable `-f` or as positional
paths after the mode. `-pass` accepts either one literal password or an
existing line-oriented password file; `-i` adds a password file.

```bash
./METAL_CRYPTO_TOOLKIT -monerowallet -f wallet.keys \
  -pass passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -monerowallet wallet.keys \
  -pass "correct horse battery staple" -wallet-mem all -device 0
```

Metal runs the exact CryptoNight-v0 password KDF as staged init, scratch-fill,
524288-step mixing, fold, Keccak and selected Blake/Groestl/JH/Skein kernels.
Each active password owns a 2 MiB scratchpad. `-wallet-mem
auto|all|NN%|SIZE` limits the complete unified-memory working set; automatic
lane count is reduced after allocation failure, while explicit `-n` is a
strict active-lane count. `-monero-kdf-rounds` defaults to one and should be
changed only for a wallet known to have been created with a different round
count.

Modern ChaCha20/JSON and legacy ChaCha8 portable-account payloads are detected
separately. For modern encrypted secret keys the mode derives the additional
`CryptoNight(base_key || 'k')` memory key before decrypting them. A password
is reported only after canonical scalar checks and exact ref10 regeneration
of the stored spend/view public keys:

```text
[+] MONEROWALLET_FOUND SOURCE:<file> PASSWORD:<quoted> PASSWORD_HEX:<hex> SPEND_PRIVATE:<64hex> VIEW_PRIVATE:<64hex> SPEND_PUBLIC:<64hex> VIEW_PUBLIC:<64hex> PROFILE:<monero-keys-json-chacha20|monero-keys-v0-chacha8>
```

The common `SpeedThreadFunc` is the only live statistics printer. `KDF/s`
counts password candidates completed after Metal command-buffer completion
and readback; wallet count is never used as an artificial multiplier.
Passwords are limited to 127 bytes. Hardware-device containers, custom
background-password profiles, malformed envelopes, and unknown future
versions are rejected rather than heuristically decrypted.

#### `-algorand`

This mode recovers standard Algorand 25-word English mnemonics. Supply one or
more inline phrases/templates or line-oriented files with repeatable `-i`.
Empty lines and `#` comments in files are ignored. A standalone `?` or `*`
means one unknown whole word. Repeatable `-target` accepts a canonical
58-character Algorand address, a raw 32-byte/64-hex Ed25519 public key, or a
file whose first token on each non-comment line is a target.

The first 24 words encode the 32-byte private seed plus one required zero
padding byte. Consequently data word 24 has only indexes `0..7`. Word 25 is
the first little-endian 11-bit chunk of `SHA-512/256(seed)` and is derived
automatically when marked unknown. These structural checks run before the
Ed25519 base-point multiplication.

The official SDK vector can be checked as one finite candidate:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "olympic cricket tower model share zone grid twist sponsor avoid eight apology patient party success claim famous rapid donor pledge bomb mystery security ability often" \
  -target LZTU6HAK53WDO4MJR5Q4O37V2JFBS6J6FSI7UCCRMJR6HBLT5JBFX2XOWM \
  -wallet-mem auto -n 1
```

Unknown data words form a checked mixed-radix U256 ordinal domain. `-start`
and exclusive `-end` select an exact slice; `-end 2^256` denotes the otherwise
unrepresentable upper boundary when all 24 data words are unknown. The
following finite example checks all 2048 values of the first word:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "? cricket tower model share zone grid twist sponsor avoid eight apology patient party success claim famous rapid donor pledge bomb mystery security ability ?" \
  -target LZTU6HAK53WDO4MJR5Q4O37V2JFBS6J6FSI7UCCRMJR6HBLT5JBFX2XOWM \
  -start 0 -end 2048 -wallet-mem all -n 2048
```

With `-scramble`, all 25 input words must be known. They are treated as a
multiset, so repeated words do not create duplicate permutations. This zero
seed vector has only 25 unique placements:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest" \
  -scramble \
  -target HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI \
  -start 0 -end 25 -wallet-mem auto -n 25
```

`-wallet-mem auto|all|NN%|SIZE` limits the complete unified-memory working
set; sizes accept MiB/GiB and `-n` adds a candidate-batch ceiling. A complete
resident target tile uses the measured fused derive/lookup kernel. Larger
sets are processed in bounded exact tiles while candidate derivation is
reused. Duplicate targets are computed once and retain all source labels.

Each found record contains its target and template sources, canonical address,
complete mnemonic, 32-byte seed, and public key. The host independently
repeats padding, SHA-512/256 checksum, Ed25519 derivation, and target matching.
Only the common `SpeedThreadFunc` prints live `Candidate/s`; target count is
not a speed multiplier. English standard mnemonics are the supported profile.
U256 representation and GPU acceleration do not make arbitrarily large
unknown-word or permutation domains practically searchable.

#### `-slip39`

This mode reconstructs the encrypted master secret (EMS) from standard
English SLIP-0039 mnemonic shares and searches its optional passphrase on
Metal. Pass one share per non-comment line through `-recovery FILE`, or repeat
`-recovery "WORDS ..."`. The loader verifies the official RS1024 checksum,
common metadata, group/member indexes and thresholds, the digest shares, and
both levels of GF(256) interpolation. A standalone `?` or `*` repairs one
unknown whole word; at most two unknown words are allowed in each share.

Verification is explicit. `-target` accepts a 64-hex
`SHA256(master-secret)` or a file whose first token on each non-comment line
is such a digest. `-master-secret` accepts a known 16-32 even-byte hex secret
and creates the corresponding target. Duplicate targets are evaluated once
but keep every source label.

This official non-extendable vector performs one finite password check:

```bash
./METAL_CRYPTO_TOOLKIT -slip39 \
  -recovery "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard" \
  -master-secret bb54aac4b89dc868ba37d9cc21b2cece \
  -pass TREZOR -wallet-mem auto -n 1
```

Password sources are repeatable `-pass VALUE|FILE`, streaming `-i FILE`,
`-mask` with `?d/?l/?u/?a/??`, or decimal strings generated by an exclusive
`-start/-end` interval. With no source, the standard empty passphrase is
checked. SLIP-0039 permits printable ASCII only and this mode rejects
passwords longer than 127 bytes.

Metal implements all four reverse Feistel rounds and the exact
`2500 << iteration_exponent` PBKDF2-HMAC-SHA256 work per round. A complete
resident target tile uses fused decrypt/lookup. Larger target sets use a
split path: decrypt and hash once, then reuse the derived data across bounded
target tiles. Every hit is independently decrypted and hashed with
CommonCrypto before output.

`-wallet-mem auto|all|NN%|SIZE` bounds the complete unified-memory working
set, `-device` selects Metal devices, and `-n` caps a completed batch. The
common `SpeedThreadFunc` is the only live printer and reports actual `Pwd/s`,
PBKDF2 primitive work, `Verify/s`, target residency, readback, and allocated
memory. Damaged templates are capped at one million compatible combinations.
This mode verifies the recovered master secret or its SHA256; it does not
claim a wallet derivation path or address from checksum validity alone.

#### `-substratewallet`

This mode recovers passwords for versioned Polkadot/Substrate keyring JSON
exports. Pass one or more files directly after the mode, or use `-f DIR` to
scan `.json` and extensionless files. The loader accepts only authenticated
PKCS8 records using:

- version 3: embedded scrypt parameters plus XSalsa20-Poly1305;
- version 2: legacy password bytes truncated or right-zero-padded to 32 bytes,
  plus XSalsa20-Poly1305.

The `encoding.content` field must explicitly name `pkcs8` and exactly one of
`sr25519`, `ed25519`, or `ecdsa`. The identity may be a checksummed SS58
AccountId32 or a `0x` public key; ECDSA uses a compressed 33-byte secp256k1
key. Unknown versions, invalid checksums, malformed scrypt parameters, and
unsupported encodings are rejected before GPU work.

Metal performs the complete verification. A password is reported only when
the Poly1305 tag, PKCS8 header/divider, embedded public key, exported identity,
and public key regenerated from the decrypted secret all agree. Targets with
identical scrypt parameters and salt share one KDF result. The common
`SpeedThreadFunc` reports completed `KDF/s` and actual `Verify/s`; target count
does not multiply `KDF/s`.

```bash
./METAL_CRYPTO_TOOLKIT -substratewallet account.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -substratewallet -f keyring_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o substrate_found.txt

./METAL_CRYPTO_TOOLKIT -substratewallet account.json \
  -i exact-password-bytes.hex -hex -wallet-scrypt-mem 4096 -save
```

Result:

```text
SUBSTRATEWALLET:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:<substrate-v3-scrypt-pkcs8|substrate-v2-legacy-pkcs8>
```

`VAULT` is a stable encrypted-artifact fingerprint, not decrypted secret
material. Hardware/remote signers, watch-only records, unencrypted exports,
and keyring JSON versions other than 2/3 are not password-recovery targets.

#### `-electrumwallet`

**Artifacts:** Electrum BIE1 storage, encrypted JSON `xprv`/`seed` fields with `pw_hash_version=1`, and:

```text
$electrum$5*<compressed_pubkey_hex>*<cipher_hex>*<mac_hex>
$electrum$2*<iv_hex>*<cipher_hex>
```

BIE1 uses PBKDF2-HMAC-SHA512/1024, ECDH, AES, and HMAC verification. FIELD records use double-SHA256 password material and AES-CBC. Plaintext JSON is reported immediately. BIE2 storage and hardware-style JSON stores are recognized as unsupported and are not checked; this is not a general hardware-wallet parser.

```bash
./METAL_CRYPTO_TOOLKIT -electrumwallet -f electrum_wallets \
  -i passwords.txt -save
```

Result:

```text
ELECTRUMWALLET:<source>:PASSWORD:<password>:TYPE:<BIE1|FIELD|PLAINTEXT>:DETAIL:<sha256>
```

#### `-exodusseco`

**Artifacts:** binary `.seco` version-0 containers tagged `seco-v0-scrypt-aes`. The parser checks metadata, reads scrypt parameters, and verifies AES-256-GCM.

`-f` expects a directory and scans `.seco`; one or more direct files may follow the mode name. `-wallet-scrypt-mem` and `-n` limit active scrypt memory/jobs.

```bash
./METAL_CRYPTO_TOOLKIT -exodusseco -f exodus_wallets \
  -i passwords.txt -save
```

Result:

```text
EXODUSSECO:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:seco-v0-scrypt-aes
```

#### `-bitcoinjwallet` / `-multidogewallet`

**Artifacts:** encrypted bitcoinj, MultiDoge, and Coinomi protobuf wallets. The mode reads `ScryptParameters` and encrypted keys, converts each password to Java UTF-16BE, runs scrypt, decrypts AES-256-CBC/PKCS#7, and compares the derived public key.

Directory scanning accepts `.wallet`, `.dat`, and extensionless files. `-wallet-scrypt-mem` and `-n` control scratch/jobs.

```bash
./METAL_CRYPTO_TOOLKIT -bitcoinjwallet -f protobuf_wallets \
  -i passwords.txt -save
```

Result:

```text
BITCOINJWALLET:<source>:PASSWORD:<password>:PRIV:<64_hex>:PUBKEY:<hex>
```

#### `-armorywallet`

**Artifacts:** encrypted Armory `BA WALLET` files with a root record. The mode validates record checksums, runs KdfRomix(SHA-512), decrypts AES-256-CFB, and compares the stored root public key.

Plaintext Armory files are not password-recovery targets; inspect them with `-walletscan`. `-wallet-scrypt-mem` and `-n` control KdfRomix scratch/jobs.

```bash
./METAL_CRYPTO_TOOLKIT -armorywallet -f armory_wallets \
  -i passwords.txt -save
```

Result:

```text
ARMORYWALLET:<source>:PASSWORD:<password>:PRIV:<64_hex>:PUBKEY:<hex>
```

#### `-stellarwallet`

**Input format:**

```text
$stellar$<salt_base64>$<iv_base64>$<ciphertext_plus_tag_base64>
```

The decoded salt is 16 bytes and IV is 12 bytes. Verification is PBKDF2-HMAC-SHA256 with 4096 iterations plus AES-256-GCM.

```bash
./METAL_CRYPTO_TOOLKIT -stellarwallet stellar.hash \
  -i passwords.txt -save
```

Result:

```text
STELLARWALLET:<source#line>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:stellar-pbkdf2-aes-gcm
```

#### `-blockchainwallet`

**Input formats:**

```text
$blockchain$<declared_len>$<hex_blob>
$blockchain$v2$<iterations>$<declared_len>$<hex_blob>
```

The legacy profile uses 10 PBKDF2-HMAC-SHA1 iterations; v2 reads the count from the line. AES-256-CBC output is checked for plausible wallet JSON. Only the first 64 decoded blob bytes participate in this fast verification, and the declared length field is not a security check.

```bash
./METAL_CRYPTO_TOOLKIT -blockchainwallet blockchain.hash \
  -i passwords.txt -save
```

Result profile: `blockchain-pbkdf2-sha1-aes-cbc`.

#### `-multibitwallet`

**Input formats:**

```text
$multibit$1*<salt_8_bytes_hex>*<data_32_bytes_hex>
$multibit$2*<iv_16_bytes_hex>*<block1_16_bytes_hex>*<block2_16_bytes_hex>
$multibit$3*<N>*<r>*<p>*<salt_8_bytes_hex>*<blob_32_bytes_hex>
```

Profile 1 uses MD5 EVP_BytesToKey and AES-CBC. Profile 2 uses Java UTF-16BE, fixed scrypt `16384/8/1`, and AES-CBC. Profile 3 reads scrypt parameters and checks AES-CBC padding. `-wallet-scrypt-mem` and `-n` affect profiles 2 and 3.

```bash
./METAL_CRYPTO_TOOLKIT -multibitwallet multibit.hash \
  -i passwords.txt -save
```

Result profile is one of `multibit-classic-md5-aes`, `multibit-hd-scrypt-aes`, or `multibit-classic-scrypt-aes`.

#### `-bip38`

This mode recovers passwords and private keys from standard Bitcoin-mainnet BIP38 `6P...` records. Text files may contain one or more embedded Base58Check keys. The loader rejects invalid checksums, prefixes, flags, and payload lengths before any GPU work.

Both BIP38 profiles have exact Metal verification:

- non-EC records run scrypt `16384/8/8`, AES-256-ECB decryption, secp256k1 public-key derivation, complete P2PKH address encoding, and address-hash verification;
- EC-multiply records additionally implement owner salt/entropy, optional lot/sequence, passpoint derivation, the second scrypt `1024/1/1`, seed/factor recovery, and scalar multiplication.

The following official BIP38 vectors are also embedded as executable
correctness fixtures:

```text
6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg
6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo
6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX
6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j
```

The first three use `TestingOneTwoThree`; the lot/sequence vector uses
`MOLON LABE`. They recover the private keys published with BIP38 and are used
by the exact CPU-to-Metal regression.

The deterministic local mask/range fixture
`6PYWCzYbiDh88rbbQVRFUCdqS51ptYow6EEeKRGFNAWqRG5FC4evLvwJd9` uses password
`0` and recovers private key `3`; it is not an official BIP38 vector.

Dictionary candidates are normalized to UTF-8 NFC as required by BIP38. Use `-hex` to supply exact password bytes without text normalization. Mask and raw-range candidates are byte-oriented. `-wallet-mem` bounds the complete wallet working set, `-wallet-scrypt-mem MiB` further bounds per-device scratch, `-n` caps active scrypt jobs, and `-device` splits candidate ordinals without overlap. With default or explicit `-wallet-mem auto`, BIP38 targets up to 32 GiB of scratch when it fits; explicit memory sizes, percentages, `all`, and `-wallet-scrypt-mem` remain strict user limits.

```bash
./METAL_CRYPTO_TOOLKIT -bip38 encrypted.txt \
  -i passwords.txt -wallet-scrypt-mem 8192 -save

./METAL_CRYPTO_TOOLKIT -bip38 -f bip38_keys \
  -mask "?a?a?a?a?a?a?a?a" -n 256 -device 0 \
  -wallet-mem all -wallet-scrypt-mem 16384 -save -o bip38_found.txt

./METAL_CRYPTO_TOOLKIT -bip38 encrypted.txt \
  -i password-bytes.hex -hex -save
```

Results contain the source line, password, verified 64-hex private key, compression kind, HASH160, and profile. Statistics are printed only by `SpeedThreadFunc`: `KDF/s` is completed BIP38 KDF work, while `Verify/s` is complete target verification work. Neither rate uses target count as an artificial multiplier.

Only encrypted private-key records are recovery targets. BIP38 confirmation codes and intermediate passphrase codes are not accepted. Dictionary passwords are limited to 127 bytes after NFC normalization.

#### `-keyrepair`

This mode repairs a limited number of unknown characters in key material that
you already own. Select one explicit profile with `-repair-type`: `wif`,
`xprv`, `xpub`, `address`, `raw-private`, or `raw-public`. A `?` denotes one
unknown Base58 character or hexadecimal nibble. Repeat `-i`, pass templates
positionally, or provide a text file containing one template per line; blank
lines and `#` comments are ignored.

Base58Check profiles are generated and structurally filtered on Metal before
double-SHA256 checksum verification. Raw private candidates are checked against
one or more full 33/65-byte secp256k1 public keys supplied by repeatable
`-target` arguments or target files. Compressed and uncompressed forms of the
same target are canonicalized as one identity. Raw public candidates receive a
complete curve-point check. Every GPU hit is independently reconstructed and
verified on the host before it is written.

```bash
./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type wif \
  -i "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoW?" -n 128

./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type raw-private \
  -i "000000000000000000000000000000000000000000000000000000000000000?" \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type address \
  -i "1BoatSLRHtKNngkdXEeobR76b53LETtpy?" -save
```

`-device` divides each exact mixed-radix space into deterministic,
non-overlapping U256 shards. `-n` controls only the resident GPU window, so a
logical domain may exceed 64 bits without requiring a single giant buffer.
Overflowed hit windows are retried at a smaller size and are credited only
once. Ongoing `Candidate/s` and `Verify/s` statistics are emitted exclusively
by the existing `SpeedThreadFunc`.

At most 15 positions may be unknown. This is intended for bounded repair, not
unrestricted key search. A checksum-valid address produces only its address
and payload. It does not imply knowledge of any private key. `raw-private`
therefore refuses to run without a related public-key target.

#### `-nonce`

This mode recovers secp256k1 private keys only when an ECDSA or BIP340 nonce is
already bounded, partially known, related to another nonce, or supplied by an
external preprocessing step. Pass records repeatedly with `-i`, or use a text
file containing one record per line. Blank lines and `#` comments are ignored.

ECDSA records use `ecdsa:R:S:Z[:PUBKEY]`. BIP340 records use
`bip340:SIGNATURE64:MESSAGE32[:PUBKEY_X]`. When the public key is omitted,
supply one shared `-target` or one target per record. ECDSA targets are complete
33/65-byte keys; BIP340 also accepts a 32-byte x-only key.

```bash
./METAL_CRYPTO_TOOLKIT -nonce -i signatures.txt \
  -start 1 -end 0x1000000 -n 1048576

./METAL_CRYPTO_TOOLKIT -nonce -i signature.txt \
  -mask "000000000000000000000000000000000000000000000000000000000000????"

./METAL_CRYPTO_TOOLKIT -nonce -nonce-model bip340 -i schnorr.txt \
  -target signer_xonly.txt -nonce-lattice lattice_candidates.txt

./METAL_CRYPTO_TOOLKIT -nonce -i related.txt \
  -nonce-relation affine:3:7
```

`-start/-end` define an exact exclusive interval. `-mask` accepts either 64
hex/`?` nibbles or 256 binary `0`/`1`/`?` bits.
`-nonce-candidates` and its `-nonce-lattice` alias accept exact scalar
candidates, one per line. `-random` applies a seeded bijection to a range, so it
changes traversal order without repeats or omissions. `-device` divides the
checked U256 ordinal space into non-overlapping shards and `-n` controls only
the resident window.

Repeated ECDSA `r` values are automatically tested as both `k2=k1` and
`k2=-k1 mod n`. For the first two records,
`-nonce-relation same|add:B|mul:A|affine:A:B` solves `k2=A*k1+B` directly.
Each GPU hit is reconstructed and verified against `R`, the signature
equation, and the supplied public key before output. Live `Nonce/s` and
`Verify/s` statistics come only from the existing `SpeedThreadFunc`.

This mode does not make uniformly random 256-bit nonces searchable. General
hidden-number/lattice reduction remains an external CPU preprocessing task;
its candidate scalars can then be passed through the exact Metal verification
path.

#### `-aezeed`

Use this mode for standard LND 24-word aezeed/cipherseed password recovery.
Pass an inline mnemonic or a file with one mnemonic per line. The parser uses
the exact English BIP39 list, external version 0, and CRC32C. A standalone
`?` or `*` repairs one unknown whole word; at most two unknown positions are
accepted.

```bash
./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt

./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt \
  -pass passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -aezeed \
  -recovery "above judge emerge veteran reform crunch system all snap please shoulder vault hurt city quarter cover enlist swear success suggest drink wagon enrich body" \
  -entropy 81b637d86359e6960de795e41e0b4cfd

./METAL_CRYPTO_TOOLKIT -aezeed -recovery damaged.txt \
  -target root_public_keys.txt -mask "secret?d?d" \
  -wallet-mem all -device 0
```

`-pass` accepts a literal or an existing file and `-i` always streams a
dictionary. `-mask` supports `?d/?l/?u/?a/??`; `-start/-end` generate exact
decimal-string candidates with a checked U256 counter. With no password
source, the LND default password `aezeed` is tested.

An optional `-target` is either `SHA256(entropy)` or a full 33/65-byte
secp256k1 BIP32-root public key; `-entropy` supplies the exact 16-byte wallet
entropy. If no target is available, the authenticated AEZ tag and known LND
internal version are used as the recovery proof. `-wallet-mem` follows the
shared Apple unified-memory rules, while `-wallet-scrypt-mem` can impose a
smaller scratch-only ceiling. Each active v0 scrypt lane needs roughly
32 MiB, so `-n` controls resident concurrency rather than total search size.

Only aezeed container version 0 and internal derivation versions 0/1 are
recognized. Passwords are printable ASCII below 128 bytes. Supporting the
format does not weaken scrypt or make a high-entropy unknown password
practical to exhaust.

#### `-stronghold`

Use this mode for password recovery from supported IOTA Stronghold v2 and
Tauri Stronghold snapshots. Supply one or more files after `-stronghold`, or
use `-f` to scan a directory. The parser accepts only the exact `PARTI` header
with version bytes `02 00`.

```bash
./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile blake2b -pass passwords.txt -save

./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile argon2id -stronghold-salt stronghold.salt \
  -i passwords.txt -wallet-mem auto

./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile tauri-argon2id \
  -stronghold-salt 00112233445566778899aabbccddeeff \
  -mask "secret?d?d" -target plaintext.sha256 \
  -wallet-mem all -device 0
```

The required profile is one of:

- `blake2b`: Blake2b-256 of the password;
- `argon2id`: rust-argon2 default, Argon2id v19 with `m=19456 KiB`, `t=2`,
  `p=1`, and a 32-byte result;
- `tauri-argon2id`: the published Tauri example, Argon2id v19 with
  `m=10000 KiB`, `t=10`, `p=4`, and a 32-byte result.

Argon2 profiles require `-stronghold-salt`. An existing file is read as raw
bytes exactly as stored by the application; a non-file value is decoded as
hex. `-pass` accepts a literal or existing text file, `-i` streams a
dictionary, `-mask` supports `?d/?l/?u/?a/??`, and `-start/-end` generate
decimal-string candidates with a checked U256 counter.

By default, an authenticated XChaCha20-Poly1305 decrypt followed by successful
exact Stronghold LZ4 decompression is the recovery proof. `-target` can add one
or more expected `SHA256(decompressed snapshot plaintext)` digests. Each Metal
candidate is fully rechecked on the host with X25519, authentication,
decompression, and target matching before it is reported.

`-wallet-mem auto|all|NN%|SIZE` controls the Apple unified-memory budget;
`-wallet-scrypt-mem` remains a compatible stricter KDF-scratch ceiling, and
`-n` caps resident jobs rather than total search size. A snapshot does not
store which external KDF or salt its application used, so custom or unknown
profiles cannot be guessed safely and are rejected. Supporting these exact
formats does not make a strong unknown password practical to exhaust.

#### `-bisqwallet`

**Active input format:**

```text
$bisq$3*<N>*<r>*<p>*<salt_8_bytes_hex>*<blob_32_bytes_hex>
```

The first 16 bytes of `blob_32_bytes_hex` are the IV and the next 16 bytes are ciphertext. The password is converted to UTF-16BE, then scrypt and an AES-CBC padding check are applied. `-wallet-scrypt-mem` controls scratch memory. `$bisq$1` and `$bisq$2` tokens are recognized but their check paths are not enabled in v14.

```bash
./METAL_CRYPTO_TOOLKIT -bisqwallet bisq.hash \
  -i passwords.txt -save
```

#### `-dogechainwallet`

**Input format:**

```text
$dogechain$0*<iterations>*<payload_base64>*<salt_base64>
```

The mode hashes the password with SHA-256, Base64-encodes that digest, applies PBKDF2-HMAC-SHA256, and checks decrypted AES-CBC bytes and padding.

```bash
./METAL_CRYPTO_TOOLKIT -dogechainwallet dogechain.hash \
  -i passwords.txt -save
```

Result profile: `dogechain-sha256b64-pbkdf2-aes-cbc`.

#### `-ethpresale`

**Artifacts:** Ethereum presale JSON containing `encseed`, `ethaddr`, and `bkp`, or:

```text
$ethereum$w*<encseed_hex>*<eth_address_20_bytes_hex>*<bkp_16_bytes_hex>
```

For every password, the mode runs PBKDF2-HMAC-SHA256(password, password, 2000), decrypts AES-128-CBC, validates padding and backup bytes, derives the private key with Keccak, and checks the complete Ethereum address.

```bash
./METAL_CRYPTO_TOOLKIT -ethpresale presale.json \
  -i passwords.txt -save
```

Result:

```text
ETHPRESALE:<source>:PASSWORD:<password>:PRIV:<64_hex>:ETH:<0x_address>
```

#### `-androidwallet`

**Active input format:**

```text
$ab$<version>*<cipher>*<iterations>*<user_salt>*<ck_salt>*<user_iv>*<masterkey_blob>
```

The hexadecimal fields decode to 64-byte salts, a 16-byte IV, and a 96-byte master-key blob. The current command path supports cipher type 0 and verifies PBKDF2-HMAC-SHA1 plus AES-CBC tail data. bitcoinj protobuf files belong to `-bitcoinjwallet`, not this mode.

`ck_salt` and the separate `user_iv` are parsed and length-checked. The active verifier derives from `user_salt` and uses the IV/cipher tail stored inside `masterkey_blob`; extraction tools should preserve those fields exactly.

```bash
./METAL_CRYPTO_TOOLKIT -androidwallet android_backup.hash \
  -i passwords.txt -save
```

Result profile: `android-backup-pbkdf2-sha1-aes-cbc`.

#### `-eth2validator`

`-eth2validator` has two exact GPU contours for Ethereum validator keys:

- EIP-2335 v4 keystore password recovery with PBKDF2-HMAC-SHA256 or scrypt, SHA-256 password verification, AES-128-CTR decryption, and a complete BLS12-381 public-key check;
- BIP39 mnemonic or raw-seed verification through EIP-2333 and an EIP-2334 path.

Passwords are NFKD-normalized, C0/C1/DEL control codes are removed, and the result is UTF-8 encoded before the KDF. The keystore may follow the mode positionally or through repeatable `-keystore`. Passwords use `-i`, `-pass`, `-mask`, or numeric `-start/-end`.

```bash
./METAL_CRYPTO_TOOLKIT -eth2validator validator-keystore.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -eth2validator -keystore validator.json \
  -mask "secret?d?d" -wallet-mem all
```

For validator derivation, `-target` accepts one 48-byte compressed BLS public key or a file with one key per line. The default signing path is `m/12381/3600/0/0/0`; pass a different exact path with `-path`. In this contour `-i` is a mnemonic file.

```bash
./METAL_CRYPTO_TOOLKIT -eth2validator -i mnemonics.txt \
  -target validator_pubkeys.txt -path m/12381/3600/0/0/0

./METAL_CRYPTO_TOOLKIT -eth2validator -seed seed.hex \
  -target PUBKEY -path m/12381/3600/0/0
```

`-wallet-mem auto|all|NN%|SIZE`, `-wallet-scrypt-mem`, `-n`, and `-device` control Metal residency. Apple Silicon unified memory is budgeted from the current free recommended working set; large scrypt parameters can therefore reduce the number of resident candidates to one. Statistics are emitted only by the common `SpeedThreadFunc` as completed `KDF/s`, primitive KDF work, exact BLS verification, target state, working set, and readback time.

Only version 4 files using the enabled EIP-2335 modules are accepted. Mnemonic input is checksum-valid English BIP39. Unknown-word permutations must be supplied as candidates by another mode or file. Every GPU hit is independently checked with SHA-256, AES-CTR, and the BLS public key before output.

#### `-chia`

`-chia` searches Chia keys from checksum-valid English BIP39
mnemonic/passphrase candidates or raw 32–64-byte seeds. Repeatable `-target`
accepts a compressed 48-byte BLS public key, a 32-byte standard-wallet puzzle
hash, a checksum-valid `xch`/`txch` address, or a file containing one target per
line. Duplicate targets are derived once while all input origins are preserved.

The built-in path profiles are `farmer`, `pool`, `wallet`,
`wallet-observer` (default), `local`, `backup`, `singleton`, and
`pool-auth:N`. A custom `-path-template` starts with `m/`, uses the suffix `n`
for hardened components, and may contain one `{index}` placeholder. The
placeholder interval is `[START,END)` from `-start/-end`.

```bash
./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt \
  -target farmer_pubkey.txt -path-template farmer -save

./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt -pass passes.txt \
  -target xch_addresses.txt -path-template wallet-observer \
  -start 0 -end 100 -wallet-mem auto

./METAL_CRYPTO_TOOLKIT -chia -seed seed.hex \
  -target puzzle_hashes.txt -path-template wallet -start 0 -end 50

./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt -target targets.txt \
  -path-template "m/12381n/8444n/2n/{index}n" \
  -wallet-mem all -device 0
```

`-wallet-mem auto|all|NN%|SIZE` limits the Apple Silicon unified-memory
working set. `auto` uses at most half of the currently free recommended
working set and can reduce the resident batch after an allocation failure;
`all` leaves 512 MiB for runtime. `-n` selects a resident batch from 1 to
16384, and large logical inputs are streamed. Multi-device lists use
`-device`; each completed ordinal is owned by one device.

PBKDF2-HMAC-SHA512 seed generation runs on Metal. Chia BLS master/child
derivation, compressed-key validation and standard puzzle verification are
then performed exactly across the available host CPU cores. The common
`SpeedThreadFunc` is the only statistics writer and reports completed `KDF/s`,
PBKDF2 primitive rounds, exact BLS checks, logical/resident/solved targets,
readback time and allocated working set. Target count is not multiplied into
the rate.

Chia's historical KeyGen v3 is intentionally separate from the final
EIP-2333 KeyGen used by `-eth2validator`. Standard puzzle verification covers
the canonical `p2_delegated_puzzle_or_hidden_puzzle` only; arbitrary Chialisp
puzzles, xpub-only recovery and unknown-word permutation generation are not
part of this mode. Large path-index intervals remain computationally
expensive.

### Inventory and catalogs

#### `-walletscan`

`-walletscan` reads files on the host and performs a limited signature and secret inventory. It does not generate passwords, run a wallet KDF search, or prove that every file is a valid or complete wallet.

It can identify supported WIF, xprv/xpub, mnemonic candidates, SECO markers, Armory records, and protobuf-wallet indicators. Some items are cryptographically validated, while signatures and candidates are only classified by the checks implemented for that record type. Pass explicit files after the mode or use `-f DIR`. Directory scanning considers `.txt`, `.json`, `.dat`, `.wallet`, `.ldb`, `.log`, `.seco`, and extensionless files. Candidate switches such as `-i`, masks, and ranges are rejected.

```bash
./METAL_CRYPTO_TOOLKIT -walletscan -f wallet_copies \
  -save -o wallet_inventory.txt
```

Actual finding format:

```text
WALLETSCAN:<source_file>:<type>:LINE:<line_number>:VALUE:<value>
```

Raw secrets can be printed and saved. Use `-silent` when terminal output is not appropriate.

#### `-prng_help` and `-prng64_help`

These modes print the exact generator and extraction-mode catalogs, then exit. They do not start a search.

## Argument index

This table is a reminder, not a replacement for `<mode> -help`.

| Group | Arguments |
| --- | --- |
| help | `-h`, `-help` |
| input | `-i`, `-f`, `-all`, `-hex`, `-delete`, `-comb`, `-space`, `-rep` |
| sequence | `-start`, `-end`, `-step`, `-endstep`, `-plusstep`, `-addplusstep`, `-back`, `-both`, `-random`, `-n` |
| templates | `-recovery`, `-poetry`, `-hexset`, `-wordlist` |
| transforms | `-iter`, `-utf8`, `-text`, `-size`, `-sizes`, `-w`, `-lang`, `-dub`, `-electrum`, `-128`, `-ton`, `-TON`, `-pbkdf`, `-round` |
| BIP-39/path | `-pass`, `-passbrute`, `-pass_thread`, `-der_thread`, `-d`, `-d-type`, `-d-dot` |
| target | `-c`, family subtype switches, `-hash`, `-target`, `-bf`, `-xu`, `-xc`, `-xuc`, `-xh`, `-xx`, `-xb`, `-full` |
| PRNG | `-prng`, `-prng64`, `-gen`, `-mode`, `-byte`, `-shift`, `-s`, `-e`, `-random`, `-log` |
| private | `-pb`, `-last`, `-scalar`, `-LE`, `-shash`, `-legacy`, `-em`, `-keys`, `-chunk` |
| Profanity | `-offset`, `-random-seeds`, `-gpu-split` |
| XP/WalletJS | `-once`, `-v`, `-time-s`, `-time-e`, `-time-delta`, `-time-events`, `-time-events-repeat`, `-time-mode`, `-screen-seed`, `-screen-seed-zero`, `-mileage`, `-mileage-s`, `-mileage-e`, and profile-specific variant aliases |
| wallet candidates | `-mask`, `-mask-file`, `-cs1`, `-cs2`, `-cs3`, `-cs4` |
| wallet runtime | `-wallet-load-only`, `-wallet-dry-run`, `-wallet-mem`, `-wallet-scrypt-mem`, `-scan-all`, `-walletdat-max-ckey`, `-walletdat-kdf-work`, `-walletdat-max-iter`, `-walletdat-min-jobs`, `-walletdat-kdf-loop` |
| Metal/output | `-device`, `-b`, `-t`, `-bit`, `-fsize`, `-save`, `-o`, `-silent` |

`-iteration` is not an active command-line option. `-pubkey` is intentionally rejected as deprecated.

## Input and result files

### Plain candidate files

- one logical candidate per line;
- CR/LF is normalized by the applicable loader;
- do not add comments unless that specific file format says comments are supported;
- quote command-line values containing spaces or shell metacharacters;
- use `-hex` only when every candidate line is intended to be decoded as bytes.

### Derivation files

- one path per line;
- BIP paths normally begin with `m`;
- hardened components use `'`;
- Substrate SURI paths go in the file passed to `-d-dot`.

### Recovery templates

- mnemonic template: one phrase per line, one standalone `*` per unknown word;
- mode-scoped hex template: one `*` per unknown nibble and replacements from `-hexset`;
- private key template: exactly 64 hex/nibble positions.

### Output records

Key-generation modes save the original/generated source, exact path or replay state, private/scalar material where applicable, target type, and matched binary/address form. Wallet modes use the explicit prefixes shown in their sections.

The file contains secrets in plain text unless a mode-specific field is only a fingerprint. Restrict permissions if necessary:

```bash
umask 077
./METAL_CRYPTO_TOOLKIT ... -save -o private_results.txt
```

<a id="support-the-project"></a>

## Support the project

If the toolkit is useful to you, you can support its continued development with a cryptocurrency donation. Send funds only over the network named on the same line; transfers made through an incompatible network cannot be recovered.

```text
ETH:    0xDE85c1Ef7874A1D94578f11332e8fa9A6a0eE853
BTC:    bc1q063pks7ex93eka56zyumvutdt6zs9dj959pe9p
LTC:    ltc1qysumht4lxafwvmcu4ruxzuztc2xmj8tz986fmm
TRX:    TTZ3oL16BVNzU46MSJvaoKYAhvtwdTUcnz
TON:    UQC7eqLN_NlVz82YzsjzAo4iOzKjH3t095-CMtqTJ5aoqo0l
DOT:    1jen89F5v6TbdQsRaKxsCqhNp9qAdeHeZyEUWjgrM8mW6hs
ADA:    addr1qx7qrlcy37xe7j58hjxmyhyqfgu0ppeqxzs43dayjjcgde973lzxgtgqzxdvfq3rswmngapc4sp528dpzfg7huam8v9san7h6z
DASH:   Xms41jaD967XMf2FAfEwGUxYKKhYQuok9T
SOLANA: BvDQDEgq3kbNT7VQFQRQPjc4Ta5k7d5s7GdcgoKnq3KG
```

## Troubleshooting

### `Metal Toolchain component is missing`

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -downloadComponent MetalToolchain
make clean
make -j"$(sysctl -n hw.ncpu)"
```

### `Metal library load failed: library not found`

Use the final `./METAL_CRYPTO_TOOLKIT` or `./bin/METAL_CRYPTO_TOOLKIT`, not an intermediate object. Check that the embedded section exists:

```bash
otool -l ./METAL_CRYPTO_TOOLKIT | grep -A3 __metallib
```

### The expected target is never found

Check, in order:

1. the selected main mode;
2. whether `-hex` changes the candidate bytes;
3. derivation path and `-d-type`;
4. BIP-39 passphrase, including an empty passphrase;
5. `-c` letter and network subtype;
6. whether the target is raw binary hex rather than a printed address;
7. whether the supplied `-hash` starts at the first byte and fits the comparison used by that mode: at most 20 bytes for the ordinary path, or the actual compared-value length up to 32 bytes for a mode with explicit longer-value comparison;
8. filter width, encoding, and family;
9. compressed/uncompressed public-key choice;
10. P2WSH matcher format;
11. whether the selected mode is listed as inactive.

Reduce the command to one known candidate and one direct target before testing a large filter.

### An address converter rejects a line or the filter never matches

- open the generated `*-invalid.txt`; it contains the original rejected lines;
- confirm that the address was not copied with an internal space, damaged checksum, unsupported network prefix, or missing character;
- keep one byte width in each input file. Supported printable Bitcoin-like addresses produce 20-byte matcher values, while an explicitly supplied raw 32-byte hex value remains 32 bytes and is rejected after a 20-byte result;
- remember that `base64_data_to_hex` and `solana_address_to_hex` cannot validate a source checksum because those input formats do not contain one;
- use the converter's decoded hex output, not the original printable address, as XorFilter input;
- select the matching `-c` branch. Equal-length values from unrelated currencies are not interchangeable;
- P2WSH and Taproot filters contain the converter's 20-byte RIPEMD-160 matcher values. Keep these two target families in separate files and filters even though their matcher width is the same;
- when running a source build, use `tools/<project>/bin/<tool>`; the shorter `tools/<tool>` path belongs to the ready-to-run tools archive.

Test one known address through the converter and one short search range before building a large filter.

### The process uses too much memory or is killed

- start with the automatic grid;
- remove unnecessary target families and filters;
- lower `-fsize` only if result pressure permits;
- lower `-wallet-scrypt-mem` or `-n` in scrypt/KdfRomix modes;
- use `-wallet-load-only` to inspect the job set first;
- do not use `-full` on an unbounded search.

### A wallet file is skipped

Run the mode with the explicit file instead of only directory scanning to get a clearer warning. Confirm the extension and exact extracted-hash grammar. Use `-walletscan` for inventory, not as a password checker.

### Output appears duplicated or out of order

The output file is appended, so an older run may already contain the line. Several devices and asynchronous save queues can interleave completed batches. Candidate/path fields remain in each record, but global lexical ordering is not promised.

### macOS blocks the downloaded executable

Verify the repository and archive first, then:

```bash
xattr -d com.apple.quarantine METAL_CRYPTO_TOOLKIT
```

## Repository layout

| Path | Purpose |
| --- | --- |
| `main.mm` | CLI parsing, mode orchestration, input loading, and host-side wallet parsers |
| `MetalRuntime.*`, `MetalBackend.*` | Metal device, buffer, command, and embedded-library runtime |
| `Kernel.h`, `KernelRuntime.h` | shared host/runtime declarations and fixed data layouts |
| `SaveFunc.mm` | result snapshots, formatting, filtering, and asynchronous save queues |
| `Kernels/` | one Metal entry function per `.metal` file and separate `.metalh` helpers |
| `lib/`, `host_secp/`, `sr25519-donna-32bit/` | hashing, encoding, curve, and host verification code |
| `tools/common/` | shared strict decoders, checksums, hashes, ordered reader, and CLI used by all converters |
| `tools/<converter>/` | one standalone address converter with its own `Source.cpp` and `Makefile` |
| `tools/profanity_basepoint_generator/` | optimized macOS generator for the complete Profanity recovery basepoint source list |
| `tools/Makefile` | build or clean all 14 address converters and the Profanity generator |
| `Makefile` | standalone macOS build, embedded Metal-library link, and separate `tools` targets |

---

<a id="russian"></a>

## Русский

### Изменения

#### v16

Волна 0 добавляет общую инфраструктуру для новых GPU-режимов:

- `ModeProgress` передаёт данные существующему `SpeedThreadFunc`, который
  остаётся единственным потоком печати статистики;
- checked U256-планировщик и общий helper бюджета unified memory поддерживают
  `auto`, `all`, проценты, размеры MiB/GiB, реплики выбранных устройств и
  ограничения Metal working set;
- информация об устройстве теперь включает recommended/current working set,
  `maxBufferLength` и признак unified memory.

Волна 1 включает точное восстановление BIP38:

- отдельные Metal-контуры non-EC и EC-multiply реализуют обе стадии scrypt,
  AES-256-ECB, lot/sequence, secp256k1 и полную проверку P2PKH address hash;
- словари нормализуются в UTF-8 NFC, а `-hex`, маски и raw-диапазоны сохраняют
  точную байтовую семантику;
- multi-target планировщик безопасно делит KDF-группы даже при меньшем числе
  активных заданий, а переполнение результатов повторяет незачтённую работу
  без двойного учёта;
- `-wallet-mem` задаёт общий предел unified memory, а явный
  `-wallet-scrypt-mem` является строгим cap.

Волна 2 добавляет checksum-first восстановление ключей на GPU:

- `-keyrepair` восстанавливает ограниченное число неизвестных Base58- или
  hex-позиций в WIF, xprv/xpub, raw-приватных/публичных ключах secp256k1 и
  Base58Check address payload;
- Metal-ядра генерируют кандидаты, сначала отбрасывают неверную структуру и
  checksum и передают только ограниченный буфер hits для обязательной
  host-проверки;
- mixed-radix U256 scheduler покрывает весь заявленный домен из 15 позиций, а
  выбранные Metal-устройства получают точные непересекающиеся шарды;
- для raw-private обязателен связанный публичный ключ, а результат address
  всегда описывается только как адрес/payload, но не как найденный приват.

Волна 3 добавляет точное восстановление nonce ECDSA/BIP340:

- `-nonce` принимает повторяемые записи подписей или построчные файлы и
  проверяет ограниченные диапазоны, маски известных/неизвестных битов либо
  точные списки кандидатов от внешнего lattice solver;
- Metal-ядро восстанавливает `R=kG` с явными параметрами precompute-окон и
  проверяет ECDSA `r` (включая допустимый подъём `r+n`) либо BIP340-точку с
  чётной Y;
- reused, mirrored, additive, multiplicative и affine-зависимые ECDSA nonce
  решаются алгебраически до brute-force поиска;
- каждый hit независимо сверяется на host с уравнением подписи и полным
  публичным ключом, а `Nonce/s` и `Verify/s` печатает только
  `SpeedThreadFunc`.

Волна 4 добавляет нативную Metal-генерацию vanity-адресов:

- `-vanity` поддерживает BTC compressed/uncompressed P2PKH, вложенный
  P2SH-P2WPKH, нативный Bech32 P2WPKH, lowercase Ethereum и TRON;
- повторяемый `-pattern` и потоковый `-pattern-file` принимают префиксы,
  суффиксы, wildcard `*` и односимвольный wildcard `?`;
- точные checked U256-интервалы, случайная ротация без повторов,
  multi-device-планировщик и split-key полностью покрывают заданный домен без
  пересечений;
- каждый GPU hit заново строится из скаляра и полностью кодируется на host, а
  единственным потоком печати `Key/s` остаётся общий `SpeedThreadFunc`.

Волна 5 добавляет детерминированный поиск salt Ethereum CREATE2:

- `-create2` вычисляет точный EIP-1014 preimage
  `0xff || deployer || salt || init_code_hash` отдельным Metal-ядром;
- повторяемые шаблоны и файлы шаблонов поддерживают lowercase hex-префиксы,
  суффиксы, `*` и односимвольный `?`;
- прямые U256-диапазоны salt и 64-ниббловые шаблоны перебираются без пропусков,
  а finite random меняет только циклическую начальную точку;
- каждый hit пересчитывается независимым host Keccak, а завершённые `Addr/s`
  печатает только общий `SpeedThreadFunc`.

По итогам оптимизационной части Волны 5 production-настройкой остаются 128
потоков на Metal threadgroup. Fixed-state packing, raw-nibble matching, два
salt на поток и сетки 64/256 сохранили точный результат, но не дали требуемого
стабильного выигрыша относительно обеих окружающих baseline-групп, поэтому не
были интегрированы.

Волна 6 добавляет checked GPU-поиск путей деривации BIP32:

- `-hdpath` принимает BIP39 mnemonic, raw seed, xprv/xpub либо descriptor с
  одним extended key;
- фиксированные индексы, inclusive-диапазоны, явные списки и finite wildcard
  объединяются в checked U256 mixed-radix domain без материализации путей на
  host;
- CKDpriv и non-hardened CKDpub выполняются отдельным Metal-ядром, а hardened
  потомки от xpub отклоняются до запуска;
- повторяемые полные публичные ключи и target-файлы нормализуются и
  дедуплицируются, а каждый Metal hit независимо пересчитывается на host;
- общий `SpeedThreadFunc` остаётся единственным потоком статистики и печатает
  зачтённые `Path/s`, число child derivations, точные проверки, targets,
  working set и readback time.

В оптимизационной части Волны 6 последовательно приняты два улучшения.
Переиспользование уже вычисленного публичного ключа root для первого
non-hardened шага CKDpriv уменьшило медианное wall time на
**39,26%/39,20%** относительно окружающих baseline. Затем измеряемый grid
tune выбрал 256 потоков на Metal threadgroup: на нагрузке из 16 777 216 путей
медиана принятого baseline снизилась с 1,4452/1,4399 с до 0,23679 с
(**83,62%/83,55%**, CV 1,168%, drift baseline 0,368%). Перед интеграцией цели
на границах 128- и 256-поточных групп были найдены с полной повторной
деривацией на host.

Волна 7 добавляет точный поиск приватных ключей по Hamming distance:

- `-priv -hamming BASE:DISTANCE[:MUTABLE_MASK]` перебирает точную
  комбинаторную сферу вокруг одного 256-битного base scalar; нули маски
  фиксируют биты, единицы разрешают их переключение;
- checked U256 combinadic rank/unrank сопоставляет каждому кандидату ровно
  один ordinal без материализации combinations и без дублей;
- `-start/-end` выбирают точный ordinal-поддиапазон, а Metal-устройства
  получают последовательные непересекающиеся окна;
- повторяемые полные публичные ключи secp256k1 и target-файлы канонизируются и
  дедуплицируются, а каждый GPU hit независимо восстанавливается из ordinal,
  заново вычисляется и проверяется на host;
- единственным потоком текущей статистики остаётся общий `SpeedThreadFunc`,
  который печатает зачтённые `Key/s`, scalar multiplications, точные проверки,
  targets, working set и readback time.

Волна 8 добавляет checksum-first перебор перестановок BIP39:

- `-mnemonic -scramble` принимает фразу в командной строке либо потоковые
  файлы и без материализации перебирает уникальные перестановки мультимножества;
- фиксированные слова уменьшают домен, а `*` и `{word|word}` задают свободные
  и ограниченные позиции;
- checked U256 scheduler, точное разбиение между устройствами, повтор
  переполненного незачтенного окна и `-wallet-mem` покрывают большие домены и
  unified memory;
- Metal выполняет rank/unrank мультимножества и отсев по checksum BIP39 до
  существующего pipeline seed, derivation и точной проверки целей;
- единственным live-выводом остаётся `SpeedThreadFunc` с `Candidate/s`,
  точными проверками, working set и readback time.

Волна 9 добавляет исторические memory-hard профили brainwallet:

- `-warpwallet` точно реализует WarpWallet, brainwallet.io, Brainv2 и
  RushWallet в Metal вместо приближённой замены обычными hash-режимами
  `-brain`;
- словари читаются ограниченными потоковыми окнами, а повторяемые цели
  hash160/P2PKH нормализуются, дедуплицируются, сортируются и загружаются
  шардами меньше лимита памяти и `maxBufferLength`;
- дорогие KDF и secp256k1/hash160 выполняются один раз на пароль; каждый шард
  целей делает только точный lookup, поэтому число целей не умножает
  зачтённую KDF-работу;
- Brainv2 разделён на first, параллельный middle, last и finalize kernels.
  RushWallet принимает как префикс до `!`, так и полный фрагмент с десятью
  hex-символами checksum для раннего отсева;
- каждый Metal hit независимо проверяется через host secp256k1/hash160,
  переполненные batches повторяются без двойного зачёта, а единственным
  потоком live-статистики `KDF/s` остаётся общий `SpeedThreadFunc`.

Волна 10 расширяет обычный быстрый контур `-brain`:

- `-brain-profile` задаёт стабильные имена историческим SHA-256 aliases, а
  также binary/hex double-hash, SHA3-256, Keccak-256, BLAKE2b-256 и raw;
- `-brain-rules FILE` один раз компилирует основной совместимый набор правил
  hashcat, удаляет дубли и применяет ограниченные преобразования до
  существующего Metal pipeline hash/secp256k1;
- `-brain-combine FILE` добавляет конкатенацию словарей `lr`, `rl` или `both`
  и опциональный `-space`; логическое декартово произведение поступает через
  backpressure-stream и не материализуется отдельным огромным списком;
- правый словарь до 64 MiB хранится resident, больший повторно читается
  ограниченным потоком, а выход за 512 байт и неприменимые позиции правил
  явно учитываются вместо тихого усечения;
- расширенные кандидаты сохраняют точные фильтры целей, формат результатов,
  multi-device dispatch и единственный общий `SpeedThreadFunc`.

Волна 11 добавляет аутентифицированное восстановление Substrate keyring:

- `-substratewallet` загружает JSON Polkadot/Substrate версий 2/3 и до запуска
  Metal проверяет PKCS8, curve, SS58/hex identity, структуру encoded и параметры
  scrypt;
- версия 3 использует сгруппированный scrypt и XSalsa20-Poly1305, версия 2 —
  точное legacy-правило 32-байтового ключа из пароля;
- plaintext принимается только после проверки Poly1305, заголовка/разделителя
  PKCS8, встроенного public key и независимого восстановления public key из
  секрета для sr25519, ed25519 или secp256k1 ECDSA;
- цели с одинаковыми KDF-параметрами делят один scrypt, ciphertext хранится
  компактным пулом, а `-wallet-mem`/`-wallet-scrypt-mem` ограничивают реальный
  working set unified memory;
- live `KDF/s` и `Verify/s` печатает только общий `SpeedThreadFunc`; количество
  целей не умножает `KDF/s`.

Волна 12 добавляет аутентифицированное восстановление backup Copay/BitPay:

- `-copaywallet` загружает один или несколько versioned SJCL JSON backup
  напрямую либо сканирует каталог, отклоняя неподдерживаемые параметры до
  запуска Metal;
- production-профиль точно повторяет стандарт Copay/BitPay SJCL:
  PBKDF2-HMAC-SHA256 с 10 000 итераций, AES-128-CCM, 64-битным tag, пустым
  associated data и точным 13-байтовым clamp nonce из SJCL;
- backup с одинаковыми salt и числом итераций разделяют результат KDF, а
  компактное хранение ciphertext и окна целей удерживают большие наборы в
  пределах `-wallet-mem`;
- каждый выведенный пароль прошёл полное сравнение authentication tag AES-CCM
  на Metal; повреждённый или просто правдоподобный plaintext не принимается;
- live `KDF/s` и `Verify/s` печатает только общий `SpeedThreadFunc`, без
  искусственного умножения показателей на число artifacts.

Волна 13 добавляет строгое восстановление legacy-экспорта Terra Station:

- `-terrawallet` принимает исторический mobile exported-key JSON напрямую
  либо в исходной внешней Base64-обёртке;
- loader требует `name`, checksum-valid адрес `terra1...` с 20-байтовым
  payload и точную структуру salt/IV/ciphertext поля `encrypted_key`;
- Metal выполняет PBKDF2-HMAC-SHA1 со 100 итерациями, AES-256-CBC/PKCS7,
  строгий разбор 64 hex-символов приватного ключа, восстановление secp256k1
  public key и точное сравнение HASH160 адреса;
- цели с одинаковым salt разделяют результат KDF, компактный пул ciphertext
  ограничен `-wallet-mem`, а завершённые `KDF/s` и реальные `Verify/s`
  печатает только общий `SpeedThreadFunc`;
- неизвестные Terra-форматы, mnemonic/hardware-wallet записи, неверные
  checksum и эвристики «похожего plaintext» отклоняются.

Волна 14 добавляет точное восстановление exported keys BitShares 0.x:

- `-bitshareswallet` загружает официальную JSON-схему `exported_keys` с
  password checksum и параллельными массивами encrypted private/public keys;
- до запуска Metal loader проверяет каждый Base58 public key BTS/BTSX вместе
  с его RIPEMD-160 checksum и удаляет повторяющиеся key records;
- Metal один раз на checksum-группу вычисляет `SHA512(password)`, сверяет
  сохранённый `SHA512(password_key)`, расшифровывает AES-256-CBC/PKCS7
  производными key/IV, проверяет приватный scalar и точно восстанавливает
  compressed public key secp256k1;
- ключи с одинаковым `password_checksum` разделяют один SHA-512, компактные
  metadata/ciphertext остаются в пределах `-wallet-mem`, а завершённые `KDF/s`
  и реальные `Verify/s` печатает только общий `SpeedThreadFunc`;
- произвольные записи wallet database, watch-only entries, неверные checksum,
  нарушенные массивы и неизвестные контейнеры отклоняются.

Волна 15 добавляет аутентифицированное восстановление Yoroi IndexedDB /
EMIP-3:

- `-yoroiwallet` читает реальные таблицы IndexedDB `Key` и `KeyDerivation` и
  проходит только точную цепочку root -> `1852'` -> `1815'` -> `account'` до
  сохранённого account xpub BIP32-Ed25519;
- loader требует зашифрованную 156-байтовую root-запись EMIP-3, 64-байтовый
  account xpub и точную структуру salt32/nonce12/tag16/ciphertext96;
- Metal выполняет PBKDF2-HMAC-SHA512 с 19162 итерациями, проверяет tag
  ChaCha20-Poly1305, расшифровывает 96-байтовый root xprv и восстанавливает
  account public key вместе с chain code через hardened CIP-1852 derivation;
- roots с одинаковым salt разделяют один grouped KDF, компактные metadata и
  pooled ciphertext остаются в пределах `-wallet-mem`, а завершённые `KDF/s`
  и реальные `Verify/s` печатает только общий `SpeedThreadFunc`;
- mnemonic recovery, hardware signers, watch-only roots, нарушенные таблицы,
  неаутентифицированный plaintext и неизвестные контейнеры отклоняются.

Волна 16 добавляет checksum-first восстановление mnemonic Monero:

- `-monero` принимает повторяемые legacy-фразы из 25 слов и Polyseed из 16
  слов напрямую либо из построчных файлов; отдельный `?` обозначает одно
  неизвестное целое слово;
- встроены все официальные списки языков Monero legacy и Polyseed с точным
  prefix matching, предварительной проверкой legacy CRC32 и декодированием
  checksum Polyseed в GF(2^11) до дорогой derivation;
- Metal один раз на кандидата получает recovery key, канонические private
  spend/view scalars и оба Ed25519 public keys, после чего потоково проверяет
  отсортированные окна целей без умножения KDF-работы на их количество;
- standard, integrated и subaddress цели принимаются только после проверки
  checksum, повторные цели сохраняют все источники, а каждый hit независимо
  пересчитывается официальной host-арифметикой Monero ref10;
- `-wallet-mem` ограничивает весь working set unified memory, overflow hit
  batch повторяется без двойного зачёта, а завершённые `Candidate/s`,
  primitive work и реальные `Verify/s` печатает только общий
  `SpeedThreadFunc`;
- encrypted Polyseed features, нарушенные фразы, неподдерживаемые address
  prefixes и просто checksum-valid фразы без точного совпадения с целью не
  объявляются восстановленными кошельками.

Волна 17 добавляет version-aware восстановление паролей Monero `.keys`:

- `-monerowallet` принимает повторяемые современные или legacy `.keys`
  software-wallet и literal/файловые пароли через `-pass` либо `-i`;
- Metal выполняет полный CryptoNight-v0 slow hash с отдельным scratchpad
  2 MiB на активный lane, включая Keccak/AES mixing pipeline и точный
  Blake/Groestl/JH/Skein final selector;
- современные payload ChaCha20/JSON и legacy ChaCha8 portable-account
  разбираются независимо, а зашифрованные spend/view secrets получают
  обязательный memory key `CryptoNight(base_key || 'k')`;
- результат требует канонических private scalar и точного восстановления
  spend/view public keys арифметикой Monero ref10; malformed, неизвестные,
  hardware и custom-background-password профили не угадываются;
- `-wallet-mem` ограничивает весь CryptoNight scratch, automatic concurrency
  уменьшается после allocation failure, явный `-n` остаётся строгим, а
  завершённые `KDF/s` и реальную verification печатает только общий
  `SpeedThreadFunc`.

Волна 18 добавляет checksum-first восстановление mnemonic Algorand:

- `-algorand` принимает повторяемые стандартные английские фразы из 25 слов,
  inline-шаблоны и построчные файлы; отдельный `?` или `*` обозначает
  неизвестное целое слово, а `-scramble` перебирает уникальные перестановки
  multiset без дублей;
- checked U256 scheduler однозначно сопоставляет ordinal неизвестным словам
  или перестановкам, проверяет ограниченный последний data word и получает
  checksum SHA-512/256 до дорогой операции Ed25519;
- повторяемые 58-символьные адреса Algorand, исходные 32-байтовые public keys
  и файлы целей проверяются, нормализуются и дедуплицируются с сохранением
  каждого source occurrence;
- при полностью resident target tile автоматически используется fused Metal
  derive/lookup, а большие наборы целей переходят на split derivation и
  ограниченные окна, чтобы не повторять Ed25519 для каждой части списка;
- каждый hit независимо восстанавливается и проверяется на host через
  SHA-512/256, Ed25519 и каноническое кодирование адреса;
- `-wallet-mem` ограничивает unified-memory working set, overflow hit batch
  повторяется без двойного зачёта, а завершённые `Candidate/s`, primitive
  work, реальные `Verify/s`, resident targets, readback и память печатает
  только общий `SpeedThreadFunc`.

Fused pipeline Волны 18 прошёл симметричный gate на 4 194 304 кандидатах:
медиана 0.466967 с против 0.524247/0.525286 с у окружающих split-baseline,
то есть **+12.27%/+12.49%** при population CV 0.906%. Split-путь остаётся
автоматическим для наборов целей больше resident tile.

Волна 19 завершает точное восстановление SLIP-0039:

- `-slip39` разбирает официальный английский формат долей, проверяет RS1024,
  согласованность общих/group/member metadata и восстанавливает оба уровня
  Shamir вместе с обязательными digest shares;
- `?` и `*` восстанавливают до двух повреждённых слов в каждой доле без
  материализации всего word-product; checksum-valid варианты комбинируются
  под строгим пределом в один миллион сочетаний;
- Metal перебирает printable-ASCII passphrase точной четырёхраундовой схемой
  Feistel и PBKDF2-HMAC-SHA256 с iteration exponent, затем сравнивает цели
  `SHA256(master-secret)`;
- resident targets используют fused decrypt/lookup, большие наборы получают
  один decrypt и повторно используют secret/digest в ограниченных target tiles;
- каждый GPU hit независимо расшифровывается и хешируется CommonCrypto до
  вывода; `-wallet-mem` ограничивает unified memory, а завершённые `Pwd/s`,
  primitive work и `Verify/s` печатает только общий `SpeedThreadFunc`.

Волна 20 добавляет точное восстановление LND aezeed:

- `-aezeed` декодирует стандартный английский cipherseed из 24 слов,
  проверяет external version и CRC32C до запуска Metal и умеет восстановить
  до двух неизвестных целых слов, обозначенных `?` или `*`;
- Metal выполняет точные параметры v0 scrypt `N=32768,r=8,p=1`,
  специализированное для 23 байтов расшифрование AEZ-v5, проверку tag и
  извлечение известных internal version/birthday;
- результат можно проверить по точной entropy, `SHA256(entropy)` либо
  compressed/uncompressed secp256k1 public key BIP32-master, полученного из
  16-байтовой entropy LND;
- каждый hit заново независимо расшифровывается через AEZ и полностью
  проверяется по BIP32 root public key на host до вывода;
- `-wallet-mem` и `-wallet-scrypt-mem` ограничивают резидентные ROMix lanes
  примерно по 32 MiB, multi-device batch не пересекаются, а завершённые
  `KDF/s`, verification, readback и реальный working set печатает только
  общий `SpeedThreadFunc`.

Волна 21 добавляет version-aware восстановление snapshot IOTA/Tauri Stronghold:

- `-stronghold` строго принимает публичный заголовок `PARTI` и версию `02 00`;
  неизвестные версии и повреждённые файлы отклоняются до запуска Metal;
- профили `blake2b`, стандартный Stronghold/rust-argon2 `argon2id` и пример
  Tauri `tauri-argon2id` выбираются явно, поскольку snapshot не хранит
  application KDF и внешний salt;
- Metal выполняет Blake2b-256 и точный Argon2id v19 с multi-lane заполнением,
  повторно используя один address block для всех его 128 ссылок;
- каждый candidate key независимо проверяется на host через X25519,
  XChaCha20-Poly1305, точную Stronghold LZ4-декомпрессию и необязательную цель
  `SHA256(plaintext)`;
- salt-файл всегда читается как raw bytes, inline salt — как hex;
  `-wallet-mem` ограничивает unified-memory scratch, а завершённые `KDF/s`,
  verification, readback и реальный working set печатает только общий
  `SpeedThreadFunc`.

Волна 22 добавляет общий backend BLS12-381:

- portable scalar arithmetic, EIP-2333 key generation, сжатые G1 public keys и
  строгая проверка subgroup используются совместно validator- и Chia-режимами;
- arm64 assembly backend выбирается автоматически при наличии, а portable C
  остаётся эталоном корректности;
- официальные векторы покрывают EIP-2333/EIP-2334, разбор сжатых ключей,
  отклонение infinity и совпадение CPU-backend. Это инфраструктурная волна без
  отдельного CLI-режима.

Волна 23 добавляет точное восстановление Ethereum validator:

- `-eth2validator` восстанавливает пароли EIP-2335 v4 для PBKDF2- и
  scrypt-keystore с AES-128-CTR и полной проверкой BLS public key;
- derivation-контур проверяет checksum-valid English BIP39 mnemonic либо raw
  seed через EIP-2333 и точные пути EIP-2334;
- target-файлы дедуплицируются без потери источников, domains обрабатываются
  окнами внутри `-wallet-mem`, а завершённые `KDF/s`, verification и readback
  печатает только общий `SpeedThreadFunc`.

Волна 24 добавляет точное восстановление ключей Chia:

- `-chia` проверяет English BIP39 mnemonic/passphrase либо raw seed по сжатым
  BLS-ключам, 32-байтовым puzzle hash и checksum-valid адресам `xch`/`txch`;
- профили farmer, pool, wallet, observer, local, backup, singleton и pool-auth
  используют исторический Chia BLS KeyGen v3 и точные hardened/unhardened
  дочерние derivation;
- standard-wallet puzzle hash воспроизводит
  `p2_delegated_puzzle_or_hidden_puzzle`, включая signed synthetic-key offset
  и канонический default hidden puzzle;
- PBKDF2-HMAC-SHA512 выполняется ограниченными Metal-batch, точная host BLS
  verification распределяется по доступным CPU-ядрам, а завершённые `KDF/s`,
  primitive work, targets, readback и working set печатает только общий
  `SpeedThreadFunc`.

Волна 25 завершает release candidate v16 и полную регрессию:

- production-бинарник содержит только arm64, требует macOS 15.0, включает
  встроенный `metallib` и воспроизводимо упаковывается с двуязычными release
  notes, набором утилит и отдельными SHA-256;
- подробный help симметричен в обоих порядках аргументов, а release-регрессия
  покрывает BSGS, Kangaroo `compact170`/`wide256`, wallet-режимы, BLS12-381,
  Ill Bloom PRNG, default auto-grid и P2WSH;
- BIP38 переведён на изолированное grouped Metal-ядро. Оно восстанавливает
  точные non-EC и EC-multiply результаты после добавления
  Substrate/Cardano-контуров в общее wallet-ядро, не меняя остальные
  wallet-pipeline;
- независимые BIP38-группы теперь выполняются одним ограниченным памятью
  запуском и параллельно занимают доступные scrypt-lanes. Exact-регрессия
  non-EC с двумя целями на M4 Max ускорилась с медиан 9,948/9,941 с (A1/A2)
  до 5,132 с (+93,835%/+93,703% throughput, CV 0,123%).

Межволновое обновление PRNG синхронизирует каталог с текущей CUDA-версией:

- `-prng` получил Ill Bloom генераторы `332..489` и режимы `247..762`, включая
  варианты источников/runtime и полный перебор знаков цепочки и результата;
- генераторы `221..223` в `-prng64` задают компактные непересекающиеся
  пространства индексов для фиксированных знаков, runtime-профилей и byte lanes;
- режим `218` выдает исходные байты напрямую, host проверяет границы packed
  индекса, а Metal golden сверяет CUDA-векторы и все 32-байтовые маски.

#### v15

Обновление от 25 июля расширяет оба interval-DLP режима для очень больших
семейств целей:

- BSGS теперь обрабатывает цели ограниченными окнами, не удерживая весь вход в
  памяти, а `-random` использует seed-зависимую перестановку всех giant-групп
  без повторов. `-bsgs-random-seed` точно воспроизводит порядок обхода.
- `-bsgs-shifts START:COUNT[:STEP]` задаёт арифметическое семейство
  `Q-(START+i*STEP)G` с 64-битным количеством элементов без разворачивания
  миллионов публичных ключей в памяти.
- При двух и более целях Kangaroo автоматически включает настоящий
  multi-target контур с общим tame herd.
  `-kangaroo-mem auto|all|NN%|SIZE` задаёт фактический предел рабочего набора
  без фиксированного ограничения 16 GiB, а резидентные окна целей сохраняют
  ограниченное потребление физической памяти.
- `-kangaroo-shifts START:COUNT[:STEP]` предоставляет Kangaroo такой же
  компактный источник смещённых целей. Поиск семейства останавливается после
  первого полностью проверенного совпадения, а штатный speed thread выводит
  завершённую работу и уникальное эквивалентное покрытие с учётом пересечений.

Финальный BSGS-кандидат с ранней остановкой принят на Apple M4 Max: медианное
wall time уменьшилось **на 82,96–83,18%** относительно обеих окружающих
baseline-групп (0,3145 с против 1,8458/1,8701 с, CV 2,180%). Закрытый набор
корректности проверил BSGS/Kangaroo shifted first-hit, независимый multi-target,
неповторяющийся случайный обход BSGS, циклические пересечения, `compact170`,
`wide256`, private 1:1 и P2WSH.

Обновление `-bsgs` от 24 июля добавляет нативный детерминированный режим BSGS
для Metal:

- одна или несколько compressed/uncompressed целей secp256k1 принимаются
  напрямую или из файлов; грамматика точных, списочных и битовых диапазонов
  совпадает с Kangaroo;
- negation-map движок объединяет shared-inversion генерацию точек
  `P+J`/`P-J`, компактные точные buckets `fingerprint64 + j`, GPU lookup и
  resolve, полную проверку публичной точки, пакетную обработку целей и
  динамическое multi-GPU распределение без пропусков и пересечений;
- `-bsgs-mem` и `-bsgs-table` управляют unified memory и точным размером baby
  table, а версионированный кеш с контрольными суммами включается только явно;
- вся текущая статистика печатается стандартным `SpeedThreadFunc`. В поиске
  используются названия `GStep/s` и `EqKey/s`; Metal
  negation-map walk выводит эффективное уникальное покрытие по формуле
  `EqKey/s = GStep/s × 2M`.

На Apple M4 Max итоговый точный pipeline сократил медианное время профиля
width-44, 16 целей, `M=2^22` с 1,100 до 0,370 с относительно внутреннего
textbook baseline (**на 66,37% меньше wall time**, CV 2,019%). На контрольном
профиле width-56 с одной целью получены медианные **1,130 млрд GStep/s** и
**9,476 квадриллиона EqKey/s** без регрессии производительности из-за нового
формата статистики.

Обновление `-kangaroo` от 24 июля добавляет два независимо
оптимизированных Metal-движка:

- `compact170` автоматически выбирается для эффективной ширины диапазона от 32
  до 170 бит. В нём горячий affine point walk отделён от восстановления
  расстояния, прыжки сохраняются в 16-битное кольцо метаданных, расстояние
  обрабатывается тремя знаковыми limb, а полный SOTA+ `P+J`/`P-J` выполняет по
  восемь кенгуру на Metal-поток.
- `wide256` автоматически выбирается для ширины от 171 до 256 бит. Он использует
  тот же разделённый point-walk/replay-конвейер, полную знаковую 256-битную
  арифметику расстояния без усечения и по 16 кенгуру на Metal-поток.
- При ошибке выделения памяти явно включается legacy fallback. Синтаксис команд,
  формат результата, multi-GPU, tame cache и чтение PSWDP2/3/4 не изменились.

Следующие дополнительные ускорения относительно первоначальной сборки v15
подтверждены на Apple M4 Max со штатной автоматической сеткой,
`METAL_VANITY_GROUP_SIZE=1024`, двумя прогревами и симметричными фазами A1/B/A2
по 11 замеров:

- диапазон формы puzzle 135 `[2^134, 2^135)` с DP44:
  **на 11,024–11,101% быстрее**, **380,368 млн прыжков/с**;
- полный 256-битный контроль с DP60:
  **на 4,064–4,065% быстрее**, **356,467 млн прыжков/с**.

Во всех основных сериях коэффициент вариации остался ниже 0,3%.
`compact170` точно восстановил известный небольшой приватный ключ, а `wide256`
выполнил 1 966 080 000 переходов полного диапазона без переполнения или
расхождения replay.

В первоначальном выпуске v15 уже были подтверждены следующие ускорения
относительно предшествующей реализации Kangaroo:

- путь обхода реального 256-битного диапазона стал **на 30,654–30,753% быстрее**;
- контрольный 128-битный диапазон стал **на 31,091–31,231% быстрее**.

#### v14.1

Ниже перечислены только подтвержденные ускорения на Apple M4 Max со штатной
автоматической сеткой, `METAL_VANITY_GROUP_SIZE=1024` и парными замерами медиан
A1/B/A2. Каждый диапазон показывает результат оптимизированной сборки
относительно обеих окружающих baseline-сборок:

- `mnemonic`: ограниченный перебор passphrase для seekable mnemonic-входов стал **на 89,922–89,935% быстрее**;
- `entropy`: пакетный перебор `entropy × passphrase` стал **на 92,314–92,317% быстрее**;
- `minikeys`: последовательный путь единичного Base58-инкремента стал **на 9,530–10,379% быстрее**;
- `profanity`: reverse recovery с предварительной GPU-фильтрацией совпадений стал **на 10,512–11,779% быстрее**;
- `poetry`: ограничение finite-grid и пакетная обработка одинаковых шаблонов вместе дали **ускорение на 20,735–21,324%**;
- `armory`: round-0 вывод compressed public key с переиспользованием вычисленного child key стал **на 10,170–10,361% быстрее**.
- `keystore`: адаптивная scrypt-конкурентность на профиле r=8/256 паролей дала **ускорение на 49,499–49,646%**;
- `walletdat`: uniform KDF-профиль словаря из 4 096 паролей стал **на 63,039–63,131% быстрее**;
- `stellarwallet`: проверка AES-GCM для payload размером 64 КиБ стала **на 20,397–20,399% быстрее**;
- `blockchainwallet`: PBKDF2-SHA1 с переиспользованием состояний HMAC стал **на 36,971–37,964% быстрее**;
- `bisqwallet`: scrypt-профиль N=1024/r=1 со словарем из 4 096 паролей стал **на 48,986–49,203% быстрее**;
- `dogechainwallet`: PBKDF2-профиль с 10 000 итерациями стал **на 2,111–2,693% быстрее**;
- `ethpresale`: групповая проверка encrypted seed размером 608 байт стала **на 34,941–35,576% быстрее**;
- `walletscan`: mnemonic-heavy сканирование текстового набора объемом 2 ГиБ стало **на 14,131–14,187% быстрее**.

### Что это за программа

`METAL_CRYPTO_TOOLKIT` — программа командной строки для восстановления собственных криптовалютных кошельков и исследования способов генерации ключей на компьютерах Apple Silicon. Основные вычисления выполняются на видеокарте через Metal.

Программа умеет:

- работать с мнемониками BIP-39, фразами Poetry brainwallet, энтропией, seed, готовым HMAC BIP32, путями деривации и дополнительными passphrase BIP-39;
- получать и проверять результаты secp256k1, ed25519 и sr25519 для Bitcoin, Ethereum, TON, Solana, Polkadot/Substrate, Cardano, Filecoin, IOTA, Aptos, Sui, XRP, ICP и Tezos;
- искать одну известную цель напрямую либо проверять большие наборы целей через Bloom- и XOR-фильтры;
- перебирать диапазоны приватов, восстанавливать неизвестные шестнадцатеричные позиции, проверять мини-ключи Casascius и воспроизводить известные старые генераторы;
- восстанавливать приват secp256k1 через `-bsgs` или `-kangaroo`, когда известны полный публичный ключ и ограниченный диапазон скаляра, включая multi-target и компактный поиск по смещённым целям;
- проверять пароли поддерживаемых файлов кошельков и заранее извлеченных хешей;
- передавать найденные записи на вывод в фоне, не останавливая вычисления после каждого совпадения.

Это не кошелек и не программа для подключения к блокчейну. Она получает или создает кандидаты, выполняет заданные преобразования и деривации, сравнивает двоичный результат с целью и записывает найденное совпадение.

### Ответственное использование

Используйте программу только для своих кошельков, резервных копий, ключей и хешей либо при наличии прямого разрешения владельца. Найденная мнемоника, seed, пароль или приват дает доступ к средствам, поэтому с результатом нужно обращаться как с самым важным секретом.

Практические меры безопасности:

- запускайте поиск на надежном, по возможности отключенном от сети Mac;
- работайте с копией файла кошелька, а не с единственной резервной копией;
- не оставляйте словари, команды и найденные ключи в общедоступных папках;
- не отправляйте реальные мнемоники и приваты на сайты и в облачные сервисы;
- сложную команду сначала проверяйте на маленьком примере с заранее известным ответом;
- не запускайте два процесса с одним выходным файлом, если перемешивание строк недопустимо.

### Лицензирование

Исходные части тулкита сохраняют лицензию MIT из файла `LICENSE`. Нативная
Metal-реализация `-kangaroo` адаптирована из RCKangaroo и распространяется по
GNU GPLv3. Поэтому сборки, включающие этот режим, распространяются по GPLv3.
Полный текст и атрибуция находятся в `COPYING.GPLv3.txt` и
`THIRD_PARTY_NOTICES.md`.

### Системные требования

#### Готовый выпуск v16

- Mac на Apple Silicon (`arm64`);
- macOS 15.0 или новее;
- видеокарта Apple с поддержкой Metal;
- около 425 МБ для распакованного исполняемого файла;
- дополнительная объединенная память для фильтров, буфера результатов и тяжелых KDF кошельков.

В выпуске находится один исполняемый файл. Библиотека Metal встроена прямо в Mach-O, поэтому для запуска не нужны внешний `.metallib`, Python, пакеты Homebrew или папка с исходниками.

#### Сборка из исходников

- macOS 15.0 или новее;
- полная версия Xcode;
- компонент Metal Toolchain;
- `make`.

### Загрузка, проверка и первый запуск

На странице [выпуска v16](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v16) загрузите:

- `METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz`;
- `METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz.sha256`.

Там же находится необязательный набор программ для преобразования адресов:

- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz`;
- `METAL_CRYPTO_TOOLKIT-tools-v16-macos-arm64.tar.gz.sha256`.

Он нужен только тогда, когда обычные адреса криптовалют требуется превратить в однородные списки hex для последующего создания фильтров. Основной исполняемый файл Toolkit в этот архив не входит.

Положите оба файла в одну папку и выполните:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v16-macos-arm64.tar.gz
chmod +x METAL_CRYPTO_TOOLKIT
./METAL_CRYPTO_TOOLKIT -help
```

Контрольная сумма показывает, что архив не повредился и загрузился полностью. Она лежит рядом с архивом и поэтому не заменяет независимую подпись автора. Перед запуском убедитесь, что оба файла загружены из нужного закрытого репозитория и принадлежат ожидаемой учетной записи.

Если macOS блокирует файл, снимайте карантин только после проверки источника:

```bash
xattr -d com.apple.quarantine METAL_CRYPTO_TOOLKIT
```

### Сборка

Выберите полную установку Xcode и при необходимости загрузите компилятор Metal:

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -downloadComponent MetalToolchain
```

Соберите программу:

```bash
make clean
make -j"$(sysctl -n hw.ncpu)"
```

Готовый исполняемый файл появится по двум путям:

```text
./METAL_CRYPTO_TOOLKIT
./bin/METAL_CRYPTO_TOOLKIT
```

`build/default.metallib` — промежуточный файл сборки. Makefile добавляет его внутрь итогового исполняемого файла. Минимальная версия системы по умолчанию — macOS 15.0.

Программы преобразования адресов собираются отдельно и не требуют повторной сборки основного Toolkit:

```bash
make tools -j"$(sysctl -n hw.ncpu)"
```

Сборка или очистка одной программы и очистка всего набора:

```bash
make -C tools/cardano_address_to_hex
make -C tools/cardano_address_to_hex clean
make tools-clean
```

Обычная команда `make` по-прежнему собирает только `METAL_CRYPTO_TOOLKIT`.

### Встроенная справка

Краткий список режимов:

```bash
./METAL_CRYPTO_TOOLKIT -h
./METAL_CRYPTO_TOOLKIT -help
```

Подробная справка по конкретному режиму:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -help
./METAL_CRYPTO_TOOLKIT -poetry -help
./METAL_CRYPTO_TOOLKIT -priv -help
./METAL_CRYPTO_TOOLKIT -walletdat -help
./METAL_CRYPTO_TOOLKIT -xp -help
```

В одной рабочей команде указывайте только один основной режим. Если вместе с `-help` написано несколько режимов, будет показана справка для первого распознанного.

## Как читать команду

Обычная команда поиска состоит из имени программы и пяти логических частей:

```text
ПРОГРАММА  РЕЖИМ  ИСТОЧНИК_КАНДИДАТОВ  ПРЕОБРАЗОВАНИЕ_ИЛИ_ПУТЬ  ЦЕЛЬ  ФОРМАТ_РЕЗУЛЬТАТА
```

Небольшой пример:

```bash
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end 1000 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save -o found.txt
```

Разберем его по частям:

- `-priv` включает режим обычных приватных ключей;
- `-start 01 -end 1000` ограничивает перебор диапазоном от `0x01` до `0x1000`;
- `-c c` создает HASH160 сжатого открытого ключа Bitcoin;
- `-hash ...` сравнивает все 20 байтов этого HASH160 с указанным фиксированным значением;
- `-save` преобразует найденный Bitcoin HASH160 в печатные формы адреса;
- `-o found.txt` выбирает `found.txt` вместо стандартного `result.txt`.

В этом режиме найденная запись добавляется в файл и без `-save`. Без флага совпавшее значение остается в виде исходного hex. С флагом то же самое совпадение записывается как адрес, предусмотренный выбранной буквой `-c`. Для `-c c` программа выводит формы Bitcoin P2PKH и P2WPKH.

Последовательность hex в этом примере нужна только для показа формата команды. В рабочем запуске замените ее реальным значением цели либо известными начальными байтами, которые требуется найти.

### Три правила, которые избавляют от большинства ошибок

1. Один `-hash` и общий набор фильтров применяются ко всем выбранным буквам `-c`. Поэтому сочетайте несколько букв только тогда, когда один и тот же набор двоичных целей намеренно должен проверяться во всех этих ветках.
2. В фильтре лежат двоичные значения, а не напечатанные адреса. Адрес Bitcoin, строка Ethereum с `0x`, открытый ключ и HASH160 — разные данные.
3. Основание числа зависит от параметра. Например, `-step`, `-endstep`, Profanity `-offset` и многие границы seed/time записываются в hex, а `-plusstep`, `-addplusstep`, размеры буферов и количество заданий — обычными десятичными числами.

## Откуда берутся кандидаты

### Файлы, папки и стандартный ввод

| Параметр | Что происходит |
| --- | --- |
| `-i FILE` | Добавляет входной файл. В режимах с несколькими источниками параметр можно повторять. Обычно одна строка — один кандидат. |
| `-f DIR` | Рекурсивно просматривает папку. В обычных текстовых режимах выбираются `.txt`, а с `-all` — все файлы. В режимах кошельков набор расширений зависит от формата. |
| `-all` | Расширяет обычный просмотр `-f` за пределы `.txt`. К поиску файлов кошельков этот флаг не относится. |
| стандартный ввод | Используется только режимами, в которых предусмотрено чтение кандидатов из stdin; обычно это происходит, если не заданы `-i` и `-f`. |
| `-hex` | В поддерживающих его режимах меняет разбор входной строки на hex-байты. Точное правило, включая дополнение, разбиение и ограничение длины, зависит от режима. |
| `-delete` | Удаляет обработанный входной файл после завершения его файлового цикла. Действие необратимо; используйте только для копий. |
| `-comb LIST` | Каждый номер или диапазон задает количество слов в кандидате. Для каждого указанного количества программа составляет упорядоченные выборки из разделенных пробелами слов входного файла. Например, `1,2,4-6` означает кандидаты длиной 1, 2, 4, 5 и 6 слов. |
| `-space` | Вставляет пробелы между словами, выбранными через `-comb`. |
| `-rep` | Разрешает `-comb` повторно брать одну и ту же позицию. |

`-comb`, `-space` и `-rep` работают только во входной файловой обертке. Они не меняют стандартный ввод, PRNG, последовательный перебор и маски паролей.

### Диапазоны, направление и случайные окна

| Параметр | Назначение |
| --- | --- |
| `-start VALUE` | Первая точка. Длина и представление зависят от режима. |
| `-end VALUE` | Последняя точка. Если она не задана, режим подставляет свою максимальную границу: диапазон остается конечным, но на практике может быть неисчерпаемо большим. |
| `-step HEX` | Шаг в шестнадцатеричном виде, по умолчанию `1`. Поэтому `-step 10` означает 16, а не 10. |
| `-back` | Идти назад от `-start`. |
| `-both` | Идти в обе стороны. При двух границах положительная ветка начинается с `-start`, отрицательная — с `-end`. |
| `-random` | Выбирать случайные точки или окна внутри области, которую понимает текущий режим. |
| `-n N` | Размер окна, число раундов или другой объем работы. Точный смысл указан в справке режима. |

Не используйте `-back` и `-both` одновременно. Если написать оба, последнее разобранное направление определит поведение.

Только в последовательном `-priv` доступно расписание шага:

| Параметр | Как записывается | Что означает |
| --- | --- | --- |
| `-endstep HEX` | hex | последний шаг перед переходом расписания на новый круг |
| `-plusstep N` | десятичное число | сколько прибавлять к шагу на следующем круге |
| `-addplusstep N` | десятичное число | сколько прибавить к самому `plusstep` после достижения `endstep` |

### Свой алфавит hex и шаблоны с пропусками

`-hexset CHARS` задает от 1 до 16 неповторяющихся шестнадцатеричных символов. Порядок важен и сохраняется при переборе.

Есть два разных варианта работы:

1. **Перебор по границам.** Нужен `-start` с четным числом hex-символов. Необязательный `-end` также должен иметь четную длину. Каждая позиция перебирается по указанному алфавиту.
2. **Восстановление шаблона внутри режима.** В поддерживающих это режимах `-recovery TEMPLATE` использует один знак `*` для одной неизвестной hex-позиции, а варианты берутся из `-hexset`.

Восстановление обычного приватного ключа работает отдельно: шаблон из ровно 64 позиций читается из `-i FILE` или стандартного ввода, допускается не более 32 знаков `*`, и каждый из них всегда перебирает полный набор `0..f`. `-hexset` в этом маршруте не используется.

Пример для последних двух позиций приватного ключа:

```bash
printf '%s\n' \
  '00000000000000000000000000000000000000000000000000000000000000**' | \
  ./METAL_CRYPTO_TOOLKIT -priv -recovery -c c \
    -hash 00112233445566778899aabbccddeeff00112233
```

Шаблон содержит ровно 64 позиции. Будут проверены все 256 окончаний от `00` до `ff`.

`-hexset` нельзя сочетать с `-size`, `-sizes`, расписанием шага, направлением, случайным перебором, `-n`, PRNG, `-pass_thread` и `-der_thread`. Hex-шаблоны внутри конкретного режима поддерживаются для mnemonic, entropy, seed, HMAC, BIP32, brain, старого Electrum, старого Electrum seed, Armory Easy16 и Armory root. Для `-priv -recovery` действует отдельное правило: ровно 64 позиции.

### Маски паролей

Маски используются в режимах паролей кошельков и парольных профилях WalletJS. Маску нельзя сочетать с сырым диапазоном `-start/-end`.

| Обозначение | Какие символы перебираются |
| --- | --- |
| `?l` | строчные латинские буквы |
| `?u` | заглавные латинские буквы |
| `?d` | цифры |
| `?h` | строчные hex-символы |
| `?H` | заглавные hex-символы |
| `?s` | знаки ASCII |
| `?a` | все печатные ASCII |
| `??` | обычный знак вопроса |
| `?1` ... `?4` | свой набор из `-cs1` ... `-cs4` |

Пример:

```bash
./METAL_CRYPTO_TOOLKIT -keystore wallet.json \
  -mask '?u?l?l?l?l?d?d' -save -o keystore_found.txt
```

Здесь проверяются пароли из семи символов: одна заглавная буква, четыре строчные и две цифры. Маску лучше всегда заключать в кавычки, чтобы оболочка командной строки не разобрала специальные знаки сама.

### Встроенные каталоги PRNG

`-prng` и `-prng64` нужны для точного воспроизведения известного генератора и способа извлечения байтов. Это исследовательские режимы для восстановления старых ключей, а не способ создавать новые безопасные ключи.

| Параметр | 32-разрядный каталог | 64-разрядный каталог |
| --- | --- | --- |
| область seed | `0..FFFFFFFF` | `0..FFFFFFFFFFFFFFFF` |
| `-gen` | номера `1..489` | номера `1..223` |
| `-mode` | номера `1..762` | номера `1..218` |
| `-byte LIST` | длина получаемых байтов | длина получаемых байтов |
| `-shift LIST` | сколько значений пропустить, по умолчанию `0` | сколько значений пропустить, по умолчанию `0` |
| `-s/-e` | границы seed в hex | границы seed в hex |
| `-random` | случайные окна seed | случайные окна seed |
| `-log FILE` | включает журнал хода работы в указанном файле | включает журнал хода работы в указанном файле |

Если `-gen` или `-mode` не указаны, программа рассматривает все разрешенные сочетания, и объем работы увеличивается во много раз. В обычной PRNG-команде обязательно задавайте хотя бы одно значение `-byte`: без длины генерируемых данных некоторым маршрутам нечего отправлять на обработку.

Перед составлением команды посмотрите точные каталоги:

```bash
./METAL_CRYPTO_TOOLKIT -prng_help
./METAL_CRYPTO_TOOLKIT -prng64_help
```

Добавленный каталог совместимости Ill Bloom включает исходные профили, варианты runtime и фаз, все маски знаков внутренней цепочки и результата из соответствующей CUDA-реализации. Для энтропии 16/20/24/28/32 байта полный BE-набор содержит 128/512/2 048/8 192/32 768 уникальных знаковых потоков; для LE к диапазону mode прибавляется 256. Генераторы `221..223` режима `-prng64` упаковывают 32-разрядный seed и селектор профиля в единое пространство без повторов; режим `218` выдает исходные байты напрямую. Gen 221 хранит 7-битную маску цепочки, 8-битную маску результата и endian-бит над seed, gen 222 выбирает один из 120 runtime-профилей, gen 223 — один из 256 raw-byte профилей. Максимальные индексы этих семейств: `0000FFFFFFFFFFFF`, `00000077FFFFFFFF` и `000000FFFFFFFFFF`. Если `-e` не задан или выходит за пределы, он автоматически ограничивается выбранным семейством.

```bash
./METAL_CRYPTO_TOOLKIT -entropy -prng -gen 332 -mode 247 \
  -byte 16 -s 0 -e FFFFFFFF

./METAL_CRYPTO_TOOLKIT -entropy -prng64 -gen 221 -mode 218 \
  -byte 16 -s 0 -e 0000FFFFFFFFFFFF
```

## Пути деривации и passphrase BIP-39

### Файл путей

`-d FILE` читает по одному пути из каждой строки:

```text
m/44'/0'/0'/0/0
m/49'/0'/0'/0/0
m/84'/0'/0'/0/0
```

`-d-type` выбирает алгоритм деривации. Можно писать номер или понятное имя:

| Значение | Допустимые имена | Алгоритм |
| --- | --- | --- |
| `1` | `bip32` | BIP32 на secp256k1 |
| `2` | `slip0010`, `slip10`, `ed25519` | SLIP-0010 на ed25519 |
| `3` | `bip32-ed25519`, `cardano`, `ada` | Cardano BIP32-ed25519 |

Несколько значений разделяются запятыми либо задаются повторно. Если `-d-type` отсутствует, программа старается выбрать нужный алгоритм по семействам из `-c`.

`-d-dot FILE` читает пути SURI для Polkadot/Kusama/Substrate. У SURI другой синтаксис, поэтому такой файл задается отдельно. Для DOT достаточно `-d-dot`, обычный `-d` не обязателен.

### Дополнительная passphrase BIP-39

Passphrase BIP-39 — это дополнительный текст в преобразовании мнемоники в seed. Это не пароль от файла кошелька.

| Параметр | Что делает |
| --- | --- |
| `-pass FILE` | Если такой файл существует, читает по одной passphrase из каждой строки. |
| `-pass TEXT` | Если файл с таким именем не открылся, использует сам аргумент как одну буквальную passphrase. |
| `-passbrute HEX_START:HEX_END` | Перебирает байтовый диапазон passphrase, записанный в hex. |
| `-pass_thread` | Оставляет одну мнемонику/энтропию и распределяет множество passphrase по потокам и устройствам. |
| `-der_thread` | Оставляет один источник и распределяет множество путей по потокам и устройствам. |
| `-pbkdf N` | Меняет число повторений PBKDF2; по умолчанию `2048`. |

`-pass_thread` и `-der_thread` описывают взаимоисключающие схемы. Разборщик отклоняет не каждое такое сочетание: если оба флага доходят до запуска mnemonic или entropy, сначала проверяется `-pass_thread`, а `-der_thread` не выполняется. Оба режима также не поддерживаются с hexset-шаблонами и несовместимыми последовательными/случайными ветками.

## Что означает `-c`

`-c TYPES` выбирает, какие значения строить из каждого ключа. Регистр букв важен. По умолчанию используется `cus`. Один глобальный префикс `-hash` и один общий набор Metal-фильтров, объединенных по правилу ИЛИ, применяются к каждой выбранной ветке. Поэтому сочетайте буквы только тогда, когда такой общий набор целей действительно нужен.

| Буква | Кривая | Что проверяется |
| --- | --- | --- |
| `c` | secp256k1 | Bitcoin HASH160 сжатого открытого ключа |
| `u` | secp256k1 | Bitcoin HASH160 несжатого открытого ключа |
| `s` | secp256k1 | HASH160 для ветки SegWit, завернутой в P2SH |
| `p` | secp256k1 | ветка P2WSH; в найденной записи хранится полный 32-байтовый witness program |
| `r` | secp256k1 | выходной ключ Taproot; сравнение выполняется по RIPEMD-160 от этого 32-байтового ключа |
| `e` | secp256k1 | 20-байтовое значение адреса Ethereum |
| `x` | secp256k1 | 32-байтовая координата X открытого ключа |
| `T` | ed25519 | варианты адресов TON |
| `S` | ed25519 | открытый ключ/адрес Solana |
| `d` | ed25519/sr25519 | Polkadot/Substrate |
| `f` | secp256k1 | Filecoin f1/f4 |
| `i` | secp256k1/ed25519 | IOTA |
| `a` | ed25519 | семейства Byron/Shelley Cardano |
| `A` | ed25519/secp256k1 | Aptos |
| `U` | secp256k1/ed25519 | Sui |
| `X` | secp256k1/ed25519 | XRP |
| `I` | ed25519/secp256k1 | Internet Computer |
| `Z` | secp256k1/ed25519 | Tezos |

Для `p` сравнение с фильтром выполняется по RIPEMD160 от 32-байтового P2WSH witness program. Найденная запись содержит полный 32-байтовый program, а с `-save` он выводится как адрес Bech32. Поэтому фильтр P2WSH нужно строить именно из ожидаемых программой 20-байтовых значений сравнения, а не из текстовых адресов и не из произвольных 32-байтовых строк.

У ветки `r` также различаются сохраняемое значение и значение сравнения. В найденной записи находится полный 32-байтовый выходной ключ Taproot, а `-hash` и фильтры проверяют его 20-байтовый RIPEMD-160. Мультивалютный конвертер выполняет этот RIPEMD-160 автоматически, когда получает адрес Taproot Bech32m. Если исходными данными является сырой 32-байтовый выходной ключ, значение сравнения нужно рассчитать отдельно либо сразу передать готовый 20-байтовый hex.

### Варианты сетей и адресов

Списки понимают запятые и диапазоны: например, `-ton-type 1,4-10`. Если параметр варианта не задан, включаются все варианты этого семейства.

| Параметр | Значения |
| --- | --- |
| `-ton-type` | `1=v1r1`, `2=v1r2`, `3=v1r3`, `4=v2r1`, `5=v2r2`, `6=v3r1`, `7=v3r2`, `8=v4r1`, `9=v4r2`, `10=v5r1`, `11=highload v1`, `12=highload v2`, `13=highload v3` |
| `-dot-type` | `1=ed25519`, `2=sr25519` |
| `-fil-type` | `1=f1`, `2=f4` |
| `-iota-type` | `1=secp256k1`, `2=ed25519` |
| `-ada-type` | `1=Byron Icarus`, `2=Shelley Base`, `3=Shelley Enterprise`, `4=Byron Daedalus`, `5=Shelley Reward`, `6=Shelley Pointer`, `7=Shelley Exodus`, `8=Byron Ledger`, `9=Shelley Ledger`, `10=Byron Legacy` |
| `-ada-pointer slot:tx:cert` | значения указателя Cardano type 6; без них эта ветка молча пропускается, даже если type 6 выбран |
| `-aptos-type` | `1=legacy ed25519`, `2=generalized ed25519`, `3=generalized secp256k1` |
| `-sui-type` | `1=secp256k1`, `2=ed25519` |
| `-xrp-type` | `1=secp256k1`, `2=ed25519` |
| `-icp-type` | `1=ed25519`, `2=secp256k1` |
| `-xtz-type` | `1=secp256k1`, `2=ed25519` |

Поддержка целей и проверка сочетаний зависят от режима. Часть неподдерживаемых сочетаний источник/цель отклоняется, а часть принимается, но затем пропускается или не может дать совпадение. Перед большим запуском проверьте подробную справку режима и один заранее известный пример.

## Прямая цель и фильтры

### Одна цель

| Параметр | Назначение |
| --- | --- |
| `-hash HEX` | В режимах прямого поиска задает одну фиксированную двоичную цель-префикс длиной от 2 до 32 байтов. Обычная проверка принимает не более 20 байтов. Байты с 21-го по 32-й работают только в режимах, где отдельно реализовано сравнение более длинного двоичного значения, и никогда не выходят за его настоящую длину. Режимы паролей файлов кошельков этот параметр не используют; WalletJS использует. |
| `-target HEX` | Другое имя `-hash` в обычных режимах проверки целей. В `-profanity -recovery` оба имени принимают полный открытый ключ, как описано в разделе этого режима. |
| `-pubkey` | Устарел и намеренно отклоняется. Используйте `-target` или `-hash`. |
| `-full` | Перед обычной проверкой прямой цели и Metal-фильтров считать найденным каждое вычисленное значение. Это отладочный флаг, который очень быстро заполняет память и диск. |

После необязательного префикса `0x` параметр `-hash` должен содержать четное число hex-символов. Разборщик принимает ровно от 2 до 32 байтов, то есть от 4 до 64 hex-символов. Сравнение всегда начинается с первого байта вычисленного значения. Обычная проверка останавливается на 20 байтах; режимы с отдельной проверкой более длинного значения останавливаются на его настоящей длине или на 32 байтах, если значение длиннее. Поэтому одна только длина результата выбранной буквы `-c` не гарантирует, что в этой ветке можно использовать прямую цель длиной 21–32 байта.

- `-c c -hash 00112233` проверяет первые 4 байта HASH160 сжатого открытого ключа;
- `-c c -hash 00112233445566778899aabbccddeeff00112233` проверяет все 20 байтов этого HASH160;
- обычный 20-байтовый путь сравнения не может совпасть с `-hash` длиннее 40 hex-символов;
- 21–32 байта можно проверить только в режиме, где отдельно реализовано сравнение значения такой длины.

В `-hash` передаются декодированные двоичные байты в виде hex, а не адрес Base58, Bech32, SS58 или другого печатного формата. Например, `-c p` для P2WSH сравнивает 20-байтовый RIPEMD160, хотя в найденную запись помещается полный 32-байтовый witness program.

В v14 последовательные и Vanity-кернелы `-priv` используют обычную 20-байтовую проверку даже для 32-байтового результата, такого как `-c x`. В этих маршрутах прямой `-hash` длиннее 20 байтов совпасть не может. Некоторые другие режимы отдельно сравнивают более длинные значения и могут проверять до 32 байтов.

Повторяющиеся последовательности `001122...` в примерах показывают только формат и длину hex. Это не встроенные цели программы. Замените их конкретным полным значением либо известным начальным префиксом для своей разрешенной задачи.

Если одновременно заданы `-hash` и один или несколько обычных Metal-фильтров, кандидат должен совпасть с прямым префиксом **и** хотя бы с одним активным Metal-фильтром. `-full` пропускает эти проверки на стороне Metal, но явно заданный `-xx` или `-xb` по-прежнему может отклонить предварительное совпадение на CPU до записи результата.

### Bloom- и XOR-фильтры

| Параметр | Тип |
| --- | --- |
| `-bf PATH` | Bloom-фильтр |
| `-xu PATH` | несжатый XOR-фильтр |
| `-xc PATH` | сжатый XOR-фильтр |
| `-xuc PATH` | сверхсжатый XOR-фильтр |
| `-xh PATH` | максимально сжатый XOR-фильтр |

Для создания и проверки Binary Fuse 4-wise фильтров используйте отдельный проект [XorFilter](https://github.com/XopMC/XorFilter).

| Файл XorFilter | Параметр при создании | Параметр поиска |
| --- | --- | --- |
| `.xor_u` | без сжатия | `-xu` |
| `.xor_c` | `-compress` | `-xc` |
| `.xor_uc` | `-ultra` | `-xuc` |
| `.xor_hc` | `-hyper` | `-xh` |

Пример:

```bash
mkdir -p filters
(cd filters && XorFilter -i ../btc_compressed_hash160.txt -compress -check)
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff \
  -c c -xc filters/btc_compressed_hash160_0.xor_c -save -o found.txt
```

В исходном списке должно быть одно двоичное значение в hex на строку. Фильтр должен быть однородным по длине и двоичному представлению. Файлы фильтров не привязаны к отдельным буквам `-c`: каждая выбранная ветка проверяется по каждому активному фильтру, а совпадения обычных Metal-фильтров объединяются по правилу ИЛИ. Не смешивайте в одном фильтре адреса, открытые ключи, HASH160, значения Ethereum, значения сравнения P2WSH и разные сетевые семейства.

Сжатие экономит память, но повышает вероятность того, что случайный кандидат дойдет до обработки результатов. Даже `.xor_u` хранит отпечаток конечной длины и сам по себе не является математическим доказательством: найденный секрет всегда проверяйте независимо.

### Необязательная проверка на CPU: `-xx` и `-xb`

Эти параметры не обязательны. Для обычного поиска достаточно `-hash`/`-target` либо одного из основных Metal-фильтров из таблицы выше. Дополнительная проверка нужна тогда, когда в основном Metal-кернеле выгодно использовать небольшой сжатый фильтр, а редкие предварительные совпадения требуется перепроверить по более крупному и точному набору.

| Параметр | Что делает | Когда применять |
| --- | --- | --- |
| `-xx PATH` | Загружает несжатый `.xor_u` для проверки на CPU | Чтобы перепроверять совпадения от `-xc`, `-xuc` или `-xh` по соответствующему несжатому XOR-набору |
| `-xb PATH` | Загружает Bloom-фильтр для проверки на CPU | Чтобы перепроверять совпадения сжатого XOR-фильтра, если для того же набора целей имеется Bloom-фильтр |

Работа делится на два этапа:

```text
Metal-кернел -> компактный фильтр -> редкое совпадение -> проверка на CPU -> вывод результата
```

В обычных режимах такая перепроверка выполняется в фоновой очереди обработки результатов. CPU не проверяет каждый созданный кандидат. В `-profanity -recovery` у `-xx` есть еще одно важное назначение: отсеять ложные совпадения basepoint-X до значительно более тяжелого этапа восстановления seed.

У Apple Silicon общая память, поэтому `-xx` и `-xb` **не** дают отдельную «оперативную память CPU» в дополнение к «памяти видеокарты». Польза в другом: Metal-кернел постоянно обращается только к небольшому фильтру, а CPU читает крупный проверочный набор лишь при редких совпадениях. При этом оба фильтра занимают одну и ту же общую память Mac.

Полезные сочетания:

```bash
# Самый компактный фильтр в Metal и дополнительная проверка по менее сжатому XOR-набору на CPU.
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff -c c \
  -xh btc_targets.xor_hc -xx btc_targets.xor_u -save

# Сжатый XOR-фильтр в Metal и дополнительная проверка по Bloom на CPU.
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff -c c \
  -xuc btc_targets.xor_uc -xb btc_targets.blf -save
```

Важные правила:

- основной фильтр и проверочный набор должны использовать одну длину и одно двоичное представление, а CPU-фильтр обязан содержать каждую цель, которую вы хотите принять; обычно оба фильтра создаются из одного исходного списка;
- `-xx` и `-xb` являются вторым этапом проверки, а не самостоятельным источником целей;
- сочетание `-xu targets.xor_u -xx targets.xor_u` обычно бессмысленно: один несжатый набор будет проверен дважды;
- сочетание `-bf targets.blf -xb targets.blf` также не дает дополнительной точности;
- если одновременно указаны `-xx` и `-xb`, достаточно совпадения в любом загруженном CPU-фильтре; не смешивайте в них посторонние наборы целей;
- наибольший смысл CPU-проверка имеет вместе с `-xc`, `-xuc` или `-xh`. Если обычный `-xu` свободно помещается в память и работает с приемлемой скоростью, дополнительный CPU-фильтр чаще всего не нужен.

## Преобразование адресов в hex

В папке `tools/` находятся 14 небольших конвертеров адресов и отдельная программа `profanity_basepoint_generator`. Конвертеры проверяют обычные адреса криптовалют или закодированные строки и формируют из них то двоичное значение, которое сравнивает выбранная ветка цели. Это значение записывается в виде строчного hex. Конвертеры не перебирают ключи и не создают Bloom- или XOR-фильтры. Их единственная задача — подготовить чистый однородный список для программы, которая строит фильтр.

У всех программ одинаковый интерфейс:

```text
TOOL <input.txt> [output.txt] [-t N]
TOOL -h
```

- в `input.txt` указывается по одному адресу или значению на строку;
- имя `output.txt` можно не писать: тогда для `name.txt` рядом будет создан `name-hex.txt`;
- `-t N` задает от 1 до 256 потоков CPU; по умолчанию используется число логических процессоров Mac;
- пробелы по краям строк и переносы CRLF разрешены, пустые строки пропускаются;
- правильные значения записываются в исходном порядке, по одному строчному hex на строку;
- отклоненные строки записываются в `name-invalid.txt` после удаления пробелов по краям; если ошибок нет, такой файл не создается;
- отдельные плохие строки не делают весь запуск ошибочным. Код возврата `1` означает ошибку параметров, открытия/записи файла или внутренний сбой.

Первый правильный результат задает длину всех значений в текущем выходном файле. Если следующий адрес преобразуется в другое число байтов, он попадет в `-invalid.txt`. Такая проверка не дает случайно смешать, например, 20-байтовые и 32-байтовые цели.

После сборки из исходников исполняемый файл находится по пути `tools/<проект>/bin/<программа>`. В готовом архиве выпуска 14 конвертеров и генератор базовых точек Profanity лежат прямо в распакованной папке `tools/`.

| Программа | Что можно подать на вход | Что записывается в hex | Совместимая ветка Toolkit |
| --- | --- | --- | --- |
| `cardano_address_to_hex` | Cardano Shelley Bech32 или Byron Base58 с проверкой CBOR/CRC | SHA-256 от декодированного адреса, 32 байта / 64 hex-символа | `-c a` с подходящим `-ada-type` |
| `algorand_address_to_hex` | 58-символьный адрес Algorand Base32 с checksum SHA-512/256 | исходный открытый ключ ed25519, 32 байта / 64 hex-символа | `-c S` |
| `multicoin_base58_bech32_address_to_hex` | Bitcoin-подобные Base58Check, SegWit Bech32/Bech32m, CashAddr либо готовый hex на 20/32 байта | 20-байтовое значение сравнения для адреса; raw hex сохраняет длину 20/32 байта | `-c c`, `u`, `s`, `p` или `r` в зависимости от устройства адреса |
| `base64_data_to_hex` | строгий Base64 или Base64URL с padding либо без него | декодированные байты; одна длина на файл | определяется тем, что означают декодированные байты |
| `cosmos_bnb_address_to_hex` | Bech32 с 20-байтовым payload либо готовый 20-байтовый hex | payload 20 байтов / 40 hex-символов | `-c c` для обычных secp256k1 account addresses |
| `polkadot_kusama_address_to_hex` | SS58 с 32-байтовым account ID и одно- или двухбайтовым префиксом сети | account ID 32 байта / 64 hex-символа | `-c d` с `-dot-type 1` или `2` |
| `filecoin_address_to_hex` | Filecoin `f1`, `t1`, `f410` или `t410` с checksum Blake2b | payload 20 байтов / 40 hex-символов | `-c f -fil-type 1/2`; делегированные `f410/t410` также подходят для `-c e` |
| `solana_address_to_hex` | открытый ключ Base58, который декодируется ровно в 32 байта | исходный открытый ключ ed25519, 32 байта / 64 hex-символа | `-c S` |
| `stellar_address_to_hex` | Stellar StrKey `G...` или muxed-адрес `M...` с CRC16 | исходный открытый ключ ed25519, 32 байта / 64 hex-символа | `-c S` |
| `stacks_address_to_hex` | Stacks C32Check `SP`, `ST`, `SM` или `SN` | HASH160 20 байтов / 40 hex-символов | `SP/ST`: `-c c` или `u`; для `SM/SN` общей single-key ветки нет |
| `ton_address_to_hex` | friendly-адрес TON Base64/Base64URL, `workchain:hex` либо готовый 32-байтовый hex | account ID 32 байта / 64 hex-символа | `-c T` с подходящим `-ton-type` |
| `tron_address_to_hex` | адрес Tron Base58Check с буквы `T` либо готовый 20-байтовый hex | совместимый с Ethereum account ID, 20 байтов / 40 hex-символов | `-c e` |
| `xrp_address_to_hex` | XRP Classic Base58Check либо готовый 20-байтовый hex | account ID 20 байтов / 40 hex-символов | `-c X` с `-xrp-type 1` или `2` |
| `tezos_address_to_hex` | адрес Tezos `tz1` или `tz2` с Base58Check | key hash 20 байтов / 40 hex-символов | `-c Z`; для `tz1` нужен `-xtz-type 2`, для `tz2` — `1` |

`profanity_basepoint_generator` не является конвертером адресов. Он создает полный список базовых точек фиксированной длины, обязательный для `-profanity -recovery`; формат и порядок работы описаны ниже отдельно.

### Совместимость двоичного значения и формат результата

В таблице указана совместимость двоичных значений. Это не означает, что Toolkit напечатает адрес в формате исходной сети. У нескольких сетей совпадает значение, которое сравнивается внутри программы:

- `-c S` сравнивает исходный 32-байтовый открытый ключ ed25519. Поэтому с этой веткой можно использовать списки Solana, Algorand и Stellar, но `-save` подпишет и закодирует результат как Solana;
- `-c c` сравнивает HASH160 сжатого открытого ключа secp256k1. Такое же 20-байтовое значение используется в обычных secp256k1-аккаунтах Cosmos/BNB и в P2PKH-адресах Stacks, но `-save` сформирует адреса Bitcoin;
- `-c e` сравнивает 20-байтовое EVM-значение, полученное через Keccak. Эти же байты находятся в адресах Tron и делегированных адресах Filecoin `f410/t410`, но `-save` выведет представление Ethereum;
- совместимая буква `-c` не выбирает способ получения ключа. Режим входа, трактовка seed, путь деривации, кривая и subtype должны привести к тому же ключу, из которого был создан исходный адрес.

### Каждая программа отдельно

#### `cardano_address_to_hex` - Cardano

Принимает адреса Shelley `addr...`/`stake...` в Bech32 и Byron в Base58. Для Shelley проверяются сеть, строение адреса и кодирование pointer, если он присутствует. Для Byron проверяются CBOR и CRC. В файл записывается SHA-256 от декодированных байтов адреса — именно его сравнивает ветка `-c a`.

Необходимо выбрать соответствующий `-ada-type`: Byron, Shelley Base, Enterprise, Reward и Pointer являются разными подтипами. Конвертер также принимает Shelley-адреса, где payment- или stake credential является хешем скрипта. Такой адрес можно правильно декодировать, но обычный перебор приватных ключей не сможет создать его script credential, поэтому сам факт декодирования не делает его key-derived целью.

```bash
tools/cardano_address_to_hex cardano-addresses.txt cardano-targets.txt -t 8
```

#### `algorand_address_to_hex` - Algorand

Принимает обычный 58-символьный адрес Algorand в верхнем регистре, проверяет алфавит Base32 и checksum SHA-512/256, затем записывает исходный 32-байтовый открытый ключ ed25519, из которого согласно [формату адресов Algorand](https://developer.algorand.org/docs/get-details/encoding/) и состоит основная часть адреса. Эти байты совместимы с `-c S`, потому что ветка `S` сравнивает сам открытый ключ ed25519. Выбранный режим должен получить именно ключ Algorand; `-save` оформит совпадение как Solana, а не восстановит адрес Algorand.

```bash
tools/algorand_address_to_hex algorand-addresses.txt algorand-public-keys.txt
XorFilter -i algorand-public-keys.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c S -xu algorand-public-keys_0.xor_u
```

#### `multicoin_base58_bech32_address_to_hex` - мультивалютные Bitcoin-подобные сети

Это общий конвертер для Bitcoin-подобных валют, а не программа только для Bitcoin. Он принимает Base58Check с правильной checksum, префиксом от одного до четырех байтов и 20-байтовым payload, witness v0 в Bech32, Taproot v1 в Bech32m, CashAddr с 20-байтовым payload и готовый hex на 20 или 32 байта. Конвертер проверяет кодирование, но не содержит списка разрешенных сетевых префиксов и Bech32 HRP. Поэтому по одному payload он не может определить исходную валюту.

P2PKH от сжатого ключа и P2WPKH используют `-c c`; P2PKH от несжатого ключа использует `-c u`. У Base58Check- или CashAddr-адреса P2SH внутри может быть любой redeem script. Используйте `-c s` только тогда, когда точно известно, что это именно P2SH-wrapped SegWit, который строит Toolkit. Обычный multisig и другие P2SH-скрипты автоматически к `s` не относятся. Для P2WSH и Taproot конвертер берет 32-байтовый witness program и сразу рассчитывает 20-байтовый RIPEMD-160, который ожидают `-c p` и `-c r`. Готовый raw hex на 32 байта остается без изменений, потому что в нем нет версии адреса, позволяющей выбрать ветку.

Правила основаны на формате, поэтому тот же бинарник декодирует совместимые сети на основе Bitcoin, например Litecoin, Dogecoin и Dash. Каждую валюту, способ построения адреса и ветку цели храните в отдельном исходном файле и фильтре.

```bash
tools/multicoin_base58_bech32_address_to_hex bitcoin-addresses.txt bitcoin-targets.txt
```

#### `base64_data_to_hex` - данные Base64 и Base64URL

Строго декодирует Base64/Base64URL с padding или без него. Неизвестные символы, смешение двух алфавитов, `=` в неправильном месте и ненулевые неиспользуемые биты отклоняются. В Base64 нет checksum, и само кодирование ничего не говорит о назначении данных. Выбирайте `-c` только после того, как определили, что находится внутри: account ID, открытый ключ, HASH160 или другое поддерживаемое значение. Все строки в одном файле должны иметь одинаковую длину и смысл.

```bash
tools/base64_data_to_hex encoded-values.txt decoded-values.txt
```

#### `cosmos_bnb_address_to_hex` - семейство Cosmos и BNB

Принимает Bech32 с 20-байтовым payload, включая обычные адреса Cosmos Hub и BNB, либо готовый 20-байтовый hex. Программа проверяет Bech32, но не сверяет HRP со списком известных сетей. Правильная checksum и длина 20 байтов сами по себе не доказывают принадлежность адреса к определенной сети.

У обычного secp256k1-аккаунта payload равен RIPEMD-160(SHA-256(сжатый открытый ключ)). Это в точности значение ветки `-c c`; тот же порядок вычислений указан в [описании адресов Cosmos SDK](https://docs.cosmos.network/sdk/latest/guides/reference/bech32). Такое соответствие нельзя применять к legacy multisig, validator consensus address, secp256r1 и другим схемам ключей. `-save` оформит совпадение как Bitcoin, поэтому для Cosmos/BNB сравнивайте найденный 20-байтовый payload с результатом конвертера.

```bash
tools/cosmos_bnb_address_to_hex cosmos-addresses.txt cosmos-payloads.txt
XorFilter -i cosmos-payloads.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c c -xu cosmos-payloads_0.xor_u
```

#### `polkadot_kusama_address_to_hex` - Polkadot, Kusama и Substrate

Принимает полную форму SS58 с 32-байтовым account ID и правильным одно- или двухбайтовым префиксом сети. Программа проверяет checksum Blake2b с префиксом `SS58PRE` и возвращает только account ID. Для ed25519 используйте `-c d -dot-type 1`, для sr25519 — `-c d -dot-type 2`. Префикс SS58 не определяет кривую и не входит в сравниваемое значение. Другие размеры payload и другие схемы ключей не принимаются.

```bash
tools/polkadot_kusama_address_to_hex substrate-addresses.txt substrate-account-ids.txt
```

#### `filecoin_address_to_hex` - Filecoin

Принимает mainnet/testnet адреса `f1`/`t1` и делегированные `f410`/`t410`. Проверяются строчный Base32, протокол или namespace, точная длина payload и checksum Blake2b. Эти два вида нужно хранить отдельно:

- `f1/t1` содержит Filecoin Blake2b-160 от открытого ключа secp256k1 и используется с `-c f -fil-type 1`;
- `f410/t410` из namespace 10 содержит обычный 20-байтовый адрес Ethereum, как описано в документации [Filecoin Ethereum Address Manager](https://docs.filecoin.io/smart-contracts/filecoin-evm-runtime/address-types). Его можно искать через `-c f -fil-type 2`, чтобы `-save` вывел Filecoin, либо через `-c e`, чтобы получить формат Ethereum.

```bash
tools/filecoin_address_to_hex filecoin-addresses.txt filecoin-targets.txt
XorFilter -i filecoin-f1-targets.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c f -fil-type 1 -xu filecoin-f1-targets_0.xor_u
```

#### `solana_address_to_hex` - Solana

Декодирует открытый ключ Solana из Base58 и требует получить ровно 32 байта. В адресе Solana нет checksum, поэтому опечатку можно обнаружить только по неправильному алфавиту или длине после декодирования. Результат используется с целью `-c S`.

```bash
tools/solana_address_to_hex solana-addresses.txt solana-public-keys.txt
```

#### `stellar_address_to_hex` - Stellar

Принимает обычный Stellar StrKey с буквы `G` и muxed-адрес с буквы `M`. Проверяются байт версии и checksum CRC16-XMODEM. Для `M...` записывается исходный 32-байтовый открытый ключ ed25519 без muxed ID. В [формате muxed accounts Stellar](https://developers.stellar.org/docs/build/guides/transactions/pooled-accounts-muxed-accounts-memos) этот ID является отдельной частью, поэтому разные muxed ID одного аккаунта дают одинаковый hex. Открытый ключ совместим с `-c S`, но исходный режим должен повторить способ получения ключа Stellar, а `-save` оформит результат как Solana.

```bash
tools/stellar_address_to_hex stellar-addresses.txt stellar-public-keys.txt
XorFilter -i stellar-public-keys.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c S -xu stellar-public-keys_0.xor_u
```

#### `stacks_address_to_hex` - Stacks

Принимает четыре стандартных варианта [Stacks C32Check](https://docs.stacks.co/more-guides/c32check) и после проверки алфавита, версии, длины и checksum записывает 20-байтовый HASH160. Разные классы адресов необходимо хранить отдельно:

- `SP` в mainnet и `ST` в testnet являются P2PKH. Их HASH160 совместим с `-c c` для обычного сжатого открытого ключа либо с `-c u`, если адрес специально создавался из несжатого ключа;
- `SM` в mainnet и `SN` в testnet являются P2SH. По payload нельзя восстановить redeem script, поэтому это не общая single-key цель и такие адреса нельзя автоматически запускать через `-c s`.

С ветками `c` и `u` флаг `-save` сформирует адрес Bitcoin. При поиске Stacks P2PKH сравнивайте найденный HASH160 с результатом конвертера.

```bash
tools/stacks_address_to_hex stacks-addresses.txt stacks-hash160.txt
XorFilter -i stacks-p2pkh-hash160.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c c -xu stacks-p2pkh-hash160_0.xor_u
```

#### `ton_address_to_hex` - TON

Принимает friendly-адрес TON в Base64/Base64URL, запись `workchain:64-hex` или готовый 32-байтовый account ID. У friendly-адреса проверяются допустимый tag, точная длина и CRC16. Workchain, bounceable/test flags и внешний вид адреса отбрасываются, поэтому разные friendly-формы одного аккаунта дают одинаковый hex. Используйте `-c T` и тот `-ton-type`, которым был создан исходный wallet contract.

```bash
tools/ton_address_to_hex ton-addresses.txt ton-account-ids.txt
```

#### `tron_address_to_hex` - Tron

Принимает адрес Tron в Base58Check с обязательным сетевым байтом `0x41` либо готовый 20-байтовый hex account ID. Программа проверяет checksum и удаляет только сетевой байт Tron. Оставшиеся 20 байтов являются тем же значением, полученным из Keccak и используемым Ethereum-подобной целью `-c e`; печатная строка `T...` повторно не хешируется.

```bash
tools/tron_address_to_hex tron-addresses.txt ethereum-style-account-ids.txt
```

#### `xrp_address_to_hex` - XRP Ledger

Принимает XRP Classic или готовый 20-байтовый account ID. Используется отдельный алфавит Base58 XRP, проверяются Base58Check и версия Classic account. Полученные байты используются с `-c X`. По самому Classic address нельзя определить исходную кривую: для secp256k1 укажите `-xrp-type 1`, для ed25519 — `-xrp-type 2` в соответствии с исходным кошельком. X-addresses не принимаются.

```bash
tools/xrp_address_to_hex xrp-addresses.txt xrp-account-ids.txt
XorFilter -i xrp-account-ids.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-keys.txt \
  -c X -xrp-type 1 -xu xrp-account-ids_0.xor_u
```

#### `tezos_address_to_hex` - Tezos

Принимает implicit account `tz1` на ed25519 и `tz2` на secp256k1, проверяет их префикс Base58Check и checksum, затем записывает 20-байтовый key hash для `-c Z`. Для `tz1` используйте `-xtz-type 2`, для `tz2` — `-xtz-type 1`; храните их в разных фильтрах. `tz3`, `KT1` и остальные классы адресов Tezos намеренно отклоняются.

```bash
tools/tezos_address_to_hex tezos-addresses.txt tezos-key-hashes.txt
XorFilter -i tezos-tz1-key-hashes.txt -check
./METAL_CRYPTO_TOOLKIT -priv -hex -i private-seeds.txt \
  -c Z -xtz-type 2 -xu tezos-tz1-key-hashes_0.xor_u
```

#### `profanity_basepoint_generator` - базовые точки Profanity recovery

Это генератор, а не конвертер адресов. Для каждого выбранного 32-битного seed Profanity он повторяет уязвимое состояние MT19937-64, вычисляет базовую открытую точку secp256k1 и записывает первые 20 байтов ее канонической affine-X координаты. На каждый seed получается ровно 40 строчных hex-символов и `\n`; строки идут по возрастанию seed. Именно такой исходный список нужен для XOR-фильтров режима `-profanity -recovery`.

Программа использует общую 14-битную таблицу secp256k1, подобранную для процессоров Apple Silicon, многопоточное умножение, пакетную инверсию поля, ограниченную очередь упорядоченной записи и сброс данных каждые 256 MiB. Сам XOR-фильтр она не создает.

```text
profanity_basepoint_generator [output.txt] [-s HEX32] [-e HEX32] [-t N] [--resume]
```

- без имени файла создается `PROFANITY_BASEPOINT.txt`;
- `-s` и `-e` задают включительные границы seed32; по умолчанию используется весь диапазон `00000000..ffffffff`;
- `-t` задает `1..256` потоков CPU; по умолчанию берется число логических процессоров Mac;
- `--resume` вычисляет следующий seed по размеру уже записанного файла. Продолжение разрешено только при размере, кратном фиксированным 41 байтам на строку, если файл не длиннее выбранного диапазона, а первая и последняя записанные строки соответствуют этому диапазону;
- при `SIGINT`/`SIGTERM` программа дописывает уже взятые блоки и оставляет непрерывный файл, который можно продолжить.

Сначала соберите программу и проверьте небольшой диапазон:

```bash
make -C tools/profanity_basepoint_generator
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  profanity-test.txt -s 0 -e ffff -t 8
```

Полный список лучше создавать на локальном SSD, где свободно не менее 200 GB:

```bash
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  PROFANITY_BASEPOINT.txt -t "$(sysctl -n hw.logicalcpu)"

# Продолжение того же диапазона после штатной остановки:
tools/profanity_basepoint_generator/bin/profanity_basepoint_generator \
  PROFANITY_BASEPOINT.txt -t "$(sysctl -n hw.logicalcpu)" --resume
```

Полный исходник для `2^32` seed имеет точный размер `176 093 659 136` байт: 176,09 GB в десятичной записи или 164 GiB. Создавайте его на быстром локальном диске и переносите после завершения: при прямой записи на SMB или сетевой диск ограничением может стать сеть. Создание фильтров и требования к памяти подробно описаны в разделе `-profanity -recovery`.

Результаты P2WSH и Taproot из `multicoin_base58_bech32_address_to_hex` можно сразу передавать в XorFilter: дополнительная обработка через OpenSSL не нужна. Строка raw hex на 32 байта сохраняется полностью. Если это полный выходной ключ Taproot, а не заранее подготовленное значение сравнения, передайте адрес Bech32m либо самостоятельно рассчитайте требуемый 20-байтовый RIPEMD-160 перед созданием фильтра.

### Как фильтруются списки на 20 и 32 байта

Полный результат конвертера и ключ внутри фильтра — не одно и то же:

- конвертеры записывают полное целевое значение, которое они сформировали, без скрытого обрезания: 40 hex-символов для 20-байтового результата или 64 для 32-байтового;
- текущий формат [XorFilter](https://github.com/XopMC/XorFilter) строит ключ по первым 20 байтам каждой строки, а Bloom/XOR-проверка Toolkit сравнивает те же первые 20 байтов;
- фильтр из 32-байтовых целей поэтому работает как 160-битный предварительный фильтр. В найденный результат попадает полный payload кандидата, но любой Binary Fuse-фильтр является вероятностным; у каждого формата есть указанная для него вероятность ложного совпадения;
- каждый найденный результат необходимо сверять с полным исходным списком конвертера. Для Algorand/Stellar через `S` и Cosmos/Stacks через `c` сравнивайте именно двоичные данные, потому что `-save` использует формат Solana или Bitcoin.

Не смешивайте в одном входном файле разные валюты, алгоритмы ключей, способы построения адреса и длины 20/32 байта. Даже при одинаковой длине отдельные фильтры не дадут ошибочно отнести совпадение к другой ветке.

Полная цепочка подготовки фильтра выглядит так:

```text
addresses.txt -> конвертер -> targets-hex.txt -> XorFilter -> .xor_* -> METAL_CRYPTO_TOOLKIT
```

Например:

```bash
tools/cardano_address_to_hex cardano-addresses.txt cardano-targets.txt -t 8
mkdir -p filters
(cd filters && XorFilter -i ../cardano-targets.txt -check)
./METAL_CRYPTO_TOOLKIT -mnemonic -i phrases.txt -d derivation.txt \
  -c a -xu filters/cardano-targets_0.xor_u -save -o found.txt
```

Сам Binary Fuse-фильтр создает отдельный проект [XopMC/XorFilter](https://github.com/XopMC/XorFilter). Конвертеры лишь готовят для него список. Полный файл, созданный конвертером, остается основным списком для окончательной проверки найденных результатов.

## Сохранение, буферы и устройства

### Формат результата и файл

| Параметр | Что делает |
| --- | --- |
| `-save` | В режимах поиска ключей и дериваций преобразует найденное двоичное значение в адрес криптовалюты, если для выбранного типа цели предусмотрено адресное представление. В перечисленных ниже специальных режимах этот флаг также разрешает запись результата в файл. |
| `-o FILE` | Выбирает файл; по умолчанию `result.txt`. |
| `-silent` | Не печатает найденные строки в терминал. Поведение файла остается таким, как описано ниже для выбранного режима. |
| `-fsize N` | Количество мест под результаты на каждом устройстве; по умолчанию `150000`. |

В режимах `-mnemonic`, `-recovery`, `-poetry`, `-entropy`, `-seed`, `-hmac`, `-bip32`, `-pass_thread`, `-der_thread`, `-priv`, `-minikeys`, `-brain`, старого Electrum и ключевых режимах Armory файл результата открывается в режиме добавления, а каждое совпадение записывается даже без `-save`. Этот флаг не подтверждает кандидата, не включает дополнительную проверку и не влияет на поиск. Он меняет только конечное представление найденного значения:

- без `-save` большинство хешей и других двоичных значений записываются как исходный hex;
- с `-save` значения Bitcoin, TON, Solana, Polkadot/Substrate, Filecoin, IOTA, XRP, Tezos и других поддерживаемых целей преобразуются в предусмотренные для них печатные адреса;
- типы целей, для которых отдельного адресного кодировщика нет, остаются в hex;
- ветки Cardano уже формируют свои адреса как часть стандартного результата и не зависят от `-save` так же, как обычный HASH160.

Режимы проверки паролей кошельков, `-walletscan`, `-walletjs`, `-xp`, а также поиск и восстановление Profanity используют отдельные функции вывода. В них `-save` нужен, чтобы добавить структурированную найденную строку в файл, выбранный через `-o`. Без `-save` результат показывается только в терминале, если вывод не скрыт через `-silent`. Для WalletJS, XP и Profanity флаг одновременно включает адресное представление тех целей, для которых оно поддерживается.

Когда выбранный режим пишет файл, новые строки добавляются в конец: старое содержимое не стирается. Снимки результатов обычных ключевых и деривационных режимов передаются отдельным очередям вывода; на каждом устройстве может ожидать до 64 задач. Специальные обработчики кошельков записывают уже проверенные результаты напрямую. В каждой строке остаются ее кандидат, путь и номера режима, но весь файл не сортируется. При нескольких устройствах готовые пакеты могут приходить в разном порядке, а строки могут получать префикс `GPU N:`.

`-full` используйте только с очень маленьким закрытым диапазоном.

### Устройства Metal и автоматическая сетка

`-device` принимает один номер, список или диапазон:

```bash
-device 0
-device 0,1,3
-device 0-3
```

Программа перечисляет устройства Metal и делит номера кандидатов без намеренных пересечений и пропусков. На обычном Mac с Apple Silicon чаще всего будет видно одно объединенное устройство.

По умолчанию сетка выбирается автоматически под устройство и конкретный режим. Ручные параметры нужны только для измерений:

| Параметр | По умолчанию | Где используется |
| --- | --- | --- |
| `-b N` | автоматически | число threadgroup в режимах, разрешающих ручную настройку |
| `-t N` | автоматически | число потоков в threadgroup |
| `-bit N` | 18 для priv/minikey, 10 для recovery, 16 для остальных | размер профиля предвычислений secp256k1 |
| `-keys N` | `1024` | работа priv seq/vanity; значение приводится к единицам по 1024 и не бывает меньше 1024 |
| `-chunk N` | `1` | число пакетов приватов на поток |
| `-em` | выключен | эндоморфизм secp256k1 в priv seq/random |
| `-legacy` | выключен | старая схема priv seq/random |

Настройки от другой видеокарты или другого режима могут дать меньшую скорость и больший расход памяти. Сначала всегда проверяйте автоматические значения.

## Справочник режимов

В описании каждого режима указано, что лежит во входной строке, какие преобразования выполняются, какие параметры особенно важны, что попадает в результат и как выглядит короткий безопасный пример.

### Мнемоники, seed и пути

#### `-mnemonic [ПОДРЕЖИМ]`

**Когда использовать:** для готовых мнемоник BIP-39 либо текста, который нужно предварительно преобразовать, а затем провести через mnemonic/seed/derivation. Если основной режим вообще не указан, запускается именно этот.

**Что находится в одной строке:** обычно одна мнемоника или текстовый кандидат. С `-hex` строка сначала декодируется в байты. Пути находятся в отдельном файле `-d`, а passphrase BIP-39 берутся из `-pass` или `-passbrute`.

**Какими способами можно задавать кандидаты:**

| Задача | Параметры | Что именно перебирается |
| --- | --- | --- |
| Проверить готовые фразы или текст | `-i FILE` либо стандартный ввод | По одной строке за раз |
| Идти по диапазону байтов по порядку | `-start HEX -end HEX [-step HEX]` | Исходные байты для выбранного подрежима mnemonic |
| Брать случайные точки внутри диапазона | `-start HEX -end HEX -random [-n N]` | Случайные значения между двумя границами |
| Использовать встроенный генератор | `-prng` или `-prng64` с `-gen/-mode/-s/-e` | Байты, полученные выбранным профилем PRNG |
| Ограничить допустимые hex-символы | `-hexset CHARS -start HEX [-end HEX]` | Значения фиксированной длины только из заданных символов |
| Восстановить неизвестные слова BIP-39 | отдельный режим `-recovery` | Слова из словаря вместо отдельных `*` |
| Проверить много passphrase для одной фразы | `-pass_thread` | Меняется passphrase BIP-39, сама мнемоника остается прежней |
| Проверить много путей для одной фразы | `-der_thread` | Меняется путь, сама мнемоника остается прежней |

В последовательном режиме увеличивается шестнадцатеричное значение исходных байтов. Программа не переходит напрямую от одного слова словаря к следующему. Полученные байты обрабатываются выбранным подрежимом так же, как входная строка. Если важна длина, не убирайте ведущие нули.

| Значение | Предварительное преобразование |
| --- | --- |
| не указано | обычная обработка мнемоники |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | каждый входной байт превращается в два строчных hex-символа ASCII; длина материала удваивается, но не превышает внутренний предел 512 байт |

`-iter LIST` задает число повторений преобразования. `-utf8` включает повторное хеширование через текстовое UTF-8/hex-представление, а `-text` оставляет совместимый промежуточный результат текстом. `-electrum [seg]`, `-128` и `-ton`/`-TON` включают соответствующие варианты мнемоники. `-ton` и `-TON` — одинаковые псевдонимы. `-round N` дополнительно проверяет приваты вокруг каждого полученного значения в обе стороны.

Пример последовательного перебора:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic 1 \
  -start 00000000 -end 0000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Здесь по порядку проверяется четырехбайтовый диапазон, затем применяется подрежим `1` (SHA-256), а полученные кандидаты проходят обычные этапы BIP-39 и деривации. Полный список параметров всегда можно посмотреть командой `./METAL_CRYPTO_TOOLKIT -mnemonic -help`.

**Найденная запись:** исходная строка, при необходимости `bip39_pass(...)`, точный путь, приват или скаляр, тип цели и найденное значение/адрес.

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -i mnemonics.txt -d derivations.txt \
  -d-type bip32 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

Команда читает по одной фразе из `mnemonics.txt`, проходит все пути из `derivations.txt` через BIP32/secp256k1 и проверяет только HASH160 сжатого ключа Bitcoin.

##### `-mnemonic -scramble`

Этот подрежим нужен, когда все слова BIP-39 известны, но полностью или частично
неизвестен их порядок. Исходную фразу из 12/15/18/21/24 слов можно написать
после `-scramble` либо читать по одной строке из повторяемых `-i FILE`.
Повторяющиеся слова образуют мультимножество и не создают одинаковых
перестановок.

Metal напрямую преобразует проверенный U256 ordinal в уникальную перестановку,
сначала проверяет checksum BIP-39 и только после этого передает подходящие
фразы в существующий pipeline seed, derivation и точной проверки целей. Список
перестановок в памяти не строится. Единственным потоком статистики остается
`SpeedThreadFunc`, который показывает завершенные `Candidate/s`.

В `-pattern` на каждую выходную позицию приходится ровно один токен:

- `*` разрешает любое оставшееся слово исходной фразы;
- обычное слово фиксирует его на этой позиции;
- `{word|word}` ограничивает позицию перечисленными словами.

`-pattern-file FILE` читает один шаблон без комментариев. `-start N` и
исключающая граница `-end N` задают U256-интервал ordinal; без них проходится
весь домен уникальных перестановок. `-n N` управляет завершенным GPU-окном.
`-wallet-mem auto|all|NN%|SIZE` принимает размеры MiB/GiB и ограничивает
unified memory Metal. Диапазоны нескольких GPU не пересекаются. При
переполнении checksum-hit буфера незачтенное окно делится пополам и полностью
повторяется.

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -scramble \
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  -pattern "* * * * * * * * * * * *" \
  -d derivations.txt -c c -hash 00112233445566778899aabbccddeeff00112233
```

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -scramble -i phrases.txt \
  -pattern-file positions.txt -start 0 -end 0x100000 \
  -wallet-mem all -device 0 -d derivations.txt -c p \
  -hash 00112233445566778899aabbccddeeff00112233
```

U256 позволяет корректно представить огромный домен, но не делает такой поиск
практичным. Фиксированные позиции действительно уменьшают домен перестановок;
ограничения в фигурных скобках сейчас фильтруют точный домен мультимножества на
GPU.

#### `-recovery`

**Когда использовать:** если в мнемонике BIP-39 неизвестно одно или несколько целых слов.

Шаблон можно написать прямо после `-recovery` либо передать через повторяемую конструкцию `-recovery -i FILE`. Один отдельный `*` означает одно неизвестное слово. `-wordlist FILE` задает свой словарь из ровно 2048 уникальных непустых слов без пробелов; иначе используется словарь из `-lang`.

Коды языка:

| Код | Язык |
| --- | --- |
| `EN` | английский, по умолчанию |
| `SA` | испанский |
| `JA` | японский |
| `IT` | итальянский |
| `FR` | французский |
| `CZ` | чешский |
| `PT` | португальский |
| `KO` | корейский |
| `CS` | китайский упрощенный |
| `CT` | китайский традиционный |

Неизвестный код сейчас молча переключается на английский. Поэтому после запуска обязательно смотрите, какой словарь загрузился.

```bash
./METAL_CRYPTO_TOOLKIT -recovery \
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon *' \
  -lang EN -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

Последняя позиция заменяется английскими словами BIP-39, готовая фраза проверяется, затем выполняются пути из файла.

Для предсказуемого поиска сразу задавайте правильное число слов и отмечайте каждое неизвестное место знаком `*`. Текущий разборщик умеет дополнять слишком короткую фразу звездочками до количества, которое не меньше трех и делится на три, а неизвестное написанное слово может заменить ближайшим словом из словаря. В серьезном восстановлении на такое автоматическое исправление лучше не рассчитывать.

Здесь `*` означает целое слово. Не путайте этот режим с `-priv -recovery`, где одна звездочка — всего одна hex-позиция.

#### `-poetry`

**Когда использовать:** если нужно проверить или восстановить фразу Poetry brainwallet, в которой известны все слова либо пропущено одно или несколько целых слов. Poetry — отдельный формат фразы, а не BIP-39: здесь нет checksum BIP-39, дополнительной passphrase PBKDF2, mnemonic seed и путей деривации.

**Как передать шаблоны:**

| Источник | Вид команды | Что происходит |
| --- | --- | --- |
| Прямо в команде | `-poetry "ШАБЛОН"` | Добавляет один шаблон. Для нескольких конечных заданий повторите `-poetry "..."`. |
| Файл | `-poetry -i FILE` | Читает по одному шаблону из каждой непустой строки. Параметр можно повторить для нескольких файлов. |
| Стандартный ввод | `-poetry` | Читает по одному непустому шаблону из каждой строки stdin. Выбрать stdin можно только один раз. |

В шаблоне должно быть ровно `3`, `6`, `9`, `12`, `15`, `18`, `21` или `24` слова, разделенных пробелами. Каждое неизвестное слово обозначается отдельным знаком `*`. Программа не добавляет звездочки сама: в `just just *` неизвестна одна позиция, а в `* * *` — все три.

Режим использует встроенный словарь Poetry из 1626 слов. Известные слова переводятся в нижний регистр. Если написанного слова нет в словаре, программа выбирает ближайшее по написанию и показывает строку `Recovery replace`. Перед долгим запуском обязательно проверьте такие сообщения: автоматическая замена меняет фиксированную часть проверяемой фразы.

**Как из фразы получается ключ:** у каждого слова есть номер в словаре. Каждая последовательная группа из трех номеров по правилам Poetry превращается в четыре байта. Поэтому 3 слова дают 4 значащих байта, 6 слов — 8 байтов, а 24 слова — все 32 байта. Короткое значение дополняется нулевыми байтами слева до одного 32-байтового ключа. Этот ключ проверяется напрямую, без промежуточного seed мнемоники и без дочерних ключей.

Из полученного ключа строятся семейства целей, выбранные через `-c`. Прямые префиксы `-hash`/`-target`, Bloom- и XOR-фильтры работают так, как описано выше в разделе целей. Для обычного приватного ключа secp256k1 используются ветки `c`, `u`, `s`, `p`, `r`, `e` и `x`; цели ed25519/sr25519 и отдельных сетей применяют соответствующую обработку ключа, реализованную в этой ветке.

**Конечный и случайный перебор:**

| Вариант | Что происходит |
| --- | --- |
| Конечный, по умолчанию | Полностью перебирает все `1626^N` сочетаний для `N` звездочек. Быстрее всего меняется крайняя правая `*`. Шаблон без звездочек проверяется один раз. Перед запуском задания печатается точное число сочетаний. Несколько шаблонов выполняются по очереди, а выбранные Metal-устройства делят пространство одного задания без намеренного пересечения номеров кандидатов. |
| `-random` | Бесконечно подставляет случайные слова словаря только вместо звездочек. Без `-n` допускается ровно один шаблон, и в нем должна быть хотя бы одна `*`. Фиксированные слова не меняются; естественной точки завершения у такого запуска нет. |
| `-random -n N` | Принимает один или несколько шаблонов. Для каждого шаблона программа создает ровно `N` случайных сочетаний звездочек суммарно на всех выбранных Metal-устройствах, затем переходит к следующему шаблону. После последнего шаблона начинается новый пронумерованный цикл с первого. В каждом шаблоне должна быть хотя бы одна `*`. |

`-round N` дополнительно проверяет ключи в обе стороны от каждого декодированного значения, а `-em` включает эндоморфизм secp256k1. Для проверок ed25519 флаг `-scalar` считает декодированные байты скаляром, `-LE` вместе с `-scalar` задает little-endian, а `-shash` считает декодированные байты уже полученным хеш-материалом ed25519 до clamp.

У Poetry собственный источник кандидатов. Не сочетайте его с другим основным режимом; общими параметрами файлов и каталогов `-f`, `-all` и `-delete`; диапазонами и направлением `-start`, `-end`, `-step`, `-back` и `-both`; параметрами `-hex`, `-hexset`, `-size`, `-sizes`, `-recovery`, `-wordlist`, `-prng`, `-prng64`, `-comb`, `-mutation`, passphrase BIP-39, `-d`, `-d-type`, `-d-dot`, `-pass_thread` и `-der_thread`. Для файла пишите именно `-poetry -i FILE`, а не отдельный общий `-i FILE`.

**Найденная запись:** готовая фраза добавляется перед обычным результатом ключевого режима. Строка имеет вид:

```text
phrase:private:currency:payload
```

Без `-save` поле `payload` обычно остается найденным hash или значением фиксированной длины в hex. С `-save` поддерживаемые цели записываются как обычные печатные адреса. Совпадения дописываются в `-o FILE` (по умолчанию `result.txt`), поэтому связь всегда остается явной: `phrase:<result>`, и по каждой строке можно восстановить точную найденную фразу.

Конечный шаблон прямо в команде:

```bash
./METAL_CRYPTO_TOOLKIT -poetry "just just *" -c c \
  -hash 00112233445566778899aabbccddeeff00112233 \
  -save -o poetry-found.txt
```

Шаблоны из файла и stdin:

```bash
./METAL_CRYPTO_TOOLKIT -poetry -i poetry-templates.txt \
  -device 0 -c cus -xc btc-targets.xor_c -o poetry-found.txt

./METAL_CRYPTO_TOOLKIT -poetry < poetry-templates.txt
```

Бесконечный случайный перебор:

```bash
./METAL_CRYPTO_TOOLKIT -poetry "* * *" -random \
  -c e -xc ethereum-targets.xor_c -o poetry-found.txt
```

Циклические случайные пакеты для нескольких шаблонов:

```bash
./METAL_CRYPTO_TOOLKIT \
  -poetry "just * * * * *" \
  -poetry "love * * * * *" \
  -random -n 1000000000 \
  -c e -xc ethereum-targets.xor_c -o poetry-found.txt
```

В этом примере каждый шаблон получает ровно один миллиард кандидатов за цикл. Если выбрано несколько устройств, этот миллиард делится между ними, а не повторяется целиком на каждом устройстве.

#### `-der_thread`

**Когда использовать:** есть один исходный материал и очень большой список путей. Режим работает вместе с mnemonic, entropy, seed, HMAC и BIP32.

На одном раунде источник остается неизменным, а строки из `-d`, типы `-d-type` и SURI из `-d-dot` распределяются по потокам видеокарты и выбранным устройствам. При нужных целях обрабатываются Cardano BIP32-ed25519 и пути DOT/SURI.

```bash
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' | \
  ./METAL_CRYPTO_TOOLKIT -mnemonic -der_thread -d many_paths.txt \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

Не сочетайте `-der_thread` с `-pass_thread`, recovery, `-hexset` и несовместимыми seq/random-источниками.

#### `-pass_thread`

**Когда использовать:** известна одна мнемоника или энтропия, но неизвестна passphrase BIP-39 и нужно проверить большой список.

Источник приходит из стандартного ввода или файла. Кандидаты passphrase берутся из `-pass FILE` или `-passbrute START:END`. В найденной записи остаются и исходная фраза/энтропия, и подошедшая passphrase.

```bash
printf '%s\n' 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' | \
  ./METAL_CRYPTO_TOOLKIT -mnemonic -pass_thread -pass passphrases.txt \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

Алгоритм BIP-39 не меняется; меняется только порядок распределения работы. Режим нельзя смешивать с `-der_thread`, PRNG, seq/random, hexset и recovery.

#### `-entropy [ПОДРЕЖИМ]`

**Когда использовать:** исходно известны байты энтропии, из которых нужно построить мнемонику, seed и дочерние ключи.

С `-hex` одна строка — это энтропия в hex. `-size N` задает одну конечную длину в байтах, `-sizes LIST` — несколько длин. По умолчанию используются 16 байт и 12 слов. `-w N` округляет число слов до кратного трем и выбирает связанную длину энтропии.

| Значение | Преобразование |
| --- | --- |
| не указано | обычный entropy-маршрут |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | каждый входной байт превращается в два строчных hex-символа ASCII; длина материала удваивается, но не превышает внутренний предел 512 байт |

**Как можно получать энтропию:**

| Задача | Параметры | Что происходит |
| --- | --- | --- |
| Читать известные значения | `-i FILE -hex` либо hex-строки из стандартного ввода | Одна энтропия в каждой строке |
| Перебирать энтропию по порядку | `-start HEX -end HEX [-step HEX]` | К текущему значению прибавляется `-step`, пока не достигнут `-end` |
| Проверять случайные точки диапазона | `-start HEX -end HEX -random [-n N]` | Вместо полного прохода выбираются окна внутри заданных границ |
| Использовать профили генераторов | `-prng`/`-prng64` и их параметры | Энтропия строится выбранным обычным или историческим генератором |
| Ограничить каждый hex-символ | `-hexset CHARS -start HEX [-end HEX]` | Используются только символы из указанного набора |
| Восстановить неизвестные позиции | `-recovery ... -hexset CHARS` внутри режима | Каждый `*` заменяется символами из `-hexset` |
| Распределить passphrase или пути | `-pass_thread` либо `-der_thread` | Одна энтропия остается неизменной, а по потокам распределяется другое измерение |

Для последовательного перебора BIP-39 задавайте обе границы с нужной длиной. Например, 32 hex-символа — это 16 байт энтропии и обычная мнемоника из 12 слов. Ведущие нули входят в эту длину, поэтому убирать их нельзя.

```bash
printf '%s\n' 000102030405060708090a0b0c0d0e0f | \
  ./METAL_CRYPTO_TOOLKIT -entropy -hex -size 16 -lang EN \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

В примере ровно 16 переданных байтов превращаются в английскую мнемонику/seed, после чего проверяются пути из файла.

Пример перебора энтропии по порядку:

```bash
./METAL_CRYPTO_TOOLKIT -entropy \
  -start 00000000000000000000000000000000 \
  -end   0000000000000000000000000000ffff -step 1 \
  -size 16 -lang EN -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Команда последовательно проверяет все 65 536 значений показанного 128-битного диапазона. Каждое значение проходит тот же путь entropy -> mnemonic -> seed -> derivation -> target, что и строка из файла. Полная справка: `./METAL_CRYPTO_TOOLKIT -entropy -help`.

#### `-bip32 [ПОДРЕЖИМ]`

**Когда использовать:** для входной passphrase/данных до получения master-материала BIP32. Это не режим готового 64-байтового HMAC.

По умолчанию используется HMAC-SHA256 в стиле bip32.org и 50000 повторений в базовой цепочке. Дополнительные преобразования: `1=SHA-256`, `2=SHA-512`, `3=Keccak-256`, `4=SHA3-256`, `5=MD5`, `6=без преобразования`. `-iter LIST` задает число повторений выбранного преобразования.

Кандидаты можно читать из `-i` или стандартного ввода, перебирать как hex-байты через `-start/-end/-step`, случайно выбирать внутри ограниченного диапазона, создавать через `-prng`/`-prng64` или ограничивать с помощью `-hexset`. `-der_thread` нужен для обратной задачи: один неизменный BIP32 payload и очень много путей.

```bash
./METAL_CRYPTO_TOOLKIT -bip32 2 -iter 1 -i bip32_inputs.txt -hex \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

В результат входят исходные данные, число повторений, путь, приват, тип цели и совпавшее значение.

Пример последовательного диапазона:

```bash
./METAL_CRYPTO_TOOLKIT -bip32 6 \
  -start 00000000 -end 0000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Здесь увеличиваются четырехбайтовые исходные данные до master-этапа, а не готовый chain code. Подрежим `6` передает эти байты в BIP32 без дополнительного преобразования из списка. Полная справка: `./METAL_CRYPTO_TOOLKIT -bip32 -help`.

#### `-seed`

**Когда использовать:** seed уже получен и повторно выполнять mnemonic/PBKDF2 не нужно.

С `-hex` каждая строка декодируется в байты, без него используется текстовый/сырой маршрут. Эффективное представление seed ограничено 64 байтами. Пути задаются через `-d` и `-d-type`; для очень большого списка можно добавить `-der_thread`.

Seed можно читать из файла или стандартного ввода, перебирать по диапазону `-start/-end`, случайно выбирать внутри границ, создавать профилем PRNG либо перебирать через `-hexset`. В последовательном режиме длина `-start` задает значимую длину seed, максимум 64 байта. Для формата фиксированной длины обязательно сохраняйте ведущие нули.

```bash
printf '%s\n' 000102030405060708090a0b0c0d0e0f | \
  ./METAL_CRYPTO_TOOLKIT -seed -hex -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Найденная запись помечает источник как `seed:` и содержит точный путь.

Пример последовательного seed:

```bash
./METAL_CRYPTO_TOOLKIT -seed \
  -start 00000000000000000000000000000000 \
  -end   0000000000000000000000000000ffff -step 1 \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Команда по порядку перебирает 16-байтовые seed. PBKDF2 BIP-39 здесь не выполняется: каждый кандидат уже считается готовым seed. Полная справка: `./METAL_CRYPTO_TOOLKIT -seed -help`.

#### `-hmac`

**Когда использовать:** уже имеются готовые 64 байта master-материала BIP32 `I_L || I_R`: 32 байта master private/scalar и 32 байта chain code.

При чтении из файла или стандартного ввода режим создает 64-байтовый master-буфер, заранее заполненный нулями. С `-hex` в него декодируются не более первых 128 hex-символов; без `-hex` копируются не более первых 64 входных байтов. Поэтому короткое значение дополняется нулевыми байтами справа. Если требуется точный `I_L || I_R`, используйте ровно 128 допустимых hex-символов. Mnemonic PBKDF2 здесь повторно не выполняется.

Готовые master-значения можно читать из файла или стандартного ввода, перебирать в 64-байтовом диапазоне `-start/-end`, случайно выбирать внутри него, получать из профиля PRNG либо создавать через `-hexset`. Это специальный режим: последовательный счетчик изменяет все значение `I_L || I_R`, включая половину chain code.

```bash
printf '%0128d\n' 0 | ./METAL_CRYPTO_TOOLKIT -hmac -hex \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Нули приведены только для демонстрации длины. Некорректное master-значение будет отклонено активной деривацией.

Пример последовательного HMAC:

```bash
./METAL_CRYPTO_TOOLKIT -hmac \
  -start 00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000 \
  -end   0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000ffff \
  -d derivations.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

Обе границы содержат по 128 hex-символов, то есть 64 байта master-материала. Полная справка: `./METAL_CRYPTO_TOOLKIT -hmac -help`.

### Приваты и старые генераторы

#### `-priv [ПОДРЕЖИМ]`

**Когда использовать:** для обычных приватов, ограниченного диапазона скаляров или одной из явно заданных схем изменения ключа.

С `-hex` вход из файла или stdin разбирается блоками по 64 символа: короткий последний блок дополняется нулями слева, из первых 128 символов может получиться не более двух ключей, а последующие символы игнорируются. Без `-hex` используются такие же блоки по 32 сырых байта с дополнением нулевыми байтами слева. Для предсказуемой схемы «одна строка — один ключ» используйте ровно 64 допустимых hex-символа либо ровно 32 сырых байта. Файл путей не нужен.

**Основные варианты работы `-priv`:**

| Вариант | Параметры | Что происходит |
| --- | --- | --- |
| Приваты из файла | `-priv -hex -i keys.txt` | Рекомендуется ровно один 64-символьный hex-ключ в строке; короткие и длинные строки нормализуются по правилу выше |
| Приваты из внешнего потока | `producer \| ./METAL_CRYPTO_TOOLKIT -priv -hex ...` | Строки того же формата читаются из стандартного ввода |
| **Priv Seq: диапазон по порядку** | `-priv -start HEX -end HEX [-step HEX]` | Приваты последовательно проверяются от первой до последней границы |
| Обратный проход или два направления | добавить `-back` или `-both` | Идти вниз от старта либо одновременно в положительную и отрицательную стороны |
| Случайные точки диапазона | добавить `-random [-n N]` | Выбирать окна внутри заданного диапазона приватов |
| Встроенные генераторы | `-prng`/`-prng64` и их параметры | Получать байты привата из выбранного профиля генератора |
| Ограниченный набор hex-символов | `-hexset CHARS -start HEX [-end HEX]` | Перебирать только приваты, составленные из указанного набора |
| Частично известный приват | `-priv -recovery -i templates.txt` либо stdin | Подставлять в каждую позицию `*` полный набор `0..f` |
| Изменения готовых приватов | `-priv 0` ... `-priv 6` | Применять одну явно выбранную схему из таблицы ниже |

**Быстрый путь Priv Seq.**

Если в последовательном диапазоне `-start/-end` выбраны только secp256k1-цели `c`, `u`, `s`, `p`, `r`, `e` и `x`, программа автоматически включает специальные Vanity-walk кернелы. Сначала вычисляется начальная точка кривой, после чего соседние приваты обрабатываются последовательным сложением точек. Полное умножение точки на скаляр не выполняется заново для каждого следующего ключа.

Этот путь особенно важен для сжатых и несжатых Bitcoin HASH160, P2WPKH, P2WSH, Taproot, Ethereum и координаты X открытого ключа. На подходящем Apple Silicon простой запуск с одним типом цели может проверять больше миллиарда ключей в секунду. Это не фиксированная гарантия: набор целей, размер и тип фильтров, дополнительные проверки, шаг диапазона и выбранное устройство напрямую влияют на скорость.

Быстрый путь выбирается автоматически. Начинайте с автоматической сетки и стандартных значений `-keys 1024`, `-chunk 1`; обычно эти параметры вообще не нужно добавлять в команду. Если выбраны ed25519, sr25519 или другие сетевые ветки, программа сама переключается на общий кернел.

| Подрежим | Что происходит |
| --- | --- |
| не указан | базовая обработка приватов |
| `0` | сочетания циклического сдвига 256-битного значения влево |
| `1` | перебор `00..FF` в выбранных байтах |
| `2` | сочетания случайного изменения байтов |
| `3` | 16 вариантов SHA-256 и 16 вариантов Keccak на ключ |
| `4` | прибавление единицы по шаблону следующих байтов |
| `5` | прибавление единицы по всем байтам |
| `6` | повтор первых N hex-символов на длину всего привата |

В подрежиме 1 `-pb 1,2,3-10` выбирает номера байтов; по умолчанию используются 1–32. В подрежиме 6 `-pb` задает длины повторяемого шаблона, а `-last` дополнительно перебирает последнюю hex-позицию от `0` до `f`.

`-scalar` считает вход скаляром ed25519, `-LE` задает для него little-endian. `-shash` считает вход хешем seed перед clamping. Эти параметры относятся к ed25519-целям и не нужны для обычного secp256k1.

```bash
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end 100000 -c c \
  -hash 00112233445566778899aabbccddeeff00112233 \
  -save -o priv_found.txt
```

Это Priv Seq: программа последовательно проверяет все приваты от `0x01` до `0x100000` и автоматически выбирает быстрый кернел для сжатого Bitcoin HASH160. Для готового списка используйте `./METAL_CRYPTO_TOOLKIT -priv -hex -i keys.txt ...`. Полная справка: `./METAL_CRYPTO_TOOLKIT -priv -help`.

#### `-priv -recovery`

**Когда использовать:** известна часть 64-символьного привата, а некоторые hex-позиции потеряны.

Шаблоны читаются по одному из `-i FILE` либо из stdin; после `-recovery` нельзя писать шаблон прямо в командной строке. Каждая строка должна содержать ровно 64 позиции и не более 32 звездочек. Каждая `*` всегда перебирает полный набор `0..f`; `-hexset` в этом маршруте не поддерживается.

```bash
printf '%s\n' \
  '00000000000000000000000000000000000000000000000000000000000000**' | \
  ./METAL_CRYPTO_TOOLKIT -priv -recovery -c c \
    -hash 00112233445566778899aabbccddeeff00112233 -save
```

Seq/random, PRNG, числовые подрежимы priv, `-pb`, `-last`, `-size`, `-sizes` и `-dub` здесь не применяются.

#### `-kangaroo`

**Когда использовать:** когда известен полный публичный ключ secp256k1
`Q = kG`, а соответствующий приватный скаляр `k` гарантированно находится
внутри ограниченного интервала.

Это нативная Metal-реализация collision-поиска RCKangaroo, а не линейный
перебор приватов. Объём работы растёт приблизительно как квадратный корень из
ширины интервала, поэтому ширина диапазона намного важнее количества
hex-символов в его границах.

Каждая цель должна быть полным сжатым публичным ключом длиной 33 байта либо
несжатым ключом длиной 65 байтов. `-target` можно повторять; вместо ключа
можно указать текстовый файл с одним ключом на строку. Пустые строки и
`#`-комментарии игнорируются, после первого токена допустима подпись.
Дубликаты одной точки вычисляются один раз. Адрес, HASH160, Ethereum address,
x-only public key, Bloom-фильтр или XOR-фильтр недостаточны: алгоритму нужна
полная точка кривой. Проверенные результаты записываются через `-o`; обычные
параметры семейств целей `-c`, `-save` и `-i` к этому режиму не относятся.

Одна уникальная цель использует отдельно настроенный однотаргетный контур.
При двух и более уникальных целях автоматически включается настоящий
мультитаргетный контур: у всех целей общее tame-стадо и отдельные
индексированные положительные и отрицательные wild-стада. Поэтому tame-треть
не строится и не проходит заново для каждой цели. Цели обрабатываются
ограниченными резидентными окнами: tame DP сохраняются между окнами, а wild DP
удаляются. Поэтому GPU-аллокация не растёт вместе с полным числом целей.

`-kangaroo-mem` задаёт верхнюю границу рабочего набора. `auto` использует не
более 25% свободного recommended Metal working set. `all` разрешает весь
остаток, кроме резерва 512 MiB под runtime; фиксированного потолка 16 GiB
больше нет. Также можно указать процент или точный размер в MiB/GiB. Это
лимит, а не приказ бессмысленно занять всю память: настроенный однотаргетный
контур и маленькое окно сохраняют только полезное число walkers. На Apple
Silicon CPU и GPU используют общую физическую память, а для нескольких
устройств бюджет делится между репликами.

Для огромного арифметического семейства целей используйте компактный источник
`-kangaroo-shifts START:COUNT[:STEP]`, а не файл с миллионами публичных
ключей. Он задаёт `Q_i = Q - (START + i*STEP)G`, не материализуя все точки.
`START` и `STEP` — hex-скаляры, `COUNT` — decimal, `0xHEX` либо `2^EXP`.
Перекрывающиеся сдвинутые интервалы точно схлопываются в их объединение.
Разреженные интервалы генерируются последовательно и проходят через те же
ограниченные окна. После совпадения производный приват преобразуется обратно
в базовый, затем обе публичные точки обязательно проверяются.

**Форматы диапазона:**

| Форма | Какой интервал проверяется |
| --- | --- |
| `-range 64` | `[2^63, 2^64)` |
| `-range 65-72` | по очереди все полные битовые интервалы от 65 до 72 бит |
| `-range 64,67,70-72` | перечисленные полные битовые интервалы по порядку |
| `-range START:END` | один точный hex-интервал `[START, END)` |

`START` включается, `END` не включается. Точный интервал `START:END` нельзя
объединять с другим `-range`. Допустимая область:
`0 <= START < END <=`
`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`,
то есть до порядка группы secp256k1. Битовый 256-битный диапазон начинается
с `2^255` и заканчивается на порядке группы.

**Основные параметры:**

| Параметр | Значение |
| --- | --- |
| `-target HEX\|FILE` / `-hash HEX` | повторяемый полный публичный ключ либо файл целей; две и более уникальные точки включают мультитаргетный контур |
| `-range VALUE` | один или несколько битовых диапазонов либо один точный hex-интервал |
| `-kangaroo-shifts START:COUNT[:STEP]` | компактное семейство `Q-(START+i*STEP)G` без развёрнутого файла целей |
| `-kangaroo-mem auto\|all\|NN%\|SIZE` | бюджет walkers и резидентного окна; число без суффикса означает MiB, поддерживаются `MiB` и `GiB` |
| `-device LIST` | устройства Metal: `0`, `0,1,3` или `0-3`; без параметра используются все доступные |
| `-dpbits N` | число бит distinguished point, `14..60`; без параметра выбирается автоматически |
| `-lim N` | максимальный коэффициент работы; без параметра выбирается автоматически |
| `-jumps N` | размер таблицы прыжков — степень двойки от 8 до 512; по умолчанию `512` |
| `-kangsteps N` | шагов за один запуск Metal, `256..8192`; по умолчанию `1000` |
| `-exp LIST` | явная цепочка степеней, например `255,192,128` |
| `-first N -last N [-prob P]` | многократно создавать случайную убывающую цепочку; `P` по умолчанию `0.5` |
| `-kangaroo-dp-dir DIR` | папка кеша tame distinguished points |
| `-kangaroo-dp-rebuild` | не использовать старые tame points и перестроить выбранный кеш |
| `-no-kangaroo-dp-cache` | отключить чтение и сохранение tame-кеша |
| `-o FILE` | дописывать проверенные результаты; по умолчанию `result.txt` |
| `-log` | дописывать сведения о диапазонах в `_local_artifacts/kangaroo.log` |

Начинайте с автоматических `-dpbits` и `-lim`, стандартной таблицы прыжков и
автоматической Metal-сетки. Если программа сообщает переполнение DP output,
увеличьте `-dpbits`: distinguished points будут встречаться реже. Увеличение
`-kangsteps` уменьшает число синхронизаций с CPU, но удлиняет каждый запуск
кернела. Слишком маленький `-lim` может остановить корректный диапазон до
нахождения collision.

**Пример 1 — известный скаляр в точном интервале.**

Публичный ключ ниже соответствует скаляру `0x2a`. Команда проверяет интервал
`[0x1, 0x100)`, где правая граница не включается:

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af \
  -range 1:100 \
  -no-kangaroo-dp-cache \
  -o kangaroo-known-key.txt
```

Последнее поле `priv:` должно содержать:

```text
000000000000000000000000000000000000000000000000000000000000002a
```

**Пример 2 — полный 64-битный интервал на одном GPU.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_33_OR_65_BYTE_PUBLIC_KEY_HEX \
  -range 64 \
  -device 0 \
  -o kangaroo-64.txt
```

Команда проверяет `[0x8000000000000000, 0x10000000000000000)`. Вместо
placeholder требуется полный публичный ключ, а не полученный из него адрес.

**Пример 3 — несколько битовых интервалов и два Metal-устройства.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 65-68 \
  -device 0,1 \
  -kangaroo-dp-dir ./kangaroo-cache \
  -o kangaroo-multigpu.txt
```

Первый запуск создаёт пригодные для повторного использования tame-кеши.
Следующий запуск с тем же диапазоном, DP-параметрами и числом прыжков может их
переиспользовать. После намеренной замены или изменения кеша используйте
`-kangaroo-dp-rebuild`.

**Пример 4 — явное разложение в стиле RCKangaroo.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 64 \
  -exp 255,192,128 \
  -device 0 \
  -o kangaroo-exp.txt
```

Режим вычитает из публичной точки сумму выбранных степеней двойки, решает
ограниченный остаток, затем точно проверяет восстановленный полный приват.
Используйте `-exp` только для намеренного разложения. Вариант
`-first 255 -last 128 -prob 0.5` вместо этого создаёт случайные убывающие
цепочки до нахождения решения; `-exp` нельзя объединять с `-first/-last`.

**Пример 5 — мультитаргетный поиск с общим tame-стадом.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02FIRST_COMPLETE_PUBLIC_KEY \
  -target 03SECOND_COMPLETE_PUBLIC_KEY \
  -target ./kangaroo-targets.txt \
  -range 64 \
  -device 0 \
  -o kangaroo-multi.txt
```

Файл может содержать дополнительные цели и подписи после каждого ключа. Все
уникальные точки используют общие диапазоны и tame DP cache. Строка
статистики явно показывает `multi-target shared-tame`, логическое и
резидентное число целей, walkers, реально выделенный объём, выбранный лимит и
свободный working set. Ограниченные окна не дают всему списку превратиться в
одну неограниченную Metal-аллокацию.

**Пример 6 — разрешить Kangaroo использовать оставшийся Metal working set.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target ./kangaroo-targets.txt \
  -range 135 \
  -kangaroo-mem all \
  -device 0 \
  -o kangaroo-large-target-set.txt
```

Точный лимит можно задать как `-kangaroo-mem 50%`,
`-kangaroo-mem 32GiB` либо числом MiB, например
`-kangaroo-mem 32768`. Невозможный точный запрос завершается понятной
ошибкой, а не молча уменьшает аллокацию.

**Пример 7 — 100 миллионов сдвинутых целей puzzle 135 без разворачивания.**

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo \
  -target 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 \
  -kangaroo-shifts 0:100000000:1 \
  -range 135 \
  -kangaroo-mem all \
  -device 0 \
  -o puzzle135-shifted.txt
```

При плотном семействе с `STEP=1` соседние интервалы перекрываются, поэтому
движок ищет их точное объединение по исходному публичному ключу. Память целей
остаётся постоянной, но бесплатного криптографического покрытия это не даёт:
объединённый диапазон лишь немного шире исходного. Разреженные сдвиги могут не
перекрываться, однако каждый интервал тогда добавляет реальную поисковую
работу.

Результат содержит `Pub`, `Exps`, `Pub after subtract`, `k_low` и `priv`.
При sparse compact-source совпадении дополнительно выводятся `Logical target`,
`Shift`, `Base pub` и проверенный `Base priv`: `priv` относится к производной
цели, а `Base priv` — восстановленный исходный скаляр. Кеши PSWDP2 и PSWDP3
сохраняют совместимость с CUDA/RCKangaroo для дистанций до 170 бит. Более
широкие дистанции используют Metal-расширение PSWDP4 и знаковое 256-битное
состояние GPU. Поэтому реальные 256-битные границы представимы, но полный
интервал шириной 256 бит остаётся практически неразрешимым на современном
железе.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -kangaroo -help
```

#### `-bsgs`

**Когда использовать:** для детерминированного восстановления одного или
нескольких приватных скаляров secp256k1, когда известны полные публичные ключи
и ограниченный интервал каждого скаляра.

BSGS строит переиспользуемую таблицу baby steps, после чего проверяет giant
steps сразу для всех ещё не найденных целей. В отличие от Kangaroo, здесь
можно намеренно занять большой объём памяти и сократить время поиска. BSGS
обычно выгоднее на достаточно узком интервале, при нескольких целях с общими
диапазонами либо при повторном использовании кеша. Kangaroo лучше подходит
для одного более широкого диапазона или при жёстком ограничении памяти.

Параметр `-target` можно повторять. Его значением может быть сжатый ключ
длиной 33 байта, несжатый ключ длиной 65 байтов или путь к файлу. В файле
читается первый токен каждой строки; пустые строки и строки с `#` пропускаются.
Compressed и uncompressed формы одной точки вычисляются один раз, но в
результате сохраняются все исходные номера и источники.

Для очень больших арифметических семейств целей предусмотрен параметр
`-bsgs-shifts START:COUNT[:STEP]`. Для каждой базовой точки `Q` он ищет
логические цели `Q - (START + i × STEP)G`, где `0 <= i < COUNT`. `START` и
`STEP` задаются hex-скалярами, а 64-битный `COUNT` — в decimal, `0xHEX` либо
`2^EXP`. Последнее смещение должно оставаться ниже порядка secp256k1. В памяти
хранятся только базовые точки и ограниченное рабочее окно: даже сотни миллионов
логических целей не разворачиваются в объекты публичных ключей и отдельные
Metal-буферы. При совпадении выводятся приват производной цели, её смещение и
отдельно проверенный приват базовой точки.

Грамматика `-range` и исключённая правая граница полностью совпадают с
Kangaroo:

| Форма | Какой интервал проверяется |
| --- | --- |
| `-range 48` | `[2^47, 2^48)` |
| `-range 48-52` | все полные битовые интервалы от 48 до 52 |
| `-range 40,48-52` | перечисленные битовые интервалы по порядку |
| `-range START:END` | один точный hex-интервал `[START, END)` |

Точный интервал нельзя объединять с другим `-range`. Уже найденные цели
исключаются перед переходом к следующему диапазону.

**Память, таблица и кеш:**

| Параметр | Значение |
| --- | --- |
| `-bsgs-mem auto` | не более 50% свободного recommended Metal working set |
| `-bsgs-mem all` | весь остаток recommended working set, кроме резерва 512 MiB |
| `-bsgs-mem NN%` | процент текущего свободного recommended working set |
| `-bsgs-mem SIZE` | жёсткий бюджет; число без суффикса означает MiB, доступны `MiB` и `GiB` |
| `-bsgs-shifts START:COUNT[:STEP]` | компактные цели `Q-(START+i×STEP)G` |
| `-bsgs-table N` | точное число baby steps: decimal, `0xHEX` либо `2^EXP` |
| `-bsgs-table-cache` | включить кеш `_local_artifacts/bsgs_tables` |
| `-bsgs-table-dir DIR` | включить кеш в папке `DIR` |
| `-bsgs-table-rebuild` | перестроить включённый кеш |
| `-random` | посетить каждую giant-группу один раз в псевдослучайном порядке |
| `-bsgs-random-seed N` | воспроизводимый 64-битный decimal/hex seed; также включает `-random` |
| `-device LIST` | одно или несколько Metal-устройств, например `0` или `0,1` |
| `-o FILE` | дописать полностью проверенные результаты; по умолчанию `result.txt` |

Автовыбор размера таблицы учитывает стоимость построения и суммарную
оставшуюся работу `цель × диапазон` с учётом измеренного соотношения скоростей
построения baby-таблицы и giant-поиска. После полного диапазона модель
уточняется; совместимый готовый кеш участвует с нулевой стоимостью построения.
Явный `-bsgs-table` является жёстким требованием: если таблица не входит в
`-bsgs-mem`, команда завершается с понятной ошибкой. Таблица делится на шарды
меньше `maxBufferLength`, снабжается контрольными суммами и записывается
атомарно. Кеш по умолчанию выключен; повреждённый или несовместимый шард молча
не принимается.

`-random` не выполняет бесконечные случайные выборки и не нарушает полноту
поиска. Режим строит не требующую дополнительной памяти биективную перестановку
индексов giant-групп. За один раунд последовательно проверяются 1024 giant
centers из псевдослучайно выбранной группы, затем выбирается другая группа.
До завершения диапазона каждая группа посещается ровно один раз. Все GPU
забирают работу из одной логической перестановки без пропусков и пересечений.
Seed печатается при запуске; `-bsgs-random-seed` воспроизводит тот же порядок.

Production backend сохраняет все компактные кандидаты `fingerprint64 + j`,
один раз сортирует их и строит адаптивный точный bucket-индекс. Коллизии
fingerprint могут добавить проверок, но не скрывают совпадение: каждый кандидат
восстанавливается на GPU и полностью сверяется с публичной точкой на CPU.
Переполнение hit-буфера обрабатывается сужением giant batch и постраничным
чтением одной цепочки коллизий — без тихой потери hits.

В Apple Silicon используется unified memory: CPU-копия таблицы, Metal-буферы
и все реплики для нескольких GPU расходуют единый working set. На всех
выбранных устройствах применяется общий безопасный размер таблицы, а giant
groups динамически забираются без пересечений, поэтому более быстрые устройства
естественно выполняют большую долю работы. Текущая скорость печатается только
стандартным `SpeedThreadFunc` тулкита. Поиск использует те же названия, что и
CUDA BSGS: `GStep/s` — число завершённых giant-center probes в секунду, а
`EqKey/s` — эффективное уникальное покрытие скаляров в секунду. Текущий
M-разнесённый CUDA walker выводит `EqKey/s = GStep/s × M`; Metal negation-map
walker с шагом `2M` выводит `EqKey/s = GStep/s × 2M`.

**Пример 1 — автоматический бюджет и один ключ.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target 02fe8d1eb1bcb3432b1db5833ff5f2226d9cb5e65cee430558c18ed3a3c86ce1af \
  -range 1:100 \
  -bsgs-mem auto \
  -o bsgs-known-key.txt
```

**Пример 2 — повторяемые цели и файл целей.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -target YOUR_OTHER_FULL_PUBLIC_KEY_HEX \
  -range 40,48-52 \
  -bsgs-mem 16GiB \
  -device 0
```

**Пример 3 — точная экспертная таблица и opt-in кеш.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -range 1000:2000 \
  -bsgs-table 2^12 \
  -bsgs-mem 4GiB \
  -bsgs-table-cache
```

**Пример 4 — весь безопасный working set и отдельный кеш.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target YOUR_FULL_PUBLIC_KEY_HEX \
  -range 64 \
  -bsgs-mem all \
  -bsgs-table-dir /Volumes/Fast/bsgs
```

**Пример 5 — полный поиск псевдослучайными раундами.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target targets.txt \
  -range 56 \
  -random \
  -bsgs-random-seed 0x1234 \
  -bsgs-mem 16GiB
```

**Пример 6 — 100 миллионов смещённых целей без файла из 100 миллионов ключей.**

```bash
./METAL_CRYPTO_TOOLKIT -bsgs \
  -target 02145d2611c823a396ef6712ce0f712f09b9b4f3135e3e0aa3230fb9b6d08d1e16 \
  -bsgs-shifts 0:100000000:1 \
  -range 135 \
  -bsgs-mem all
```

Математически это поиск по объединению скалярных интервалов, сдвинутых на
указанные величины. Плотные соседние сдвиги сильно перекрываются, поэтому не
дают бесплатного умножения уникального покрытия. Компактный режим устраняет
ограничение загрузки и памяти и позволяет честно проверить гипотезу, но не
уменьшает объём уникальной интервальной работы.

Каждый кандидат полностью сверяется с исходной точкой до вывода. 256-битные
счётчики и границы исключают усечение, но не делают полный 256-битный
дискретный логарифм практически выполнимым на современном железе.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -bsgs -help
```

#### `-vanity`

**Когда использовать:** для генерации нового secp256k1-ключа, адрес которого
соответствует выбранному префиксу, суффиксу или wildcard-шаблону. Режим ищет
новые ключи и не восстанавливает существующий кошелёк по адресу.

Поддерживаются BTC compressed/uncompressed P2PKH, вложенный P2SH-P2WPKH,
нативный Bech32 P2WPKH, lowercase Ethereum и TRON. Тип задаётся префиксом
`p2pkh:`, `p2pkh-u:`, `p2sh:`, `bech32:`, `eth:` или `tron:`. Его также можно
определить по началу `1`, `3`, `bc1q`, `0x` или `T`. Шаблон без wildcard
считается префиксом. `*suffix` ищет суффикс, а `?` соответствует ровно одному
символу адреса.

`-pattern` можно повторять. `-pattern-file` читает по одному шаблону на строку,
игнорирует пустые строки и `#`-комментарии, а одинаковые пары тип/шаблон
вычисляет один раз. Поиск завершается, когда для каждого уникального шаблона
найден один проверенный результат либо исчерпан диапазон.

| Параметр | Значение |
| --- | --- |
| `-pattern VALUE` | добавить один типизированный или автоматически распознанный шаблон |
| `-pattern-file FILE` | загрузить построчный список шаблонов |
| `-start N -end N` | точный интервал приватных ключей `[START,END)` в decimal либо `0x` hex |
| `-random` | однократно покрыть тот же интервал со случайной циклической ротации |
| `-n N` | число кандидатов за один Metal launch |
| `-device LIST` | индексы выбранных Metal-устройств |
| `-split-key PUBKEY` | искать `k_partial*G + PUBKEY` и выводить только частичный приват |
| `-o FILE` | дописывать полностью проверенные результаты |
| `-save` | использовать `VANITY_FOUND.txt`, если `-o` не задан |
| `-silent` | не печатать found в stdout, не отключая запись |

Случайный режим остаётся полным: он циклически сдвигает порядок интервала, а
не делает выборки с повторениями. В split-key режиме программе неизвестен
секретный скаляр владельца. Результат помечается `PARTIAL_PRIVATE`; владелец
складывает его со своей секретной долей по модулю порядка secp256k1. Каждый
Metal hit независимо пересчитывается и полностью кодируется на host до вывода.

```bash
./METAL_CRYPTO_TOOLKIT -vanity \
  -pattern 1Metal \
  -pattern 'eth:0xdead*' \
  -random \
  -save
```

```bash
./METAL_CRYPTO_TOOLKIT -vanity \
  -pattern-file vanity-patterns.txt \
  -split-key 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -start 1 -end 0x100000000 \
  -device 0 \
  -o partial-vanity.txt
```

Сложность экспоненциально растёт с числом зафиксированных символов адреса.
Mixed-case checksum-шаблоны Ethereum не генерируются; Ethereum сравнивается в
lowercase hex. Статистику завершённых `Key/s` печатает только стандартный
`SpeedThreadFunc`.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -vanity -help
```

#### `-create2`

**Когда использовать:** для поиска CREATE2 salt, при котором фиксированный
deployer и фиксированный hash initialization-кода дают Ethereum-адрес с
нужным hexadecimal-шаблоном. Этот режим ищет salt, а не приватные ключи.

CREATE2 использует точную формулу EIP-1014
`keccak256(0xff || deployer || salt || init_code_hash)[12:]`.
Поэтому `-deployer` принимает ровно 20 байт, а `-init-code-hash` — ровно
32 байта. Второй параметр уже должен быть `keccak256(init_code)`, а не сырым
bytecode. Шаблоны сравниваются с lowercase Ethereum-адресом без checksum.
`-pattern` можно повторять, а `-pattern-file` игнорирует пустые строки,
комментарии и дубликаты.

| Параметр | Значение |
| --- | --- |
| `-deployer 0xADDRESS` | фиксированный 20-байтовый deployer/factory |
| `-init-code-hash 0xHASH` | фиксированный 32-байтовый Keccak hash initialization-кода |
| `-pattern VALUE` | добавить префикс/суффикс/wildcard адреса |
| `-pattern-file FILE` | загрузить по одному шаблону на строку |
| `-start N -end N` | точный интервал salt или template ordinal `[START,END)` |
| `-mask HEX/?` | 64 ниббла salt; каждый `?` заполняется из ordinal |
| `-random` | однократно покрыть finite-интервал со случайной циклической ротации |
| `-n N` | число salt за один Metal launch |
| `-device LIST` | индексы выбранных Metal-устройств |
| `-o FILE`, `-save`, `-silent` | управление выводом проверенных результатов |

Без `-mask` сам 256-битный ordinal является salt. С маской неизвестные нибблы
заполняются справа налево в обычном числовом порядке, а фиксированные не
меняются. Если `-end` не задан, используется весь template-domain.
`-end 2^256` задаёт оставшийся полный U256-domain, но несовместим с `-random`.
Переполнение hit-буфера повторяет незачтённую работу, а каждый найденный адрес
независимо пересчитывается на host.

Официальный пример 0 из EIP-1014 (`init_code = 0x00`):

```bash
./METAL_CRYPTO_TOOLKIT -create2 \
  -deployer 0x0000000000000000000000000000000000000000 \
  -init-code-hash 0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a \
  -pattern 0x4d1a \
  -start 0 -end 65536 \
  -save
```

Поиск по шаблону salt:

```bash
./METAL_CRYPTO_TOOLKIT -create2 \
  -deployer 0xdead00000000000000000000000000000000beef \
  -init-code-hash 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -pattern 'create2:0x0000*' \
  -mask '000000000000000000000000????????????????????????????????????????' \
  -random -device 0
```

Полный U256 scheduler исключает усечение, но не делает исчерпывающий
256-битный поиск salt практически выполнимым. Текущие `Addr/s` печатает
только общий `SpeedThreadFunc`.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -create2 -help
```

#### `-hdpath`

**Когда использовать:** для восстановления одного или нескольких неизвестных
BIP32 child index, когда известен корневой seed/extended key и итоговый
публичный ключ secp256k1.

Нужно выбрать ровно один root через `-mnemonic`, `-seed`, `-xprv`, `-xpub`
либо `-descriptor`. Descriptor может содержать origin metadata и derivation
suffix. `-target` можно повторять; существующий файл читается как список
compressed/uncompressed публичных ключей.

Path template начинается с `m/`. В одном шаблоне можно смешивать фиксированные
индексы, inclusive-диапазоны и списки:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath \
  -seed 000102030405060708090a0b0c0d0e0f \
  -path-template "m/{0-15}'" \
  -target 035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56
```

Wildcard использует один finite half-open интервал:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath \
  -xpub xpub... \
  -path-template "m/0/*" \
  -start 0 -end 100000 \
  -target targets.txt \
  -wallet-mem auto -device 0 -save
```

Домен планируется как checked U256 mixed radix; окно засчитывается только
после завершения Metal и успешного readback. CKDpub не может строить hardened
children, поэтому апостроф и `h` с публичным root отклоняются. Результат от
xpub содержит проверенные path и public key, но не приватный ключ.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -hdpath -help
```

#### `-priv -hamming`

**Когда использовать:** для ограниченного поиска приватных ключей, которые
отличаются от известного 256-битного base ровно в `k` выбранных битах.

Обязательный формат — `BASE:DISTANCE[:MUTABLE_MASK]`. `BASE` и необязательная
маска записываются как обычные 64-символьные big-endian hex-строки. Единица
маски разрешает менять бит, ноль фиксирует его. Без маски изменяемыми считаются
все 256 бит. Бит 0 — старший бит отображаемого scalar.

```bash
./METAL_CRYPTO_TOOLKIT -priv \
  -hamming 0000000000000000000000000000000000000000000000000000000000000001:2:00000000000000000000000000000000000000000000000000000000000000ff \
  -target 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5 \
  -wallet-mem auto
```

Полный домен содержит `C(popcount(mask), distance)` кандидатов.
`-start/-end` выбирают half-open checked-U256 ordinal-поддиапазон в decimal,
`0xHEX` или `2^EXP`. `-target` можно повторять; существующий файл читается по
одному compressed/uncompressed public key secp256k1 на строку. `-device`
выдаёт непересекающиеся окна, большие наборы целей проходят ограниченными
Metal-тайлами, `-n` управляет только resident launch, а переполнение
hit-буфера повторяется до зачёта работы.

Результат содержит combinadic ordinal, base, distance, mask, проверенный
private/public key и исходные target sources. Текущие `Key/s` печатает только
`SpeedThreadFunc`. Checked U256 исключает усечение, но не делает огромную
Hamming-сферу практически выполнимой.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -priv -hamming -help
```

#### `-minikeys`

**Когда использовать:** для мини-ключей Casascius.

Полная строка начинается с `S` или строчной `s` и имеет длину 22, 26 или 30 символов; строчная буква нормализуется. Вариант без первого символа имеет длину 21, 25 или 29. Кандидаты читаются из файла/stdin либо создаются в Base58-диапазоне `-start/-end`. Сначала проверяется контрольное условие мини-ключа, и только после этого строится приват.

```bash
./METAL_CRYPTO_TOOLKIT -minikeys -i minikeys.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
```

Обычный `-minikeys` не использует PRNG, игнорирует `-hex` и не поддерживает `-back/-both`.

#### `-minikeys -seed`

**Когда использовать:** если мини-ключи должны детерминированно строиться из seed, а не читаться готовыми.

`-hex` декодирует строки seed. `-size` или `-sizes` выбирает длины мини-ключа; по умолчанию проверяются `22,26,30`.

```bash
./METAL_CRYPTO_TOOLKIT -minikeys -seed -hex -i seed_values.txt \
  -sizes 22,30 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-profanity`

**Когда использовать:** для воспроизведения старого процесса Profanity: seed MT19937-64, получение базового ключа и дальнейший проход добавлением точки G.

| Параметр | Значение |
| --- | --- |
| `-s HEX`, `-e HEX` | границы 32-битного seed; без них весь диапазон `0..ffffffff` |
| `-n N` | раунды на lane; без параметра `2^32` |
| `-offset HEX` | первый раунд; по умолчанию `1` |
| `-random` | случайные окна seed |
| `-random-seeds N` | число случайных seed за один выбор |
| `-gpu-split round|seed|foundid` | как делить работу между устройствами; по умолчанию `round` |

Режим фиксирует `-t 256`; базовая сетка — 16384 × 256, `-fsize 150000`, а автоматический `-bit` равен 16. Запись содержит seed, lane/found ID, offset/round, приват, тип и совпавшее значение.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -s 0 -e ff -n 1024 -offset 1 \
  -c e -hash 00112233445566778899aabbccddeeff00112233 -save
```

Это маленькая демонстрация. Реальную область следует выбирать по известным сведениям о конкретном кошельке.

#### `-profanity -recovery`

**Когда использовать:** известен открытый ключ secp256k1, созданный уязвимым Profanity, и нужно восстановить seed Profanity, lane/offset и приватный ключ.

Адреса, HASH160 или одного Ethereum account ID для этого режима недостаточно. В `-target`/`-hash` обязательно передается полный сжатый открытый ключ длиной 33 байта либо несжатый ключ длиной 65 байтов. Работа идет в четыре этапа:

1. GPU выполняет обратный проход от известной открытой точки `Q` по возможным раундам и lane Profanity.
2. Для каждой возможной базовой точки берутся первые 20 байтов канонической 32-байтовой affine-X координаты.
3. Обязательный XOR-фильтр на GPU проверяет, относится ли это значение к базовой точке какого-либо seed Profanity.
4. Совпадения фильтра проверяются в выбранном диапазоне seed32, после чего программа сравнивает полный открытый ключ. Поэтому ложное совпадение вероятностного фильтра не может стать готовым результатом без точной проверки кривой.

Готового фильтра в выпуске нет: его исходник содержит одну запись для каждого seed32 Profanity. При стандартных `-s 0 -e ffffffff` фильтр обязан покрывать все `4 294 967 296` базовых точек. Частичный список допустим только тогда, когда `-s` и `-e` намеренно ограничивают восстановление точно тем же диапазоном. Если нужного seed нет в фильтре, соответствующий ключ найден не будет.

Исходный файл `PROFANITY_BASEPOINT.txt` создает программа `tools/profanity_basepoint_generator`. В каждой строке находится 40 строчных hex-символов и `\n`, поэтому полный текстовый файл имеет точный размер `176 093 659 136` байт (176,09 GB или 164 GiB). Сам Binary Fuse-фильтр пользователь создает отдельно через [XopMC/XorFilter](https://github.com/XopMC/XorFilter).

Фактические размеры файлов для полного диапазона `2^32` и текущего формата фильтров:

| Исходник/фильтр | Параметр Toolkit | Точный размер, байт | Десятичный размер | Двоичный размер |
| --- | --- | ---: | ---: | ---: |
| `PROFANITY_BASEPOINT.txt` | напрямую не загружается | `176 093 659 136` | 176,09 GB | 164,000 GiB |
| `.xor_u` | `-xu` | `36 939 235 376` | 36,94 GB | 34,402 GiB |
| `.xor_c` | `-xc` | `18 471 714 864` | 18,47 GB | 17,203 GiB |
| `.xor_uc` | `-xuc` | `9 235 857 456` | 9,24 GB | 8,602 GiB |
| `.xor_hc` | `-xh` | `4 617 928 752` | 4,62 GB | 4,301 GiB |

Это размеры готовых файлов, а не объем ОЗУ во время их построения. Для обычной машины практичнее preset `-mini`: он ограничивает пиковую память, но разделит набор `2^32` на несколько пронумерованных фильтров. Сложите файлы только одного формата в отдельную папку и передайте папку Toolkit — программа загрузит все подходящие части. `-max` позволяет получить один крупный фильтр, но документация текущего XorFilter предупреждает, что большая сборка может потребовать более 256 GB ОЗУ.

Обычный выбор — `.xor_c`: он заметно меньше исходного набора и дает мало ложных совпадений. `.xor_uc` и особенно `.xor_hc` экономят общую память Apple Silicon, но чаще запускают тяжелую проверку seed. Один `.xor_u` занимает около 34,4 GiB. Параметр `-xx` может дополнительно загрузить соответствующий `.xor_u` для проверки совпадений от сжатого фильтра до этапа seed resolve. Он не заменяет обязательный фильтр на GPU и в общей памяти Apple Silicon добавляет полный размер `.xor_u` к уже загруженному фильтру.

Пример создания сжатого фильтра с ограниченным потреблением памяти:

```bash
mkdir -p profanity-xc
XorFilter -i PROFANITY_BASEPOINT.txt -compress -mini -check -o profanity-xc

./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 02... -xc profanity-xc -save -o profanity-found.txt
```

Для другого формата замените `-compress` на `-ultra` или `-hyper`, либо не указывайте сжатие для `.xor_u`; в Toolkit им соответствуют `-xuc`, `-xh` и `-xu`. Не смешивайте разные форматы и неполный набор частей в одной папке.

Файл `-i` понимает три вида строк:

```text
<public_key_hex>
<public_key_hex>:<offset_hex>
<public_key_hex>:<offset_hex>:found
```

Последняя форма помечает уже решенную строку при продолжении пакетной работы. В файловом режиме окно `-n` по умолчанию равно 16384. Для одной цели `-offset` по умолчанию равен 0, а `-n` не используется. Параметры `-s` и `-e` задают диапазон проверки seed и по умолчанию охватывают все 32 бита.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -xc profanity-xc -save
```

Здесь указан общеизвестный открытый ключ базовой точки secp256k1: он лишь показывает требуемую длину 33 байта. В папке фильтра должен находиться полный проверенный набор базовых точек Profanity для выбранного диапазона seed.

#### `-xp PROFILE`

**Когда использовать:** только когда известны конкретное старое приложение/среда, схема состояния и примерный диапазон времени или seed. Имя `PROFILE` обязательно.

Каталог объединяет:

- состояния и повторное засевание OpenSSL/SSLeay;
- Windows CryptGenRandom: state, bridge, XOR и chain-варианты;
- Android/Java LCG и генераторы конкретных сред выполнения;
- MT, Python, NumPy, Go, Rust, PHP и семейства JavaScript;
- Milk Sad, Trust Wallet, Cake Wallet, Coinpunk, BlueWallet и другие известные схемы;
- прямые SHA-256, PID hash, low bits, timestamp, screen state и наблюдаемые значения;
- ethers, React Native, Polkadot, AlphaWallet, SJCL и другие профили из встроенного списка.

<details>
<summary><strong>Основные имена XP-профилей</strong></summary>

- Профили по готовым трассам/входам: `cgr-state`, `cgr-bridge`, `cgr-xor`, `cgr-chain`, `cgr-chain-bridge`, `ssleay-stir`, `raw32`, `randbytes`.
- Экспериментальные пути OpenSSL: `openssl`, `openssl:all`, варианты по версиям, `openssl:path0..path53` и описанные `unknown*`. Это семейства кандидатов, а не обещание полного восстановления внутреннего состояния.
- Milk Sad и связанные приложения: `milksad-bx128`, `milksad-bx192`, `milksad-bx256`, `milksad-bx256-seq`, `bip3x-mingw`, `bip3x-mingw160/224/288/320`, `milksad-bx-ecnew`, `trustwallet`, `trustwallet-ios`, `milksad-trustwallet128-seq`, `milksad-trustwallet-ecnew`, `milksad-minstd-direct`, `milksad-minstd0-direct`, `cakewallet`.
- Среды выполнения и приложения: `android-bitcoin-wallet`, `android-sha1prng`, `alphaweb3e-tinymt32`, `sjcl-bip32`, `ethers-weakrandom`, `rn-getrandomvalues-mathrandom32`, `polkadot-wasm-asmjs-zero`, `mvw-web3-mathrandom`, `tezosj-java-random`.
- Browser/Randstorm: `walletgenerator-jsbn`, `randstorm`, `randstorm:jsbn`, `randstorm:all`, `randstorm:core-jsbn`, `randstorm:raw32`, `randstorm:pool32`, `randstorm-bytes`, `coinpunk-browserify-jsbn`, `randstorm-pymt`, `randstorm-mwc32`, `randstorm:v8-2011`, `randstorm:v8-2015`, `randstorm:spidermonkey-lcg48`, `randstorm:jsc-weakrandom`, `randstorm:v8-classic-mwc`, `randstorm:v8-alt-mwc`, `randstorm:v8-mwc1616`, `randstorm-v8init`, `randstorm-v8init-bytes`, `randstorm-v8init-pool32`.
- Прямые и runtime-профили: `phpcoinaddress`, `elliptic-php-rand-hmacdrbg`, `bluewallet-isaac`, `time-lcg-direct`, `time-mt`, `java-lcg-direct`, `sha256-direct`, `pid-hash-direct`, `lowbits-direct`, `pybtc-mt`, `nano-java-random`, `pywallet-ts-weak`.
- Распознаются, но отклоняются из-за отсутствия точной схемы: `cgr-full`, `php-mt-seed`, `v8-xorshift128`, `openssl-debian`.

Точные окончания имени и допустимые значения `-v` показывает `-xp -help`. Не переносите суффикс от одного профиля к другому.

</details>

Параметры XP зависят от выбранного профиля. В его строке справки могут быть разрешены `-s/-e`, `-n`, `-once`, `-i`, `-f`, `-v`, `-time-s/-time-e`, `-time-delta`, `-time-events`, `-time-events-repeat`, `-screen-seed X:Y`, `-screen-seed-zero`, `-time-mode state|seed-sec-ms|seed-ms-offset`, `-mileage` или `-mileage-s/-mileage-e`. Нельзя считать, что любой из этих параметров подходит каждому профилю.

Имена `-jsbn`, `-jsbn-lohi`, `-raw32`, `-raw32-lohi`, `-raw32-drop1`, `-raw32-drop1-lohi`, `-pool32`, `-pool32-lohi`, `-hilo`, `-lohi`, `-high-byte`, `-high8`, `-low-byte`, `-low8`, `-byte8`, `-byte8-low-byte`, `-byte8-low8`, `-low-byte-byte8` и `-low8-byte8` — это варианты конкретных XP-профилей, а не общие флаги любого режима.

У каждого профиля свой формат состояния, поэтому один “универсальный” пример был бы ошибочным. Сначала откройте каталог и используйте пример именно нужного профиля:

```bash
./METAL_CRYPTO_TOOLKIT -xp -help
```

Небольшой закрытый пример прямого профиля:

```bash
./METAL_CRYPTO_TOOLKIT -xp sha256-direct:decimal \
  -s 0 -e ff -n 1 -c e \
  -hash 00112233445566778899aabbccddeeff00112233
```

Он хеширует десятичные строки для чисел `0x00..0xff` и не заменяет примеры остальных XP-профилей.

Результат начинается с `XP:<PROFILE>`, затем содержит нужные этому профилю seed/time/PID/состояние, приват, тип цели и найденное значение.

### Brainwallet и старые форматы seed

#### `-warpwallet`

**Когда использовать:** для точных исторических memory-hard схем
«пароль → ключ». Они специально отделены от `-brain`, потому что изменение
даже одного параметра scrypt/PBKDF2 даёт другой приватный ключ.

| Профиль | Преобразование |
| --- | --- |
| `warp:SALT` | WarpWallet: scrypt `N=2^18,r=8,p=1` XOR PBKDF2-HMAC-SHA256 `c=2^16` |
| `brainwallet.io:SALT` | scrypt brainwallet.io, затем SHA-256 от строчного hex |
| `brainv2:SALT` | точная трёхступенчатая схема scrypt Brainv2 |
| `rush:PREFIX!CHECKSUM10HEX` | URL-фрагмент RushWallet; если checksum неизвестен, допускается `rush:PREFIX!` |

Один пароль или построчный файл задаётся повторяемыми `-pass`/`-i`.
Повторяемые цели hash160/P2PKH либо файлы целей передаются через `-target`.
Словари и таблицы целей обрабатываются ограниченными окнами; KDF и точка
secp256k1 вычисляются один раз на пароль, даже если цели занимают несколько
Metal-шардов.

```bash
./METAL_CRYPTO_TOOLKIT -warpwallet \
  -profile 'rush:rush!e61ae7a87d' \
  -pass 'correct horse battery staple' \
  -target 1895f1392560ed5467adf9bed7dd4c37443bdfba \
  -wallet-mem auto
```

`-wallet-mem auto|all|NN%|SIZE` ограничивает весь unified working set.
`-wallet-scrypt-mem SIZE` может задать более строгий предел scratch-памяти,
а `-n N` — число активных парольных lanes. Brainv2 особенно тяжёлый: один
кандидат включает 258 вызовов scrypt. GPU повышает скорость, но не превращает
огромный неизвестный парольный диапазон в практически простой поиск.

Результат `WARPWALLET_FOUND` содержит профиль, точную цель, пароль, приват и
источник цели. Перед выводом каждая строка полностью перепроверяется на CPU.
Текущую статистику `KDF/s` печатает только штатный `SpeedThreadFunc`.

#### `-brain [ПОДРЕЖИМ]`

**Когда использовать:** текст или байты непосредственно превращаются в приват через выбранную хеш-функцию.

| Значение | Преобразование |
| --- | --- |
| не указано | SHA-256 |
| `1` | SHA3-256 |
| `2` | Keccak-256 |
| `3` | BLAKE2b-256 |
| `4` | оставить байты без хеширования |

`-iter` повторяет выбранное преобразование. Поддерживаются файлы, stdin, сочетания слов, диапазоны, PRNG и hex-шаблоны этого режима.

Именованные профили задаются как `-brain-profile sha256|brainflayer-sha256|brainwallet.org|bitaddress|bitcoinjs|sha256d|sha256-hex|sha3-256[d]|keccak256[d]|blake2b-256[d]|raw`. Профиль сам задаёт transform, число итераций и binary/hex chaining.

Для потоковой мутации словаря `-brain-rules FILE` принимает документированный hashcat-совместимый core (`: l u c C t r d pN f q { } [ ] k K $X ^X TN DN 'N xNM sXY @X iNX oNX zN ZN`). `-brain-combine FILE` объединяет левый и правый словари, `-brain-combine-mode lr|rl|both` выбирает порядок, а `-space` вставляет пробел. Эти параметры работают с текстовым входом и намеренно запрещены вместе с `-hex` либо внутренними seq/PRNG/template источниками.

```bash
./METAL_CRYPTO_TOOLKIT -brain -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save

./METAL_CRYPTO_TOOLKIT -brain -brain-profile sha256d \
  -brain-rules best64.rule -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233

./METAL_CRYPTO_TOOLKIT -brain -brain-profile sha256 \
  -i left.txt -brain-combine right.txt -brain-combine-mode both -space \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

В запись входят читаемый кандидат, его байты в hex, номер повторения, приват, тип цели и совпавшее значение.

#### `-old`

**Когда использовать:** для старых мнемоник Electrum v1.

В одной строке находится одна фраза. `-deep N` задает глубину дочерних ключей и по умолчанию равен 20. `-valid` дополнительно разделяет строки по файлам `Valid.txt` и `NotValid.txt`. Для документированных сценариев доступны PRNG и шаблоны.

```bash
./METAL_CRYPTO_TOOLKIT -old -i electrum_v1.txt -deep 20 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-old -seed` и `-old -entropy`

Это два имени одного маршрута, который принимает байты старого Electrum seed вместо слов. С `-hex` одна строка содержит seed в hex. Доступны файл/stdin, совместимые диапазоны, PRNG, recovery и `-deep`.

```bash
./METAL_CRYPTO_TOOLKIT -old -seed -hex -i old_seeds.txt -deep 20 \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

#### `-armory`

**Когда использовать:** для бумажной резервной копии Armory Easy16.

Одна строка содержит блоки Easy16 подряд либо разделенными знаком `%`. `-deep` задает глубину дочерних ключей. Этот режим не имеет отношения к подбору пароля зашифрованного файла `.wallet`.

```bash
./METAL_CRYPTO_TOOLKIT -armory -i easy16_backups.txt -deep 30 \
  -c c -hash 00112233445566778899aabbccddeeff00112233
```

#### `-root [ПОДРЕЖИМ]` / `-armory -root`

**Когда использовать:** имеется 32-байтовый Armory root либо 64 байта root вместе с chain code.

| Значение | Предварительное преобразование |
| --- | --- |
| `0` или не указано | обычный root |
| `1` | SHA-256 |
| `2` | SHA-512 |
| `3` | Keccak-256 |
| `4` | SHA3-256 |
| `5` | MD5 |
| `6` | активный кернел переводит входные байты в строчные hex-символы ASCII; текущая строка CLI называет этот профиль `BLAKE2b-256`, но реализованное преобразование этому названию не соответствует |
| `7` | оставить байты без хеширования |

```bash
./METAL_CRYPTO_TOOLKIT -root 0 -hex -i roots.txt -deep 30 -c c \
  -hash 00112233445566778899aabbccddeeff00112233
```

#### `-walletjs PROFILE`

**Когда использовать:** известен конкретный старый процесс генерации ключа в JavaScript/браузере.

Парольные профили:

- `cryptojs-sha256`;
- `bitaddress-sha256`;
- `brain-sha256`.

Профили ограниченного состояния JSBN/ARC4:

- `jsbn-arc4-v8-2011`;
- `jsbn-arc4-v8-2015`;
- `jsbn-arc4-spidermonkey-lcg48`;
- `jsbn-arc4-jsc-weakrandom`;
- каждое имя выше с окончанием `-exact`.

SHA-256-профили принимают словарь, маску и сырой диапазон байтов. Профили состояния браузера используют `-s/-e` в hex, `-random` и `-n`. Если границы не заданы, программа берет конечный диапазон `0x0000000000000000..0xffffffffffffffff`: это ровно `2^64` состояний, которые обычно невозможно перебрать полностью за разумное время.

Для `-exact` обязательны `-time-s` и `-time-e`. `-time-delta N` проверяет второй time seed от `time0` до `time0 + N` миллисекунд; по умолчанию 0, максимум 1024.

```bash
./METAL_CRYPTO_TOOLKIT -walletjs cryptojs-sha256 -i passwords.txt \
  -c e -hash 00112233445566778899aabbccddeeff00112233 -save
```

Нужна хотя бы одна secp256k1-ветка из `c,u,s,p,r,e,x`. Формат результата:

```text
WALLETJS:<profile>:SOURCE:<source>:PRIV:<64_hex>:<TYPE>:<value>
```

### Восстановление паролей кошельков

#### Общие правила

Выбирайте ровно один формат кошелька. `-walletscan` выполняет только ограниченную инвентаризацию поддерживаемых сигнатур и похожих на секреты записей. Для режима проверки паролей нужны сами файлы/хеши и один из трех источников кандидатов ниже; `-wallet-load-only` является исключением, потому что завершает работу после разбора и группировки целей.

Пароли можно получать тремя способами:

- один или несколько словарей `-i FILE`; флаг `-hex` только меняет разбор строк такого словаря и заставляет считать их hex-байтами пароля;
- `-mask` или `-mask-file`, при необходимости с `-cs1` ... `-cs4`;
- сырой байтовый диапазон `-start HEX [-end HEX]`.

Максимальная длина пароля — 127 байт, маски — 64 позиции. Маска и сырой диапазон взаимоисключающие. Обычные файловые флаги `-all`, `-delete`, `-comb`, `-space` и `-rep` не управляют файлами кошельков.

Добавьте `-save`, если найденный пароль, результат WalletJS/XP/Profanity или строку инвентаризации нужно записать в файл, выбранный через `-o`. Без `-save` эти специальные режимы показывают найденное только в терминале, если одновременно не включен `-silent`.

| Параметр | Что делает |
| --- | --- |
| файлы сразу после режима | загружает конкретные кошельки или файлы с хешами; большинство режимов принимает несколько |
| `-f DIR` | рекурсивно ищет расширения, подходящие выбранному формату |
| `-wallet-load-only` | разбирает, проверяет и группирует цели, затем завершает работу до перебора |
| `-wallet-dry-run` | другое имя `-wallet-load-only` |
| `-wallet-mem auto\|all\|NN%\|SIZE` | бюджет unified memory для v16-режимов, где он указан явно; включён для BIP38, Substrate wallet и mnemonic scramble |
| `-wallet-scrypt-mem MiB` | ограничивает промежуточную память только в режимах, где реально используется scrypt/KdfRomix |

`-wallet-mem auto` использует не более половины текущего свободного recommended Metal working set. `all` использует остаток за вычетом 512 МиБ для runtime; процент считается от текущей свободной памяти. На Apple Silicon host-visible таблицы и реплики на Metal-устройствах расходуют один пул unified memory. Автоматический предел памяти для scrypt сначала ориентируется на 16384 МиБ; BIP38 без явного scrypt-cap использует измеренный ориентир 32768 МиБ. Когда суммарный размер входных данных обычных GPU-фильтров достигает 8 ГиБ, ориентир снижается до 4096 МиБ. Итоговый буфер дополнительно ограничивается `-wallet-mem`, свободной объединенной памятью и размером одного задания. Явный `-wallet-scrypt-mem` является строгим пределом и завершает запуск ошибкой, если не помещается одно задание.

`-hash` и `-target` здесь не нужны: цель проверки уже находится внутри файла кошелька или извлеченной строки.

#### `-keystore`

**Что загружается:** Ethereum JSON V3, JSON/LevelDB с теми же полями либо строка:

```text
$ethereum$s*N*r*p*salt*ciphertext*mac
```

Поддерживаются PBKDF2-HMAC-SHA256 и scrypt, AES-128-CTR и проверка MAC. По папке ищутся `.json`, `.key`, `.keystore`, `.txt`, `.hash`, `.log`, `.ldb`, файлы без расширения и имена `UTC--*`/`UTC_*`.

Сразу после `-keystore` передается один файл; для множества файлов используйте `-f`. `-n` ограничивает число одновременно активных scrypt-заданий, по умолчанию 64. `-wallet-scrypt-mem` этот режим не принимает.

```bash
./METAL_CRYPTO_TOOLKIT -keystore wallet.json -i passwords.txt \
  -save -o keystore_found.txt
```

Если удалось полностью восстановить ключ:

```text
KEYSTORE:<source>:PASSWORD:<password>:PRIV:<64_hex>:ETH:<0x_address>
```

Для записи, в которой можно подтвердить только MAC:

```text
KEYSTORE:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:web3-secret-storage-mac
```

#### `-walletdat`

**Что загружается:** Bitcoin Core Berkeley DB/сырой файл с записями method-0 `mkey` и `ckey` либо извлеченная строка:

```text
$bitcoin$<mkey_len>$<mkey_hex>$<salt_len>$<salt_hex>$<iterations>$<ckey_len>$<ckey_hex>$<pubkey_len>$<pubkey_hex>
```

Обычный `-f` просматривает `.dat`; `-scan-all` заставляет проверять каждый файл. Повторяющийся SHA-512 получает ключ/IV AES, затем проверяются master key и связь ckey с открытым ключом.

| Параметр | По умолчанию | Назначение |
| --- | --- | --- |
| `-walletdat-max-ckey N` | `8` | сколько ckey брать из одного кошелька; `0` — без ограничения |
| `-walletdat-kdf-work N` | `1000000` | объем поэтапной KDF-работы в одном пакете |
| `-walletdat-max-iter N` | `0` | отклонять цели с большим числом повторений; `0` — без ограничения |
| `-walletdat-min-jobs N` | `0` | минимальное число сгруппированных заданий; `0` — автоматически |
| `-walletdat-kdf-loop N` | `16384` | число повторений на одном этапе KDF |

```bash
./METAL_CRYPTO_TOOLKIT -walletdat wallet1.dat wallet2.dat \
  -i passwords.txt -save -o walletdat_found.txt
```

В полном результате записываются `PRIV` и `PUBKEY`; если доступна только проверка master key — отпечаток `MKEY`.

#### `-browservault`

**Что загружается:** данные расширений браузера, LevelDB и экспортированные JSON/текстовые записи. У MetaMask используются поля `data`, `iv`, `salt`; у Phantom — `encrypted`, `nonce`, `salt`, `kdf`; Atomic хранит Base64-значение OpenSSL/CryptoJS с заголовком `Salted__`.

Рабочие профили:

- MetaMask browser-passworder: PBKDF2-HMAC-SHA256 и AES-256-GCM;
- Phantom: PBKDF2 либо scrypt и XSalsa20-Poly1305 secretbox;
- Atomic: CryptoJS/OpenSSL MD5 EVP_BytesToKey и AES-256-CBC.

`-wallet-scrypt-mem` влияет только на записи Phantom со scrypt.

```bash
./METAL_CRYPTO_TOOLKIT -browservault -f browser_data \
  -i passwords.txt -save -o browser_found.txt
```

Общий вид результата:

```text
<WALLET_PREFIX>:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:<exact_profile>
```

`VAULT:<sha256>` — отпечаток цели, а не расшифрованное содержимое хранилища.

#### `-copaywallet`

Режим восстанавливает пароли для зашифрованных backup Copay и BitPay в
стандартном JSON-формате SJCL. Один или несколько файлов задаются сразу после
режима; `-f DIR` рекурсивно просматривает `.json` и файлы без расширения.

Loader требует явные поля `v`, `iter`, `ks`, `ts`, `mode`, `cipher`, `adata`,
`salt`, `iv` и `ct`. Поддерживается SJCL версии 1 с PBKDF2-HMAC-SHA256,
AES-128-CCM, 64-битным authentication tag, пустым associated data и точным
clamp nonce из SJCL. Неизвестные версии, изменённые размеры key/tag,
непустой associated data, некорректный Base64, слишком длинный ciphertext и
другие cipher отклоняются до GPU.

Metal получает ключ и полностью проверяет CCM tag. Цели с одинаковыми
KDF-параметрами и salt используют один результат PBKDF2. `-wallet-mem`
ограничивает working set unified memory, `-device` выбирает Metal-устройства,
а единственным live-потоком завершённых `KDF/s` и фактических `Verify/s`
остаётся общий `SpeedThreadFunc`.

```bash
./METAL_CRYPTO_TOOLKIT -copaywallet wallet-backup.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -copaywallet -f copay_backups \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o copay_found.txt
```

Результат содержит источник, восстановленный пароль, fingerprint
аутентифицированного backup и точный профиль. Режим не предназначен для
произвольных современных баз приложения BitPay или export не в формате SJCL.

#### `-terrawallet`

Режим восстанавливает пароли исторического exported-key формата мобильного
Terra Station. Можно передать raw JSON, его исходную внешнюю Base64-обёртку
или использовать `-f DIR` для сканирования `.json`, `.txt` и файлов без
расширения.

Строгий loader требует поля `name`, `address` и `encrypted_key`. Адрес должен
быть checksum-valid Bech32 `terra1...` ровно с 20 байтами payload.
`encrypted_key` обязан содержать 16-байтовый hex salt, 16-байтовый hex IV и
80-байтовый Base64 ciphertext. Неизвестная или изменённая структура
отклоняется до GPU.

Metal получает AES-ключ через PBKDF2-HMAC-SHA1 (100 итераций), расшифровывает
AES-256-CBC с точным PKCS7 padding, разбирает все 64 hex-символа приватного
ключа, восстанавливает compressed secp256k1 public key и сравнивает HASH160 с
экспортированным адресом. Просто правдоподобный plaintext никогда не считается
результатом. Цели с одинаковым salt используют один KDF, а `-wallet-mem`
ограничивает working set unified memory.

```bash
./METAL_CRYPTO_TOOLKIT -terrawallet terra-export.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -terrawallet -f terra_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o terra_found.txt
```

Результат:

```text
TERRAWALLET:<source>:PASSWORD:<password>:PRIV:<64hex>:ADDRESS:<terra1...>:PROFILE:terra-station-pbkdf2-sha1-aes-256-cbc
```

Поддерживается только этот legacy exported-key профиль. Terra mnemonic,
hardware wallet, современные WalletConnect-записи и неизвестные будущие
форматы не являются целями восстановления пароля.

#### `-bitshareswallet`

Режим восстанавливает пароли официального JSON-формата `exported_keys`
BitShares 0.x. Один или несколько файлов передаются сразу после режима;
`-f DIR` сканирует `.json` и файлы без расширения.

Строгий loader требует 64-байтовый hex `password_checksum` и непустой массив
`account_keys`. В каждой account-записи должны находиться параллельные
непустые строковые массивы `encrypted_private_keys` и `public_keys`.
Зашифрованный приватный ключ имеет ровно 48 байт AES-CBC. Public key обязан
иметь исторический префикс `BTS` либо `BTSX`, декодироваться в compressed
secp256k1 key и содержать корректный четырёхбайтовый RIPEMD-160 checksum.

Metal вычисляет `password_key = SHA512(password)` и отбрасывает кандидата,
если `SHA512(password_key)` не совпал с export. Первые 32 байта password key
используются как AES-256 key, байты 32–47 — как CBC IV. После точной проверки
PKCS7 32-байтовый scalar заново преобразуется в compressed secp256k1 public
key и побайтно сравнивается с экспортированным identity. Ключи с одним
password checksum используют общую KDF-задачу. `-wallet-mem` ограничивает
working set unified memory.

```bash
./METAL_CRYPTO_TOOLKIT -bitshareswallet exported-keys.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -bitshareswallet -f bitshares_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o bitshares_found.txt
```

Результат:

```text
BITSHARESWALLET:<source#account/key>:PASSWORD:<password>:PRIV:<64hex>:PUBKEY:<compressed-hex>:PROFILE:bitshares-0x-exported-keys-sha512-aes-256-cbc
```

Полные базы BitShares, watch-only records и неизвестные контейнеры намеренно
не считаются этим exported-key профилем. Единственный live printer статистики
— общий `SpeedThreadFunc`; число целей искусственно не умножает `KDF/s` или
`Verify/s`.

#### `-yoroiwallet`

Режим восстанавливает пароли из JSON-снимков Yoroi IndexedDB с
EMIP-3-зашифрованным root key BIP32-Ed25519. Один или несколько снимков
передаются после режима; `-f DIR` сканирует `.json` и файлы без расширения.

Строгий loader читает таблицы `Key` и `KeyDerivation`, принимает только записи
`BIP32ED25519` и проходит точную цепочку encrypted root -> `1852'` ->
`1815'` -> `account'` до сохранённого 64-байтового account xpub.
Зашифрованный root должен иметь ровно 156 байт:
`salt32 || nonce12 || tag16 || ciphertext96`.

Metal получает 32-байтовый encryption key как
PBKDF2-HMAC-SHA512(password, salt, 19162), проверяет ChaCha20-Poly1305 с
пустым AAD, расшифровывает 96-байтовый root xprv и выполняет hardened
CIP-1852 derivation. Результат выводится только при совпадении и account
public key, и chain code с identity из IndexedDB. Roots с одним salt разделяют
grouped PBKDF2 job. `-wallet-mem` ограничивает working set unified memory.

```bash
./METAL_CRYPTO_TOOLKIT -yoroiwallet yoroi-indexeddb.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -yoroiwallet -f yoroi_snapshots \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o yoroi_found.txt
```

Результат:

```text
YOROIWALLET:<source#root/account>:PASSWORD:<password>:ROOT_XPRV:<192hex>:PROFILE:yoroi-emip3-pbkdf2-sha512-chacha20poly1305
```

Mnemonic recovery, hardware signers, watch-only roots и неизвестные будущие
контейнеры намеренно не входят в этот профиль. Проверка authentication tag и
точное восстановление account xpub обязательны. Единственный live printer —
общий `SpeedThreadFunc`; число целей не раздувает `KDF/s` или `Verify/s`.

#### `-monero`

Режим восстанавливает кошельки Monero из legacy mnemonic по 25 слов и
16-словных шаблонов Polyseed. Фразы передаются повторяемым `-i` напрямую либо
в текстовом файле по одной строке. Пустые строки и `#`-комментарии
игнорируются. Отдельный `?` обозначает одно неизвестное целое слово:

```bash
./METAL_CRYPTO_TOOLKIT -monero \
  -i "amaze buffet cake entrance symptoms tiger lamb maze nestle python dusted faxed update vague zinger boxes ornament renting glass gained island nabbing afield calamity ?" \
  -target 4... -monero-lang English -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -monero -i polyseed-templates.txt \
  -target monero-targets.txt -wallet-mem all -device 0 \
  -save -o monero_found.txt
```

Повторяемый `-target` принимает standard, integrated или subaddress, файл
целей либо экспертную точную форму
`SPEND_PUBLIC_HEX:VIEW_PUBLIC_HEX`. Адрес декодируется только после проверки
network/type prefix и Keccak checksum. Одинаковая public-пара вычисляется
один раз, но в результате сохраняются все исходные occurrences.

Режим содержит все официальные языковые списки Monero legacy и Polyseed.
`-monero-lang auto` выбирает однозначный список; для полностью неизвестного
или неоднозначного шаблона следует указать язык явно. Legacy CRC32 и checksum
Polyseed в GF(2^11) отсеивают кандидатов до GPU derivation. Зашифрованные
feature-фразы Polyseed намеренно не входят в этот recovery profile.

Metal выполняет PBKDF2-HMAC-SHA256 для Polyseed, reduction scalar,
Keccak-derivation view key и оба Ed25519 base-point multiplication один раз на
checksum-valid кандидата. Большие наборы целей сортируются и обрабатываются
ограниченными точными окнами, поэтому их количество не умножает дорогую
derivation и отображаемую скорость. `-wallet-mem auto|all|NN%|SIZE`
управляет полным working set unified memory, а `-n` задаёт дополнительный
предел candidate batch.

Каждый GPU hit восстанавливается по checked U256 ordinal и независимо
пересчитывается официальной арифметикой Monero ref10 на host:

```text
MONERO_FOUND SCHEME:<legacy|polyseed> LANGUAGE:<name> TARGET:<source> MNEMONIC:<phrase> SPEND_PRIVATE:<64hex> VIEW_PRIVATE:<64hex> SPEND_PUBLIC:<64hex> VIEW_PUBLIC:<64hex>
```

Единственный live printer — общий `SpeedThreadFunc`: он выводит зачтённые
`Candidate/s`, primitive operations, реальные `Verify/s`, resident/logical
targets, readback time и выделенный working set. Пространство растёт
экспоненциально с числом неизвестных слов; checksum pruning и GPU не делают
произвольно большие domains практически выполнимыми.

#### `-monerowallet`

Режим восстанавливает пароли официальных `.keys`-контейнеров программных
кошельков Monero. Один или несколько файлов задаются повторяемым `-f` либо
позиционными путями после режима. `-pass` принимает literal password или
существующий построчный файл паролей; `-i` добавляет файл кандидатов.

```bash
./METAL_CRYPTO_TOOLKIT -monerowallet -f wallet.keys \
  -pass passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -monerowallet wallet.keys \
  -pass "correct horse battery staple" -wallet-mem all -device 0
```

Metal выполняет точный CryptoNight-v0 password KDF как последовательность
init, заполнения scratchpad, 524288 mixing steps, fold, Keccak и выбранного
Blake/Groestl/JH/Skein kernel. Каждый активный пароль использует scratchpad
2 MiB. `-wallet-mem auto|all|NN%|SIZE` ограничивает полный working set unified
memory; automatic lane count уменьшается после allocation failure, а явный
`-n` задаёт строгое число активных lanes. `-monero-kdf-rounds` по умолчанию
равен одному и меняется только для кошелька, который точно был создан с
другим количеством раундов.

Современные payload ChaCha20/JSON и legacy ChaCha8 portable-account
определяются раздельно. Для современных зашифрованных secret keys режим
дополнительно получает memory key `CryptoNight(base_key || 'k')`. Пароль
выводится только после проверки канонических scalar и точного восстановления
сохранённых spend/view public keys арифметикой ref10:

```text
[+] MONEROWALLET_FOUND SOURCE:<file> PASSWORD:<quoted> PASSWORD_HEX:<hex> SPEND_PRIVATE:<64hex> VIEW_PRIVATE:<64hex> SPEND_PUBLIC:<64hex> VIEW_PUBLIC:<64hex> PROFILE:<monero-keys-json-chacha20|monero-keys-v0-chacha8>
```

Единственный live printer — общий `SpeedThreadFunc`. `KDF/s` считает кандидаты
только после завершения Metal command buffer и readback; число кошельков не
используется как искусственный множитель. Пароли ограничены 127 байтами.
Hardware-device контейнеры, custom background password, повреждённые envelope
и неизвестные будущие версии отклоняются без эвристической расшифровки.

#### `-algorand`

Режим восстанавливает стандартные английские mnemonic Algorand из 25 слов.
Одну или несколько фраз/шаблонов либо построчных файлов можно передавать
повторяемым `-i`; пустые строки и `#`-комментарии в файлах игнорируются.
Отдельный `?` или `*` означает одно неизвестное целое слово. Повторяемый
`-target` принимает канонический 58-символьный адрес Algorand, исходный
32-байтовый/64-hex public key Ed25519 или файл, где цель — первый токен каждой
непустой строки.

Первые 24 слова кодируют 32-байтовый private seed и один обязательный нулевой
padding byte, поэтому data word 24 допускает только индексы `0..7`. Word 25 —
первый little-endian 11-bit chunk от `SHA-512/256(seed)`; если он неизвестен,
режим получает его автоматически. Эти структурные проверки выполняются до
base-point multiplication Ed25519.

Официальный вектор SDK проверяется как один конечный кандидат:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "olympic cricket tower model share zone grid twist sponsor avoid eight apology patient party success claim famous rapid donor pledge bomb mystery security ability often" \
  -target LZTU6HAK53WDO4MJR5Q4O37V2JFBS6J6FSI7UCCRMJR6HBLT5JBFX2XOWM \
  -wallet-mem auto -n 1
```

Неизвестные data words образуют checked mixed-radix U256 domain. `-start` и
исключающий `-end` выбирают точный срез; `-end 2^256` обозначает не
представимую обычным U256 верхнюю границу, когда неизвестны все 24 data words.
Следующий конечный пример проверяет все 2048 значений первого слова:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "? cricket tower model share zone grid twist sponsor avoid eight apology patient party success claim famous rapid donor pledge bomb mystery security ability ?" \
  -target LZTU6HAK53WDO4MJR5Q4O37V2JFBS6J6FSI7UCCRMJR6HBLT5JBFX2XOWM \
  -start 0 -end 2048 -wallet-mem all -n 2048
```

С `-scramble` все 25 входных слов должны быть известны. Они считаются
multiset, поэтому повторяющиеся слова не создают одинаковые перестановки.
У zero-seed вектора всего 25 уникальных размещений:

```bash
./METAL_CRYPTO_TOOLKIT -algorand \
  -i "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invest" \
  -scramble \
  -target HNVCPPGOW2SC2YVDVDICU3YNONSTEFLXDXREHJR2YBEKDC2Z3IUZSC6YGI \
  -start 0 -end 25 -wallet-mem auto -n 25
```

`-wallet-mem auto|all|NN%|SIZE` ограничивает весь working set unified memory;
размеры принимают MiB/GiB, а `-n` дополнительно ограничивает candidate batch.
Полностью resident target tile использует измеренно более быстрый fused
derive/lookup kernel. Большие наборы обрабатываются точными ограниченными
окнами с переиспользованием candidate derivation. Дубли целей вычисляются
один раз, но сохраняют все source labels.

Каждая найденная запись содержит источники target/template, канонический
адрес, полную mnemonic, 32-байтовый seed и public key. Host независимо
повторяет padding, checksum SHA-512/256, derivation Ed25519 и target matching.
Live `Candidate/s` печатает только общий `SpeedThreadFunc`, а число целей не
используется как множитель скорости. Поддерживается стандартный английский
профиль mnemonic. U256-представление и GPU не делают произвольно большие
пространства неизвестных слов или перестановок практически выполнимыми.

#### `-slip39`

Режим восстанавливает encrypted master secret (EMS) из стандартных английских
mnemonic shares SLIP-0039 и перебирает optional passphrase на Metal. Передайте
по одной доле в каждой непустой строке через `-recovery FILE` либо повторяйте
`-recovery "WORDS ..."`. Loader проверяет официальный checksum RS1024, общие
metadata, group/member indexes и thresholds, digest shares и оба уровня
интерполяции GF(256). Отдельный `?` или `*` восстанавливает одно неизвестное
целое слово; в одной доле допускается не более двух неизвестных слов.

Verification задаётся явно. `-target` принимает 64-hex
`SHA256(master-secret)` либо файл, где digest является первым токеном каждой
непустой строки. `-master-secret` принимает известный 16-32-байтовый secret
чётной длины в hex и создаёт соответствующую цель. Дубли целей вычисляются
один раз, но сохраняют все source labels.

Официальный non-extendable вектор выполняет одну конечную проверку пароля:

```bash
./METAL_CRYPTO_TOOLKIT -slip39 \
  -recovery "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard" \
  -master-secret bb54aac4b89dc868ba37d9cc21b2cece \
  -pass TREZOR -wallet-mem auto -n 1
```

Источники паролей: повторяемый `-pass VALUE|FILE`, потоковый `-i FILE`,
`-mask` с `?d/?l/?u/?a/??` либо decimal strings из исключающего диапазона
`-start/-end`. Без источника проверяется стандартная пустая passphrase.
SLIP-0039 допускает только printable ASCII; режим отклоняет пароли длиннее
127 байт.

Metal выполняет все четыре обратных раунда Feistel и точные
`2500 << iteration_exponent` итераций PBKDF2-HMAC-SHA256 на раунд. Полностью
resident target tile использует fused decrypt/lookup. Большой набор целей
переходит на split-путь: один decrypt/hash и повторное использование derived
данных в ограниченных target tiles. Каждый hit независимо расшифровывается и
хешируется CommonCrypto до вывода.

`-wallet-mem auto|all|NN%|SIZE` ограничивает полный working set unified
memory, `-device` выбирает Metal devices, а `-n` ограничивает завершённый
batch. Единственный live printer — общий `SpeedThreadFunc`; он показывает
фактические `Pwd/s`, PBKDF2 primitive work, `Verify/s`, resident targets,
readback и allocated memory. Для повреждённых шаблонов действует предел в
один миллион совместимых сочетаний. Режим подтверждает master secret или его
SHA256, но не объявляет derivation path либо адрес кошелька только по
валидному checksum.

#### `-substratewallet`

Режим восстанавливает пароли для экспортированных JSON-файлов keyring
Polkadot/Substrate. Один или несколько файлов можно указать сразу после режима;
`-f DIR` рекурсивно ищет `.json` и файлы без расширения. Принимаются только
аутентифицированные записи PKCS8:

- версия 3: встроенные параметры scrypt и XSalsa20-Poly1305;
- версия 2: legacy-ключ из байтов пароля, обрезанный или дополненный нулями
  справа до 32 байт, и XSalsa20-Poly1305.

`encoding.content` должен явно содержать `pkcs8` и ровно одну curve:
`sr25519`, `ed25519` или `ecdsa`. Identity задаётся checksummed SS58
AccountId32 либо public key с `0x`; ECDSA использует compressed 33-byte
secp256k1 key. Неизвестные версии, неверные checksum, некорректные параметры
scrypt и неподдерживаемые encoding отклоняются до GPU.

Metal выполняет полную проверку. Пароль выводится, только если одновременно
совпали Poly1305 tag, header/divider PKCS8, встроенный public key, экспортированная
identity и public key, независимо восстановленный из расшифрованного секрета.
Цели с одинаковыми salt/KDF-параметрами используют один результат scrypt.
Общий `SpeedThreadFunc` показывает завершённые `KDF/s` и фактические
`Verify/s`; число целей не умножает `KDF/s`.

```bash
./METAL_CRYPTO_TOOLKIT -substratewallet account.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -substratewallet -f keyring_exports \
  -mask "?a?a?a?a?a?a?a?a" -wallet-mem all -device 0 \
  -save -o substrate_found.txt

./METAL_CRYPTO_TOOLKIT -substratewallet account.json \
  -i exact-password-bytes.hex -hex -wallet-scrypt-mem 4096 -save
```

Результат:

```text
SUBSTRATEWALLET:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:<substrate-v3-scrypt-pkcs8|substrate-v2-legacy-pkcs8>
```

`VAULT` — стабильный отпечаток зашифрованного artifact, а не расшифрованный
секрет. Hardware/remote signer, watch-only records, незашифрованные экспорты и
версии keyring JSON, отличные от 2/3, не являются целями подбора пароля.

#### `-electrumwallet`

**Что загружается:** Electrum BIE1, поля `xprv`/`seed` из JSON с `pw_hash_version=1` и извлеченные строки:

```text
$electrum$5*<compressed_pubkey_hex>*<cipher_hex>*<mac_hex>
$electrum$2*<iv_hex>*<cipher_hex>
```

BIE1 проверяется через PBKDF2-HMAC-SHA512/1024, ECDH, AES и HMAC. FIELD-записи используют double-SHA256 пароля и AES-CBC. Незашифрованный JSON сообщается сразу. Хранилища BIE2 и JSON-записи в стиле аппаратных кошельков распознаются как неподдерживаемые и не проверяются; это не универсальный разборщик аппаратных кошельков.

```bash
./METAL_CRYPTO_TOOLKIT -electrumwallet -f electrum_wallets \
  -i passwords.txt -save
```

```text
ELECTRUMWALLET:<source>:PASSWORD:<password>:TYPE:<BIE1|FIELD|PLAINTEXT>:DETAIL:<sha256>
```

#### `-exodusseco`

**Что загружается:** двоичные контейнеры `.seco` версии 0 с меткой `seco-v0-scrypt-aes`. Проверяются служебные данные, параметры scrypt и AES-256-GCM.

`-f` всегда означает папку и ищет `.seco`. Сразу после имени режима можно перечислить один или несколько файлов. `-wallet-scrypt-mem` и `-n` ограничивают память и число активных scrypt-заданий.

```bash
./METAL_CRYPTO_TOOLKIT -exodusseco -f exodus_wallets \
  -i passwords.txt -save
```

```text
EXODUSSECO:<source>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:seco-v0-scrypt-aes
```

#### `-bitcoinjwallet` / `-multidogewallet`

**Что загружается:** зашифрованные protobuf-кошельки bitcoinj, MultiDoge и Coinomi. Пароль переводится в Java UTF-16BE, затем выполняются scrypt, AES-256-CBC/PKCS#7 и сравнение полученного открытого ключа.

По папке ищутся `.wallet`, `.dat` и файлы без расширения. `-wallet-scrypt-mem` и `-n` управляют памятью и количеством заданий.

```bash
./METAL_CRYPTO_TOOLKIT -bitcoinjwallet -f protobuf_wallets \
  -i passwords.txt -save
```

```text
BITCOINJWALLET:<source>:PASSWORD:<password>:PRIV:<64_hex>:PUBKEY:<hex>
```

#### `-armorywallet`

**Что загружается:** зашифрованный файл Armory `BA WALLET` с root-записью. Проверяются контрольные суммы, KdfRomix(SHA-512), AES-256-CFB и сохраненный открытый ключ root.

Незашифрованные Armory-файлы не требуют подбора пароля; их следует смотреть через `-walletscan`. `-wallet-scrypt-mem` и `-n` управляют памятью KdfRomix и числом заданий.

```bash
./METAL_CRYPTO_TOOLKIT -armorywallet -f armory_wallets \
  -i passwords.txt -save
```

```text
ARMORYWALLET:<source>:PASSWORD:<password>:PRIV:<64_hex>:PUBKEY:<hex>
```

#### `-stellarwallet`

**Формат строки:**

```text
$stellar$<salt_base64>$<iv_base64>$<ciphertext_plus_tag_base64>
```

После декодирования salt должен иметь 16 байт, IV — 12 байт. Проверка выполняется через PBKDF2-HMAC-SHA256 с 4096 повторениями и AES-256-GCM.

```bash
./METAL_CRYPTO_TOOLKIT -stellarwallet stellar.hash \
  -i passwords.txt -save
```

```text
STELLARWALLET:<source#line>:PASSWORD:<password>:VAULT:<sha256>:PROFILE:stellar-pbkdf2-aes-gcm
```

#### `-blockchainwallet`

**Форматы строк:**

```text
$blockchain$<declared_len>$<hex_blob>
$blockchain$v2$<iterations>$<declared_len>$<hex_blob>
```

Старый профиль использует 10 повторений PBKDF2-HMAC-SHA1, v2 берет число из строки. После AES-256-CBC проверяется, что начало результата похоже на JSON кошелька. В быстрой проверке участвуют только первые 64 декодированных байта blob; объявленная длина не является дополнительной защитной проверкой.

```bash
./METAL_CRYPTO_TOOLKIT -blockchainwallet blockchain.hash \
  -i passwords.txt -save
```

Профиль результата: `blockchain-pbkdf2-sha1-aes-cbc`.

#### `-multibitwallet`

**Форматы строк:**

```text
$multibit$1*<salt_8_bytes_hex>*<data_32_bytes_hex>
$multibit$2*<iv_16_bytes_hex>*<block1_16_bytes_hex>*<block2_16_bytes_hex>
$multibit$3*<N>*<r>*<p>*<salt_8_bytes_hex>*<blob_32_bytes_hex>
```

Тип 1 использует MD5 EVP_BytesToKey и AES-CBC. Тип 2 — Java UTF-16BE, постоянные параметры scrypt `16384/8/1` и AES-CBC. Тип 3 читает параметры scrypt из строки и проверяет padding AES-CBC. Для типов 2 и 3 работают `-wallet-scrypt-mem` и `-n`.

```bash
./METAL_CRYPTO_TOOLKIT -multibitwallet multibit.hash \
  -i passwords.txt -save
```

В результате будет один из профилей: `multibit-classic-md5-aes`, `multibit-hd-scrypt-aes` или `multibit-classic-scrypt-aes`.

#### `-bip38`

Режим восстанавливает пароли и приватные ключи из стандартных BIP38-записей Bitcoin mainnet вида `6P...`. В текстовом файле может быть одна или несколько встроенных Base58Check-строк. Неверные checksum, prefix, flags и длина payload отклоняются до запуска GPU.

Для обоих профилей реализована точная Metal-проверка:

- обычная non-EC запись использует scrypt `16384/8/8`, AES-256-ECB, получение публичного ключа secp256k1, полную сборку P2PKH-адреса и проверку address hash;
- EC-multiply дополнительно учитывает owner salt/entropy, lot/sequence, строит passpoint, выполняет второй scrypt `1024/1/1`, восстанавливает seed/factor и умножает скаляры.

В README встроены официальные BIP38-векторы, которые одновременно служат
исполняемыми correctness fixtures:

```text
6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg
6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo
6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX
6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j
```

Для первых трёх используется пароль `TestingOneTwoThree`, для вектора с
lot/sequence — `MOLON LABE`. Результаты сверяются с опубликованными в BIP38
приватными ключами в точной CPU-to-Metal регрессии.

Детерминированный локальный fixture для маски и диапазона
`6PYWCzYbiDh88rbbQVRFUCdqS51ptYow6EEeKRGFNAWqRG5FC4evLvwJd9` использует
пароль `0` и восстанавливает приватный ключ `3`; это не официальный вектор
BIP38.

Текстовые кандидаты из словаря нормализуются в UTF-8 NFC по требованиям BIP38. `-hex` передает точные байты без нормализации. Маски и raw-диапазоны работают с байтами. `-wallet-mem` ограничивает общий working set кошелька, `-wallet-scrypt-mem MiB` дополнительно ограничивает scratch на устройство, `-n` — число активных scrypt-задач, а `-device` делит ordinal-пространство кандидатов без пересечений. При default или явном `-wallet-mem auto` BIP38 использует до 32 ГиБ scratch, если память доступна; точный размер, процент, `all` и `-wallet-scrypt-mem` остаются строгими пользовательскими пределами.

```bash
./METAL_CRYPTO_TOOLKIT -bip38 encrypted.txt \
  -i passwords.txt -wallet-scrypt-mem 8192 -save

./METAL_CRYPTO_TOOLKIT -bip38 -f bip38_keys \
  -mask "?a?a?a?a?a?a?a?a" -n 256 -device 0 \
  -wallet-mem all -wallet-scrypt-mem 16384 -save -o bip38_found.txt

./METAL_CRYPTO_TOOLKIT -bip38 encrypted.txt \
  -i password-bytes.hex -hex -save
```

В результате записываются исходная строка, пароль, проверенный 64-символьный приватный ключ, вид сжатия, HASH160 и профиль. Статистику печатает только `SpeedThreadFunc`: `KDF/s` означает завершенные BIP38 KDF-задачи, `Verify/s` — полные проверки целей. Количество целей не используется как искусственный множитель скорости.

Целями являются только зашифрованные приватные ключи. Confirmation code и intermediate passphrase code BIP38 не принимаются. После NFC-нормализации словарный пароль должен занимать не более 127 байтов.

#### `-keyrepair`

Режим восстанавливает ограниченное число неизвестных символов в принадлежащем
вам ключевом материале. Через `-repair-type` выбирается ровно один профиль:
`wif`, `xprv`, `xpub`, `address`, `raw-private` или `raw-public`. Символ `?`
означает неизвестный Base58-символ либо hex-полубайт. `-i` можно повторять,
шаблоны можно передавать позиционно или загрузить из текстового файла по одному
на строку; пустые строки и комментарии `#` игнорируются.

Base58Check-кандидаты создаются на Metal, где сначала проверяются структура и
двойной SHA-256 checksum. Raw private сверяется с одним или несколькими полными
33/65-байтовыми публичными ключами secp256k1 из повторяемых `-target` или
target-файлов. Сжатая и несжатая формы одной точки считаются одной целью. Для
raw public выполняется полная проверка точки кривой. Каждый GPU hit заново
собирается и независимо проверяется на host до записи результата.

```bash
./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type wif \
  -i "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoW?" -n 128

./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type raw-private \
  -i "000000000000000000000000000000000000000000000000000000000000000?" \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type address \
  -i "1BoatSLRHtKNngkdXEeobR76b53LETtpy?" -save
```

`-device` делит каждое mixed-radix пространство на детерминированные
непересекающиеся U256-шарды. `-n` управляет только резидентным GPU-окном,
поэтому логический домен может быть шире 64 бит и не требует одного огромного
буфера. При overflow окно повторяется с меньшим размером и засчитывается ровно
один раз. Текущую статистику `Candidate/s` и `Verify/s` печатает только
существующий `SpeedThreadFunc`.

Допускается не более 15 неизвестных позиций. Это режим ограниченного
восстановления, а не неограниченного поиска ключей. Корректный checksum адреса
даёт только адрес и его payload и не доказывает знание приватного ключа.
Поэтому `raw-private` не запускается без связанной public-key цели.

#### `-nonce`

Режим восстанавливает приват secp256k1 только тогда, когда nonce ECDSA/BIP340
уже ограничен, частично известен, связан с другим nonce либо получен внешним
preprocessing. Записи передаются повторяемым `-i` или построчным файлом;
пустые строки и комментарии `#` игнорируются.

Формат ECDSA: `ecdsa:R:S:Z[:PUBKEY]`. Формат BIP340:
`bip340:SIGNATURE64:MESSAGE32[:PUBKEY_X]`. Если public key не указан внутри
записи, передайте один общий `-target` либо по одной цели на каждую запись.
ECDSA принимает полные 33/65-байтовые ключи, BIP340 — также 32-байтовый
x-only ключ.

```bash
./METAL_CRYPTO_TOOLKIT -nonce -i signatures.txt \
  -start 1 -end 0x1000000 -n 1048576

./METAL_CRYPTO_TOOLKIT -nonce -i signature.txt \
  -mask "000000000000000000000000000000000000000000000000000000000000????"

./METAL_CRYPTO_TOOLKIT -nonce -nonce-model bip340 -i schnorr.txt \
  -target signer_xonly.txt -nonce-lattice lattice_candidates.txt

./METAL_CRYPTO_TOOLKIT -nonce -i related.txt \
  -nonce-relation affine:3:7
```

`-start/-end` задают точный диапазон с исключённой верхней границей. `-mask`
принимает 64 hex/`?` полубайта либо 256 двоичных символов `0`/`1`/`?`.
`-nonce-candidates` и его alias `-nonce-lattice` загружают точные scalar-
кандидаты по одному на строку. `-random` применяет seed-зависимую биекцию к
диапазону и меняет порядок без повторов и пропусков. `-device` делит checked
U256 ordinal-space на непересекающиеся шарды, а `-n` управляет только
резидентным окном.

Одинаковый ECDSA `r` автоматически проверяется для случаев `k2=k1` и
`k2=-k1 mod n`. Для первых двух записей
`-nonce-relation same|add:B|mul:A|affine:A:B` напрямую решает
`k2=A*k1+B`. Каждый GPU hit заново собирается и сверяется с `R`, уравнением
подписи и заданным public key до вывода. Текущие `Nonce/s` и `Verify/s`
печатает только существующий `SpeedThreadFunc`.

Режим не делает равномерный случайный 256-битный nonce практически
перебираемым. Общая hidden-number/lattice редукция остаётся внешним CPU-
preprocessing; полученные кандидаты затем можно передать в точный Metal-контур
проверки.

#### `-aezeed`

Режим восстанавливает пароль стандартного LND aezeed/cipherseed из 24 слов.
Передайте mnemonic напрямую либо файл с одной фразой на строку. Parser
использует точный английский список BIP39, external version 0 и CRC32C.
Отдельный `?` или `*` восстанавливает неизвестное целое слово; разрешено не
более двух неизвестных позиций.

```bash
./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt

./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt \
  -pass passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -aezeed \
  -recovery "above judge emerge veteran reform crunch system all snap please shoulder vault hurt city quarter cover enlist swear success suggest drink wagon enrich body" \
  -entropy 81b637d86359e6960de795e41e0b4cfd

./METAL_CRYPTO_TOOLKIT -aezeed -recovery damaged.txt \
  -target root_public_keys.txt -mask "secret?d?d" \
  -wallet-mem all -device 0
```

`-pass` принимает literal либо существующий файл, а `-i` всегда потоково
читает словарь. `-mask` поддерживает `?d/?l/?u/?a/??`; `-start/-end`
генерируют точные десятичные строки с checked U256-счётчиком. Без источника
паролей проверяется стандартный пароль LND `aezeed`.

Необязательный `-target` задаёт `SHA256(entropy)` либо полный 33/65-байтовый
secp256k1 public key BIP32-root; `-entropy` принимает точную 16-байтовую
entropy кошелька. Если цели нет, доказательством восстановления служат
аутентифицированный AEZ tag и известная internal version LND.
`-wallet-mem` следует общим правилам unified memory Apple,
`-wallet-scrypt-mem` может задать меньший предел только для scratch. Каждый
активный scrypt lane v0 требует примерно 32 MiB, поэтому `-n` управляет
резидентной параллельностью, а не общим размером поиска.

Поддерживаются только container version 0 и internal derivation version 0/1.
Пароль должен быть printable ASCII короче 128 байтов. Поддержка формата не
ослабляет scrypt и не делает полный перебор случайного сильного пароля
практически выполнимым.

#### `-stronghold`

Режим восстанавливает пароль поддерживаемых snapshot IOTA Stronghold v2 и
Tauri Stronghold. Передайте один или несколько файлов после `-stronghold` либо
используйте `-f` для сканирования каталога. Parser принимает только точный
заголовок `PARTI` с байтами версии `02 00`.

```bash
./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile blake2b -pass passwords.txt -save

./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile argon2id -stronghold-salt stronghold.salt \
  -i passwords.txt -wallet-mem auto

./METAL_CRYPTO_TOOLKIT -stronghold vault.stronghold \
  -profile tauri-argon2id \
  -stronghold-salt 00112233445566778899aabbccddeeff \
  -mask "secret?d?d" -target plaintext.sha256 \
  -wallet-mem all -device 0
```

Обязательный профиль выбирается из:

- `blake2b`: Blake2b-256 от пароля;
- `argon2id`: стандарт rust-argon2, Argon2id v19 с `m=19456 KiB`, `t=2`,
  `p=1` и 32-байтовым результатом;
- `tauri-argon2id`: опубликованный пример Tauri, Argon2id v19 с
  `m=10000 KiB`, `t=10`, `p=4` и 32-байтовым результатом.

Argon2-профилям нужен `-stronghold-salt`. Существующий файл читается как
точные raw bytes, сохранённые приложением; значение, не являющееся файлом,
декодируется как hex. `-pass` принимает literal либо существующий текстовый
файл, `-i` потоково читает словарь, `-mask` поддерживает `?d/?l/?u/?a/??`, а
`-start/-end` генерируют десятичные строки с checked U256-счётчиком.

По умолчанию доказательством восстановления служит аутентифицированное
XChaCha20-Poly1305 расшифрование с успешной точной Stronghold
LZ4-декомпрессией. `-target` может дополнительно задать один или несколько
`SHA256(decompressed snapshot plaintext)`. Каждый Metal-кандидат до вывода
полностью перепроверяется на host через X25519, authentication, decompression
и target matching.

`-wallet-mem auto|all|NN%|SIZE` управляет бюджетом unified memory Apple;
`-wallet-scrypt-mem` остаётся совместимым более строгим пределом KDF scratch,
а `-n` ограничивает число резидентных jobs, но не весь поиск. Snapshot не
хранит внешний KDF и salt приложения, поэтому неизвестные/custom-профили
нельзя надёжно угадывать — они отклоняются. Поддержка точных форматов не
делает полный перебор сильного неизвестного пароля практически выполнимым.

#### `-bisqwallet`

**Рабочий формат:**

```text
$bisq$3*<N>*<r>*<p>*<salt_8_bytes_hex>*<blob_32_bytes_hex>
```

Первые 16 байтов `blob_32_bytes_hex` являются IV, следующие 16 байтов — шифротекстом. Пароль переводится в UTF-16BE, затем выполняются scrypt и проверка padding AES-CBC. `-wallet-scrypt-mem` ограничивает промежуточную память. Метки `$bisq$1` и `$bisq$2` распознаются, но их проверка в v14 не включена.

```bash
./METAL_CRYPTO_TOOLKIT -bisqwallet bisq.hash \
  -i passwords.txt -save
```

#### `-dogechainwallet`

**Формат строки:**

```text
$dogechain$0*<iterations>*<payload_base64>*<salt_base64>
```

Сначала вычисляется SHA-256 пароля, хеш переводится в Base64, затем выполняются PBKDF2-HMAC-SHA256 и проверка расшифрованных AES-CBC байтов/padding.

```bash
./METAL_CRYPTO_TOOLKIT -dogechainwallet dogechain.hash \
  -i passwords.txt -save
```

Профиль результата: `dogechain-sha256b64-pbkdf2-aes-cbc`.

#### `-ethpresale`

**Что загружается:** JSON предварительной продажи Ethereum с полями `encseed`, `ethaddr`, `bkp` либо строка:

```text
$ethereum$w*<encseed_hex>*<eth_address_20_bytes_hex>*<bkp_16_bytes_hex>
```

Для каждого пароля выполняются PBKDF2-HMAC-SHA256(password, password, 2000), AES-128-CBC, проверка padding и backup-поля, получение привата через Keccak и полная проверка адреса Ethereum.

```bash
./METAL_CRYPTO_TOOLKIT -ethpresale presale.json \
  -i passwords.txt -save
```

```text
ETHPRESALE:<source>:PASSWORD:<password>:PRIV:<64_hex>:ETH:<0x_address>
```

#### `-androidwallet`

**Рабочий формат:**

```text
$ab$<version>*<cipher>*<iterations>*<user_salt>*<ck_salt>*<user_iv>*<masterkey_blob>
```

После hex-декодирования salts имеют по 64 байта, IV — 16 байт, masterkey blob — 96 байт. Текущий маршрут командной строки поддерживает cipher type 0 и проверяет PBKDF2-HMAC-SHA1 вместе с хвостом AES-CBC. Protobuf-файлы bitcoinj относятся к `-bitcoinjwallet`, а не к этому режиму.

`ck_salt` и отдельный `user_iv` разбираются и проверяются по длине. Активная проверка получает ключ из `user_salt`, а IV и хвост шифротекста берет из `masterkey_blob`; программа извлечения должна сохранять эти поля без изменений.

```bash
./METAL_CRYPTO_TOOLKIT -androidwallet android_backup.hash \
  -i passwords.txt -save
```

Профиль результата: `android-backup-pbkdf2-sha1-aes-cbc`.

#### `-eth2validator`

`-eth2validator` содержит два точных GPU-контура для ключей Ethereum-валидаторов:

- восстановление пароля EIP-2335 v4 с PBKDF2-HMAC-SHA256 или scrypt, проверкой пароля через SHA-256, AES-128-CTR и полной проверкой BLS12-381 публичного ключа;
- проверка BIP39-мнемоники или исходного seed через EIP-2333 и путь EIP-2334.

Перед KDF пароль приводится к NFKD, из него удаляются управляющие коды C0/C1/DEL, затем строка кодируется в UTF-8. Keystore можно передать позиционно после режима или повторяемым `-keystore`. Источник паролей задаётся через `-i`, `-pass`, `-mask` либо числовые `-start/-end`.

```bash
./METAL_CRYPTO_TOOLKIT -eth2validator validator-keystore.json \
  -i passwords.txt -wallet-mem auto -save

./METAL_CRYPTO_TOOLKIT -eth2validator -keystore validator.json \
  -mask "secret?d?d" -wallet-mem all
```

В контуре деривации `-target` принимает один 48-байтовый сжатый BLS-публичный ключ или файл с ключом в каждой строке. Путь signing key по умолчанию — `m/12381/3600/0/0/0`; другой точный путь задаётся через `-path`. Здесь `-i` означает файл мнемоник.

```bash
./METAL_CRYPTO_TOOLKIT -eth2validator -i mnemonics.txt \
  -target validator_pubkeys.txt -path m/12381/3600/0/0/0

./METAL_CRYPTO_TOOLKIT -eth2validator -seed seed.hex \
  -target PUBKEY -path m/12381/3600/0/0
```

Резидентностью Metal управляют `-wallet-mem auto|all|NN%|SIZE`, `-wallet-scrypt-mem`, `-n` и `-device`. На Apple Silicon unified memory рассчитывается из свободной части recommended working set; при тяжёлом scrypt число одновременно активных кандидатов может уменьшиться до одного. Статистику печатает только общий `SpeedThreadFunc`: завершённые `KDF/s`, фактические KDF-операции, точные BLS-проверки, состояние целей, working set и readback.

Принимаются только файлы версии 4 с поддерживаемыми модулями EIP-2335. Мнемоники должны быть checksum-valid English BIP39. Перестановки неизвестных слов нужно заранее сформировать другим режимом или файлом. Каждый GPU-hit перед выводом независимо проверяется через SHA-256, AES-CTR и BLS-публичный ключ.

#### `-chia`

`-chia` ищет Chia-ключи по checksum-valid English BIP39
mnemonic/passphrase-кандидатам или raw seed длиной 32–64 байта. Повторяемый
`-target` принимает 48-байтовый сжатый BLS public key, 32-байтовый
standard-wallet puzzle hash, checksum-valid адрес `xch`/`txch` либо файл с
одной целью в строке. Дубликаты вычисляются один раз, но все исходные ссылки
сохраняются.

Встроенные профили путей: `farmer`, `pool`, `wallet`,
`wallet-observer` (по умолчанию), `local`, `backup`, `singleton` и
`pool-auth:N`. Пользовательский `-path-template` начинается с `m/`, суффикс
`n` обозначает hardened-компонент и допускается один placeholder `{index}`.
Его интервал `[START,END)` задаётся через `-start/-end`.

```bash
./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt \
  -target farmer_pubkey.txt -path-template farmer -save

./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt -pass passes.txt \
  -target xch_addresses.txt -path-template wallet-observer \
  -start 0 -end 100 -wallet-mem auto

./METAL_CRYPTO_TOOLKIT -chia -seed seed.hex \
  -target puzzle_hashes.txt -path-template wallet -start 0 -end 50

./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt -target targets.txt \
  -path-template "m/12381n/8444n/2n/{index}n" \
  -wallet-mem all -device 0
```

`-wallet-mem auto|all|NN%|SIZE` ограничивает working set unified memory Apple
Silicon. `auto` использует не более половины текущей свободной recommended
working set и может уменьшить resident batch после ошибки allocation; `all`
оставляет 512 MiB для runtime. `-n` выбирает resident batch от 1 до 16384,
большие логические входы обрабатываются окнами. Список Metal-устройств задаёт
`-device`; каждый завершённый ordinal принадлежит ровно одному устройству.

PBKDF2-HMAC-SHA512 seed generation выполняется на Metal. Chia BLS
master/child derivation, проверка сжатого ключа и standard puzzle затем точно
распределяются по доступным CPU-ядрам host. Единственным потоком статистики
остаётся общий `SpeedThreadFunc`: он показывает завершённые `KDF/s`, PBKDF2
primitive rounds, точные BLS checks, logical/resident/solved targets, readback
и фактически выделенный working set. Количество целей не умножает скорость.

Исторический Chia KeyGen v3 намеренно отделён от финального EIP-2333 KeyGen,
который использует `-eth2validator`. Проверка standard puzzle покрывает только
канонический `p2_delegated_puzzle_or_hidden_puzzle`; произвольные Chialisp
puzzles, xpub-only recovery и генерация перестановок неизвестных слов в этот
режим не входят. Большие интервалы индексов остаются вычислительно дорогими.

### Инвентаризация и каталоги

#### `-walletscan`

`-walletscan` просматривает файлы на CPU и выполняет ограниченную инвентаризацию сигнатур и похожих на секреты записей. Он не создает пароли, не запускает KDF-перебор и не доказывает, что любой найденный файл является корректным и полным кошельком.

Режим умеет находить поддерживаемые WIF, xprv/xpub, кандидаты мнемоник, признаки SECO, записи Armory и признаки protobuf-кошельков. Часть записей проверяется криптографически, а часть только классифицируется по реализованным для ее типа признакам. Файлы пишутся сразу после режима либо собираются через `-f DIR`. При просмотре папки учитываются `.txt`, `.json`, `.dat`, `.wallet`, `.ldb`, `.log`, `.seco` и файлы без расширения. Словари `-i`, маски, диапазоны и генераторы намеренно отклоняются.

```bash
./METAL_CRYPTO_TOOLKIT -walletscan -f wallet_copies \
  -save -o wallet_inventory.txt
```

Фактический порядок полей:

```text
WALLETSCAN:<source_file>:<type>:LINE:<line_number>:VALUE:<value>
```

В найденном могут оказаться открытые секреты. Добавьте `-silent`, если их нельзя печатать в терминал.

#### `-prng_help` и `-prng64_help`

Печатают полный список генераторов и способов извлечения байтов, затем завершают работу. Сам поиск не запускается.

## Краткий указатель параметров

Это памятка. Допустимые сочетания для конкретного режима всегда проверяйте через `<режим> -help`.

| Группа | Параметры |
| --- | --- |
| справка | `-h`, `-help` |
| вход | `-i`, `-f`, `-all`, `-hex`, `-delete`, `-comb`, `-space`, `-rep` |
| последовательность | `-start`, `-end`, `-step`, `-endstep`, `-plusstep`, `-addplusstep`, `-back`, `-both`, `-random`, `-n` |
| шаблоны | `-recovery`, `-poetry`, `-hexset`, `-wordlist` |
| преобразования | `-iter`, `-utf8`, `-text`, `-size`, `-sizes`, `-w`, `-lang`, `-dub`, `-electrum`, `-128`, `-ton`, `-TON`, `-pbkdf`, `-round` |
| BIP-39 и пути | `-pass`, `-passbrute`, `-pass_thread`, `-der_thread`, `-d`, `-d-type`, `-d-dot` |
| цели | `-c`, параметры вариантов сетей, `-hash`, `-target`, `-bf`, `-xu`, `-xc`, `-xuc`, `-xh`, `-xx`, `-xb`, `-full` |
| PRNG | `-prng`, `-prng64`, `-gen`, `-mode`, `-byte`, `-shift`, `-s`, `-e`, `-random`, `-log` |
| priv | `-pb`, `-last`, `-scalar`, `-LE`, `-shash`, `-legacy`, `-em`, `-keys`, `-chunk` |
| Profanity | `-offset`, `-random-seeds`, `-gpu-split` |
| XP/WalletJS | `-once`, `-v`, `-time-s`, `-time-e`, `-time-delta`, `-time-events`, `-time-events-repeat`, `-time-mode`, `-screen-seed`, `-screen-seed-zero`, `-mileage`, `-mileage-s`, `-mileage-e` и варианты конкретных профилей |
| кандидаты паролей | `-mask`, `-mask-file`, `-cs1`, `-cs2`, `-cs3`, `-cs4` |
| кошельки | `-wallet-load-only`, `-wallet-dry-run`, `-wallet-mem`, `-wallet-scrypt-mem`, `-scan-all`, `-walletdat-max-ckey`, `-walletdat-kdf-work`, `-walletdat-max-iter`, `-walletdat-min-jobs`, `-walletdat-kdf-loop` |
| Metal и вывод | `-device`, `-b`, `-t`, `-bit`, `-fsize`, `-save`, `-o`, `-silent` |

`-iteration` не является активным параметром. `-pubkey` намеренно отклоняется как устаревший.

## Форматы входных и выходных файлов

### Обычные файлы кандидатов

- одна логическая запись в строке;
- CR/LF нормализуется подходящим загрузчиком;
- не добавляйте комментарии, если формат прямо их не разрешает;
- значения с пробелами и специальными знаками оболочки заключайте в кавычки;
- добавляйте `-hex` только тогда, когда каждая строка действительно должна декодироваться в байты.

### Пути

- один путь в строке;
- BIP-путь обычно начинается с `m`;
- hardened-компоненты помечаются знаком `'`;
- SURI Substrate находится в отдельном файле `-d-dot`.

### Шаблоны

- mnemonic recovery: одна фраза в строке, один отдельный `*` на каждое неизвестное слово;
- hex-recovery внутри режима: один `*` на неизвестную позицию, символы берутся из `-hexset`;
- priv recovery: ровно 64 hex-позиции.

### Найденные записи

Режимы генерации ключей сохраняют исходный/созданный кандидат, точный путь или состояние генератора, приват/скаляр, тип цели и совпавшее значение. У кошельков используются явные префиксы, приведенные выше.

Файл результатов содержит секреты открытым текстом, если поле не обозначено как отпечаток. Перед запуском можно запретить доступ другим пользователям:

```bash
umask 077
./METAL_CRYPTO_TOOLKIT ... -save -o private_results.txt
```

<a id="support-the-project-ru"></a>

## Поддержать проект

Если программа оказалась полезной, вы можете поддержать дальнейшую разработку переводом в криптовалюте. Отправляйте средства только через сеть, указанную в той же строке: перевод через несовместимую сеть невозможно вернуть.

```text
ETH:    0xDE85c1Ef7874A1D94578f11332e8fa9A6a0eE853
BTC:    bc1q063pks7ex93eka56zyumvutdt6zs9dj959pe9p
LTC:    ltc1qysumht4lxafwvmcu4ruxzuztc2xmj8tz986fmm
TRX:    TTZ3oL16BVNzU46MSJvaoKYAhvtwdTUcnz
TON:    UQC7eqLN_NlVz82YzsjzAo4iOzKjH3t095-CMtqTJ5aoqo0l
DOT:    1jen89F5v6TbdQsRaKxsCqhNp9qAdeHeZyEUWjgrM8mW6hs
ADA:    addr1qx7qrlcy37xe7j58hjxmyhyqfgu0ppeqxzs43dayjjcgde973lzxgtgqzxdvfq3rswmngapc4sp528dpzfg7huam8v9san7h6z
DASH:   Xms41jaD967XMf2FAfEwGUxYKKhYQuok9T
SOLANA: BvDQDEgq3kbNT7VQFQRQPjc4Ta5k7d5s7GdcgoKnq3KG
```

## Решение частых проблем

### `Metal Toolchain component is missing`

```bash
sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
xcodebuild -downloadComponent MetalToolchain
make clean
make -j"$(sysctl -n hw.ncpu)"
```

### `Metal library load failed: library not found`

Запускайте итоговый `./METAL_CRYPTO_TOOLKIT` или `./bin/METAL_CRYPTO_TOOLKIT`, а не промежуточный объект. Наличие встроенной секции можно проверить так:

```bash
otool -l ./METAL_CRYPTO_TOOLKIT | grep -A3 __metallib
```

### Известная цель не находится

Проверяйте по порядку:

1. основной режим;
2. не меняет ли `-hex` реальные байты кандидата;
3. путь и `-d-type`;
4. passphrase BIP-39, включая пустую;
5. букву `-c` и вариант сети;
6. является ли цель двоичным hex, а не напечатанным адресом;
7. начинается ли `-hash` с первого байта цели и помещается ли в проверку этого режима: не более 20 байтов для обычного пути либо не более настоящей длины сравниваемого значения и 32 байтов для режима с отдельной длинной проверкой;
8. длину, представление и семейство фильтра;
9. compressed/uncompressed вариант открытого ключа;
10. особый формат сравнения P2WSH;
11. не относится ли выбранный режим к выключенным.

Сначала сократите команду до одного заранее известного кандидата и одной прямой цели. Только после этого подключайте большой фильтр.

### Конвертер отклоняет адрес или готовый фильтр не находит цель

- откройте созданный файл `*-invalid.txt`: в нем находятся исходные строки, которые не прошли проверку;
- проверьте, не появился ли пробел внутри адреса, не повреждена ли checksum, поддерживается ли префикс сети и не потерян ли один символ;
- храните в одном файле значения одной длины. Поддерживаемые печатные Bitcoin-подобные адреса дают 20-байтовые значения сравнения, а явно переданный raw hex длиной 32 байта остается 32-байтовым и будет отклонен после 20-байтового результата;
- у `base64_data_to_hex` и `solana_address_to_hex` нет возможности проверить checksum: сами входные форматы ее не содержат;
- передавайте в XorFilter полученный hex, а не исходный напечатанный адрес;
- выбирайте соответствующую букву `-c`. Одинаковая длина значений разных валют не делает их взаимозаменяемыми;
- фильтры P2WSH и Taproot строятся из созданных конвертером 20-байтовых RIPEMD-160. Несмотря на одинаковую длину, эти два семейства целей нужно хранить в разных файлах и фильтрах;
- при сборке из исходников запускайте `tools/<проект>/bin/<программа>`. Короткий путь `tools/<программа>` используется в готовом архиве tools.

Сначала пропустите через конвертер один заранее известный адрес и проверьте его на коротком диапазоне. Большой фильтр создавайте только после этого.

### Не хватает памяти или процесс завершает система

- верните автоматическую сетку;
- уберите ненужные семейства целей и фильтры;
- не увеличивайте `-fsize` без необходимости;
- уменьшите `-wallet-scrypt-mem` или `-n` в scrypt/KdfRomix;
- сначала посмотрите объем работы через `-wallet-load-only`;
- никогда не используйте `-full` на открытом диапазоне.

### Файл кошелька пропускается

Передайте его явно после имени режима: так предупреждение обычно понятнее, чем при рекурсивном просмотре папки. Проверьте расширение и точный формат извлеченной строки. `-walletscan` показывает содержимое/тип, но не подбирает пароль.

### Повторяющиеся или перемешанные строки

Новый запуск добавляет строки к старому файлу. Несколько устройств и фоновые очереди могут записывать готовые пакеты в разном порядке. Внутри каждой записи остаются ее номера и путь, но общей сортировки нет.

### macOS не разрешает запуск

Сначала проверьте репозиторий и происхождение архива, затем снимите карантин:

```bash
xattr -d com.apple.quarantine METAL_CRYPTO_TOOLKIT
```

## Устройство репозитория

| Путь | Назначение |
| --- | --- |
| `main.mm` | разбор командной строки, запуск режимов, чтение входных данных и файлов кошельков |
| `MetalRuntime.*`, `MetalBackend.*` | устройства Metal, буферы, команды и загрузка встроенной библиотеки |
| `Kernel.h`, `KernelRuntime.h` | общие объявления и фиксированные структуры данных |
| `SaveFunc.mm` | получение результатов, форматирование, дополнительная проверка и фоновые очереди записи |
| `Kernels/` | по одной входной функции Metal в каждом `.metal` и отдельные helpers в `.metalh` |
| `lib/`, `host_secp/`, `sr25519-donna-32bit/` | хеши, кодирование, кривые и проверка на CPU |
| `tools/common/` | общие строгие декодеры, checksum, хеши, упорядоченное чтение и командная строка конвертеров |
| `tools/<конвертер>/` | отдельная программа преобразования адресов со своими `Source.cpp` и `Makefile` |
| `tools/profanity_basepoint_generator/` | оптимизированный генератор полного списка базовых точек Profanity для macOS |
| `tools/Makefile` | сборка и очистка 14 конвертеров и генератора Profanity |
| `Makefile` | самостоятельная сборка для macOS, встраивание библиотеки Metal и отдельные цели `tools` |
