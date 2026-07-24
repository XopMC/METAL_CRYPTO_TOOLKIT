# <img src="assets/apple.svg" alt="Apple" width="32" height="32"> METAL_CRYPTO_TOOLKIT <img src="assets/apple.svg" alt="Apple" width="32" height="32">

<p align="center">
  <a href="#english"><strong>English</strong></a> |
  <a href="#russian"><strong>Русский</strong></a>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS%2015%2B-111827?style=for-the-badge">
  <img alt="Architecture" src="https://img.shields.io/badge/architecture-Apple%20Silicon-0f766e?style=for-the-badge">
  <img alt="GPU API" src="https://img.shields.io/badge/GPU-Metal%203-2563eb?style=for-the-badge">
  <img alt="Version" src="https://img.shields.io/badge/version-v15-b45309?style=for-the-badge">
  <a href="#support-the-project"><img alt="Sponsor" src="https://img.shields.io/badge/Sponsor-Support%20development-EA4AAA?style=for-the-badge&amp;logo=githubsponsors&amp;logoColor=white"></a>
</p>

Author: Mikhail Khoroshavin, also known as **XopMC**

<a id="english"></a>

## English

### Changelog

#### v15

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
  Search uses the CUDA-compatible names `GStep/s` and `EqKey/s`; the Metal
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
- recover a secp256k1 private key with `-kangaroo` when the complete public key and a bounded scalar interval are known;
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

#### Ready-to-run v15 release

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

Download these two files from the [v15 release](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v15):

- `METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz.sha256`

The same release also contains the optional address-conversion package:

- `METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz.sha256`

It is needed only when printable cryptocurrency addresses must be converted into the homogeneous hexadecimal lists accepted by filter builders. It does not contain or replace the main Toolkit executable.

Then run:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz
chmod +x METAL_CRYPTO_TOOLKIT
./METAL_CRYPTO_TOOLKIT -help
```

To install the optional converter package:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz
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
| `-gen` | IDs `1..331` | IDs `1..220` |
| `-mode` | IDs `1..246` | IDs `1..217` |
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

The mode requires exactly one 33-byte compressed or 65-byte uncompressed
secp256k1 public key. An address, HASH160, Ethereum address, x-only public key,
Bloom filter, or XOR filter is not enough because the algorithm needs the
complete curve point. Kangaroo writes a verified result directly through `-o`;
ordinary target-family switches such as `-c`, `-save`, and `-i` do not belong
to this mode.

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
| `-target HEX` / `-hash HEX` | one complete compressed or uncompressed secp256k1 public key; the names are aliases |
| `-range VALUE` | one or more bit ranges, or one exact hexadecimal interval |
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

The result block contains `Pub`, `Exps`, `Pub after subtract`, `k_low`, and
`priv`. `priv` is the final verified private scalar. Cache formats PSWDP2 and
PSWDP3 remain compatible with CUDA/RCKangaroo through 170-bit distances.
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

Every candidate is checked against the complete target point before it is
printed. Full 256-bit counters and endpoints prevent truncation, but they do
not make an exhaustive 256-bit discrete-log search practical on current
hardware.

Full built-in help:

```bash
./METAL_CRYPTO_TOOLKIT -bsgs -help
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

```bash
./METAL_CRYPTO_TOOLKIT -brain -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
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
| `-wallet-scrypt-mem MiB` | scratch-memory cap for modes that actually use scrypt/KdfRomix |

The automatic scrypt scratch target starts at 16384 MiB. When the total input size of the regular GPU filters reaches 8 GiB, the target falls back to 4096 MiB. The final allocation is also bounded by available unified memory and the scratch size of one job. `-wallet-scrypt-mem` has a performance effect only in the modes explicitly identified below.

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

## Reserved or inactive in v14

The following command names are parsed or documented for future/external compatibility, but must not be used as working recovery modes in v14:

- `-bip38`: metadata parsing for non-EC and EC-multiply records exists, but the compute and verification path is disabled in this build; it cannot emit a confirmed password;
- `-slip39`: exact SLIP-39 share reconstruction worker is not enabled;
- `-aezeed`: exact LND aezeed decode/KDF worker is not enabled;
- `-eth2validator`: exact validator-key derivation worker is not enabled.

The program stops or cannot produce a confirmed result for these modes. Do not interpret a run with no result as proof that a password is absent.

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
| wallet runtime | `-wallet-load-only`, `-wallet-dry-run`, `-wallet-scrypt-mem`, `-scan-all`, `-walletdat-max-ckey`, `-walletdat-kdf-work`, `-walletdat-max-iter`, `-walletdat-min-jobs`, `-walletdat-kdf-loop` |
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

#### v15

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
  используются совместимые с CUDA названия `GStep/s` и `EqKey/s`; Metal
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
- восстанавливать приват secp256k1 через `-kangaroo`, когда известны полный публичный ключ и ограниченный диапазон скаляра;
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

#### Готовый выпуск v15

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

На странице [выпуска v15](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v15) загрузите:

- `METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz`;
- `METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz.sha256`.

Там же находится необязательный набор программ для преобразования адресов:

- `METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz`;
- `METAL_CRYPTO_TOOLKIT-tools-v15-macos-arm64.tar.gz.sha256`.

Он нужен только тогда, когда обычные адреса криптовалют требуется превратить в однородные списки hex для последующего создания фильтров. Основной исполняемый файл Toolkit в этот архив не входит.

Положите оба файла в одну папку и выполните:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v15-macos-arm64.tar.gz
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
| `-gen` | номера `1..331` | номера `1..220` |
| `-mode` | номера `1..246` | номера `1..217` |
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

Режиму нужен ровно один полный сжатый публичный ключ длиной 33 байта либо
несжатый ключ длиной 65 байтов. Адрес, HASH160, Ethereum address, x-only
public key, Bloom-фильтр или XOR-фильтр недостаточны: алгоритму нужна полная
точка кривой. Найденный результат после точной проверки записывается через
`-o`; обычные параметры семейств целей `-c`, `-save` и `-i` к этому режиму
не относятся.

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
| `-target HEX` / `-hash HEX` | один полный compressed или uncompressed публичный ключ secp256k1; имена являются алиасами |
| `-range VALUE` | один или несколько битовых диапазонов либо один точный hex-интервал |
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

Результат содержит `Pub`, `Exps`, `Pub after subtract`, `k_low` и `priv`.
Поле `priv` — итоговый проверенный приватный скаляр. Кеши PSWDP2 и PSWDP3
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

Каждый кандидат полностью сверяется с исходной точкой до вывода. 256-битные
счётчики и границы исключают усечение, но не делают полный 256-битный
дискретный логарифм практически выполнимым на современном железе.

Полная встроенная справка:

```bash
./METAL_CRYPTO_TOOLKIT -bsgs -help
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

```bash
./METAL_CRYPTO_TOOLKIT -brain -i phrases.txt -c c \
  -hash 00112233445566778899aabbccddeeff00112233 -save
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
| `-wallet-scrypt-mem MiB` | ограничивает промежуточную память только в режимах, где реально используется scrypt/KdfRomix |

Автоматический предел памяти для scrypt сначала ориентируется на 16384 МиБ. Когда суммарный размер входных данных обычных GPU-фильтров достигает 8 ГиБ, ориентир снижается до 4096 МиБ. Итоговый буфер дополнительно ограничивается свободной объединенной памятью и размером одного задания. Если конкретный формат ниже не отмечен как scrypt/KdfRomix, `-wallet-scrypt-mem` не ускорит и не изменит его проверку.

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

## Зарезервировано или выключено в v14

Следующие имена распознаются командной строкой или оставлены для совместимых форматов, но не являются рабочими режимами восстановления в v14:

- `-bip38`: разбор обычных и EC-multiply записей существует, но вычислительная проверка в этой сборке выключена; подтвержденный пароль получить нельзя;
- `-slip39`: точная сборка долей SLIP-39 не включена;
- `-aezeed`: точная обработка LND aezeed и KDF не включена;
- `-eth2validator`: точная деривация ключей валидатора не включена.

Отсутствие результата в этих режимах не доказывает, что проверяемого пароля нет.

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
| кошельки | `-wallet-load-only`, `-wallet-dry-run`, `-wallet-scrypt-mem`, `-scan-all`, `-walletdat-max-ckey`, `-walletdat-kdf-work`, `-walletdat-max-iter`, `-walletdat-min-jobs`, `-walletdat-kdf-loop` |
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
