# <img src="assets/apple.svg" alt="Apple" width="32" height="32"> METAL_CRYPTO_TOOLKIT <img src="assets/apple.svg" alt="Apple" width="32" height="32">

<p align="center">
  <a href="#english"><strong>English</strong></a> |
  <a href="#russian"><strong>Русский</strong></a>
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS%2015%2B-111827?style=for-the-badge">
  <img alt="Architecture" src="https://img.shields.io/badge/architecture-Apple%20Silicon-0f766e?style=for-the-badge">
  <img alt="GPU API" src="https://img.shields.io/badge/GPU-Metal%203-2563eb?style=for-the-badge">
  <img alt="Version" src="https://img.shields.io/badge/version-v13-b45309?style=for-the-badge">
  <a href="#support-the-project"><img alt="Sponsor" src="https://img.shields.io/badge/Sponsor-Support%20development-EA4AAA?style=for-the-badge&amp;logo=githubsponsors&amp;logoColor=white"></a>
</p>

Author: Mikhail Khoroshavin, also known as **XopMC**

<a id="english"></a>

## English

### What this program is

`METAL_CRYPTO_TOOLKIT` is a command-line toolkit for authorized cryptocurrency wallet recovery and key-generation research on Apple Silicon. The computational work runs on the Apple GPU through Metal.

The program can:

- process BIP-39 mnemonics, entropy, seed bytes, BIP32 master material, derivation paths, BIP-39 passphrases, and several legacy seed formats;
- check secp256k1, ed25519, and sr25519 results for Bitcoin, Ethereum, TON, Solana, Polkadot/Substrate, Cardano, Filecoin, IOTA, Aptos, Sui, XRP, ICP, and Tezos;
- search direct values or large target collections stored in Bloom and XOR filters;
- examine raw private-key ranges, incomplete hexadecimal templates, Casascius minikeys, and known historical generator families;
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

### Requirements

#### Ready-to-run v13 release

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

Download these two files from the [v13 release](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v13):

- `METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz`
- `METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz.sha256`

Then run:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz
chmod +x METAL_CRYPTO_TOOLKIT
./METAL_CRYPTO_TOOLKIT -help
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

### Help system

Show the main mode list:

```bash
./METAL_CRYPTO_TOOLKIT -h
./METAL_CRYPTO_TOOLKIT -help
```

Show the detailed help for a mode:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -help
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
| `r` | secp256k1 | Bitcoin Taproot output-key value |
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

In v13, the raw `-priv` and private Vanity-walk kernels use the ordinary 20-byte comparison even for a 32-byte output such as `-c x`. In those private-key paths, a direct `-hash` longer than 20 bytes cannot match. Some other modes explicitly compare longer values and can use up to 32 bytes.

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
XorFilter -i btc_compressed_hash160.txt -o btc_c.xor_c -compress -check
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff \
  -c c -xc btc_c.xor_c -save -o found.txt
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

## Output, buffers, and devices

### Result formatting and file output

| Argument | Meaning |
| --- | --- |
| `-save` | In key and derivation searches, format the matched binary payload as a cryptocurrency address where that target type has an address representation. In the specialized modes listed below, it also enables writing their result records to the output file. |
| `-o FILE` | Select the output file. Default: `result.txt`. |
| `-silent` | Suppress found lines on the terminal. It does not change the mode-specific file behavior described below. |
| `-fsize N` | Result slots per device. Default: `150000`. |

For `-mnemonic`, `-recovery`, `-entropy`, `-seed`, `-hmac`, `-bip32`, `-der_thread`, `-pass_thread`, `-priv`, `-minikeys`, `-brain`, old Electrum, and Armory key-search flows, the result file is opened in append mode and every match is written even when `-save` is absent. The flag does not validate or confirm a candidate and it does not change target matching. It changes only the final representation:

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

**Use it for:** recovering a key from a known public key produced by the vulnerable Profanity process.

`-target` must contain a 33-byte compressed or 65-byte uncompressed public key. The recovery path requires at least one compatible GPU XOR basepoint filter. In file mode, `-i` accepts:

```text
<public_key_hex>
<public_key_hex>:<offset_hex>
<public_key_hex>:<offset_hex>:found
```

The third form marks a previously solved line for restartable batches. `-n` is the per-file round/window size (default 16384); single-target `-offset` defaults to 0.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -xu profanity_basepoints.xor_u -c c -save
```

The public key is the well-known secp256k1 generator point and is used only to demonstrate the required 33-byte format. The XOR file must be a real Profanity recovery basepoint filter built for the selected search domain.

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

The first 16 bytes of `blob_32_bytes_hex` are the IV and the next 16 bytes are ciphertext. The password is converted to UTF-16BE, then scrypt and an AES-CBC padding check are applied. `-wallet-scrypt-mem` controls scratch memory. `$bisq$1` and `$bisq$2` tokens are recognized but their check paths are not enabled in v13.

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

## Reserved or inactive in v13

The following command names are parsed or documented for future/external compatibility, but must not be used as working recovery modes in v13:

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
| templates | `-recovery`, `-hexset`, `-wordlist` |
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
| `Makefile` | standalone macOS build and embedded Metal-library link |

---

<a id="russian"></a>

## Русский

### Что это за программа

`METAL_CRYPTO_TOOLKIT` — программа командной строки для восстановления собственных криптовалютных кошельков и исследования способов генерации ключей на компьютерах Apple Silicon. Основные вычисления выполняются на видеокарте через Metal.

Программа умеет:

- работать с мнемониками BIP-39, энтропией, seed, готовым HMAC BIP32, путями деривации и дополнительными passphrase BIP-39;
- получать и проверять результаты secp256k1, ed25519 и sr25519 для Bitcoin, Ethereum, TON, Solana, Polkadot/Substrate, Cardano, Filecoin, IOTA, Aptos, Sui, XRP, ICP и Tezos;
- искать одну известную цель напрямую либо проверять большие наборы целей через Bloom- и XOR-фильтры;
- перебирать диапазоны приватов, восстанавливать неизвестные шестнадцатеричные позиции, проверять мини-ключи Casascius и воспроизводить известные старые генераторы;
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

### Системные требования

#### Готовый выпуск v13

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

На странице [выпуска v13](https://github.com/XopMC/METAL_CRYPTO_TOOLKIT/releases/tag/v13) загрузите:

- `METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz`;
- `METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz.sha256`.

Положите оба файла в одну папку и выполните:

```bash
shasum -a 256 -c METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz.sha256
tar -xzf METAL_CRYPTO_TOOLKIT-v13-macos-arm64.tar.gz
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

### Встроенная справка

Краткий список режимов:

```bash
./METAL_CRYPTO_TOOLKIT -h
./METAL_CRYPTO_TOOLKIT -help
```

Подробная справка по конкретному режиму:

```bash
./METAL_CRYPTO_TOOLKIT -mnemonic -help
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
| `r` | secp256k1 | выходной ключ Taproot |
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

В v13 последовательные и Vanity-кернелы `-priv` используют обычную 20-байтовую проверку даже для 32-байтового результата, такого как `-c x`. В этих маршрутах прямой `-hash` длиннее 20 байтов совпасть не может. Некоторые другие режимы отдельно сравнивают более длинные значения и могут проверять до 32 байтов.

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
XorFilter -i btc_compressed_hash160.txt -o btc_c.xor_c -compress -check
./METAL_CRYPTO_TOOLKIT -priv -start 01 -end ffffff \
  -c c -xc btc_c.xor_c -save -o found.txt
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

## Сохранение, буферы и устройства

### Формат результата и файл

| Параметр | Что делает |
| --- | --- |
| `-save` | В режимах поиска ключей и дериваций преобразует найденное двоичное значение в адрес криптовалюты, если для выбранного типа цели предусмотрено адресное представление. В перечисленных ниже специальных режимах этот флаг также разрешает запись результата в файл. |
| `-o FILE` | Выбирает файл; по умолчанию `result.txt`. |
| `-silent` | Не печатает найденные строки в терминал. Поведение файла остается таким, как описано ниже для выбранного режима. |
| `-fsize N` | Количество мест под результаты на каждом устройстве; по умолчанию `150000`. |

В режимах `-mnemonic`, `-recovery`, `-entropy`, `-seed`, `-hmac`, `-bip32`, `-pass_thread`, `-der_thread`, `-priv`, `-minikeys`, `-brain`, старого Electrum и ключевых режимах Armory файл результата открывается в режиме добавления, а каждое совпадение записывается даже без `-save`. Этот флаг не подтверждает кандидата, не включает дополнительную проверку и не влияет на поиск. Он меняет только конечное представление найденного значения:

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

**Когда использовать:** известен открытый ключ, созданный уязвимым Profanity, и требуется восстановить связанное состояние и приват.

`-target` должен содержать сжатый открытый ключ длиной 33 байта или несжатый длиной 65 байт. Нужен хотя бы один совместимый XOR-фильтр базовых точек на GPU: `-xc`, `-xu`, `-xuc` или `-xh`; Bloom здесь не подходит. `-xx` можно использовать для дополнительной проверки.

Файл `-i` понимает три вида строк:

```text
<public_key_hex>
<public_key_hex>:<offset_hex>
<public_key_hex>:<offset_hex>:found
```

Последняя форма помечает уже решенную строку при продолжении пакетной работы. В файловом режиме окно `-n` по умолчанию равно 16384. Для одной цели `-offset` по умолчанию равен 0, а `-n` не используется.

```bash
./METAL_CRYPTO_TOOLKIT -profanity -recovery \
  -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 \
  -xu profanity_basepoints.xor_u -c c -save
```

Здесь указан общеизвестный открытый ключ базовой точки secp256k1: он лишь показывает требуемую длину 33 байта. Файл XOR должен быть настоящим фильтром базовых точек Profanity для выбранной области восстановления.

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

Первые 16 байтов `blob_32_bytes_hex` являются IV, следующие 16 байтов — шифротекстом. Пароль переводится в UTF-16BE, затем выполняются scrypt и проверка padding AES-CBC. `-wallet-scrypt-mem` ограничивает промежуточную память. Метки `$bisq$1` и `$bisq$2` распознаются, но их проверка в v13 не включена.

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

## Зарезервировано или выключено в v13

Следующие имена распознаются командной строкой или оставлены для совместимых форматов, но не являются рабочими режимами восстановления в v13:

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
| шаблоны | `-recovery`, `-hexset`, `-wordlist` |
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
| `Makefile` | самостоятельная сборка для macOS и встраивание библиотеки Metal |
