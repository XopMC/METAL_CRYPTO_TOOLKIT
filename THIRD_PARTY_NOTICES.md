# Third-Party Notices

## RCKangaroo

The `-kangaroo` mode is a native Metal adaptation of RCKangaroo:

- Copyright (c) 2024 RetiredCoder (RC)
- Upstream: https://github.com/RetiredC
- License: GNU General Public License version 3

The adapted host and GPU sources are located in `Kangaroo/` and in the
`Kernels/KangarooCore.metalh`, `Kernels/kangarooInit.metal`, and
`Kernels/kangarooWalk.metal` files. The complete GPLv3 license text is
provided in `COPYING.GPLv3.txt`.

The original METAL_CRYPTO_TOOLKIT sources retain the MIT license text in
`LICENSE`. Because the distributed executable combines that code with the
GPLv3-covered Kangaroo implementation, builds that include `-kangaroo` and
this combined source distribution are distributed under GPLv3.

## Monero

The `-monero` mode incorporates the Monero project's ref10 group/scalar
arithmetic and official legacy mnemonic word lists:

- Copyright (c) 2014-2026, The Monero Project
- Upstream: https://github.com/monero-project/monero
- Source revision: `dfc36e278b1a14be03f04bed75a5734be79d5ba0`
- License: BSD 3-Clause

The adapted reference files are located in `Monero/third_party/`; generated
word-list data derived from the official language headers is located in
`Monero/MoneroWordlists.generated.h`.

The `-monerowallet` mode additionally incorporates Monero's CryptoNight-v0
companion hash implementations and wallet ChaCha8/ChaCha20 primitive from the
same source revision. The Blake, Groestl, JH, Skein, extra-hash wrappers and
memory-wipe sources are BSD 3-Clause code from Monero/CryptoNote; the merged
ChaCha implementation by D. J. Bernstein is public domain. These files are
located in `MoneroWallet/third_party/`.

## Polyseed

The `-monero` mode embeds the official Polyseed language lists and follows the
Polyseed phrase/checksum/KDF specification:

- Copyright (c) 2020-2021 tevador
- Upstream: https://github.com/tevador/polyseed
- Source revision: `11dc7e8a70d6be0570fdf5487e9b5d10d37f6071`
- License: GNU Lesser General Public License version 3

The generated Polyseed word-list data is located in
`Monero/MoneroWordlists.generated.h`. No Polyseed implementation source is
copied into the executable; the native implementation is covered by the
project's combined GPLv3 distribution described above.

## SLIP-0039 word list

The `-slip39` mode embeds the official English SLIP-0039 word list:

- Copyright (c) 2019 SatoshiLabs
- Upstream: https://github.com/trezor/python-shamir-mnemonic
- Source revision: `17fcce14736afe498871d3018e4fa9330443471a`
- License: MIT

The generated word-list data is located in
`Slip39/Slip39Wordlist.generated.h`. The parser, Shamir reconstruction,
Feistel cipher, host verification, and Metal kernels are native project
implementations based on the public SLIP-0039 specification.

## LND aezeed and AEZ

The `-aezeed` compatibility implementation was validated against the public
LND aezeed implementation at commit
`530dca19b313566a24907a56e5bcb7b0e94af1d4` (MIT License).

The fixed-size AEZ-v5 implementation follows the public AEZ reference at commit
`e49e68abd344eba4a888cee91bc7370df2d14e27` (CC0 public-domain dedication).

## IOTA Stronghold, Tauri Stronghold, and Argon2

The `-stronghold` snapshot parser and compatibility tests follow the public
IOTA Stronghold implementation:

- Copyright (c) 2020-2026 IOTA Stiftung
- Upstream: https://github.com/iotaledger/stronghold.rs
- Source revision: `ab6ff0de98095001ed2eb75111ee034a584678b8`
- License: Apache License 2.0

The named Tauri Argon2 profile follows the public Tauri Stronghold plugin
example:

- Copyright (c) 2019-2026 Tauri Programme within The Commons Conservancy
- Upstream: https://github.com/tauri-apps/plugins-workspace
- Source revision: `304292d740a666d3903ab58329860fc0fdde2818`
- License: MIT OR Apache License 2.0

The cooperative Metal Argon2 block layout and address-block reuse were adapted
from Hashcat's MIT-licensed Argon2 OpenCL implementation:

- Copyright (c) Netherlands Forensic Institute
- Upstream: https://github.com/hashcat/hashcat
- Source revision: `994014c7faebe1b55f31f7f1b5a7d7c6fb151d8a`
- License: MIT

The host X25519 construction follows the public-domain TweetNaCl design. The
Stronghold host verifier, XChaCha20-Poly1305 implementation, exact LZ4 decoder,
memory scheduler, CLI integration, and Metal kernels are maintained as native
project code.
