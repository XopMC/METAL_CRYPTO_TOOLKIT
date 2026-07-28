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
