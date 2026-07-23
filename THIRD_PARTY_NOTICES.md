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
