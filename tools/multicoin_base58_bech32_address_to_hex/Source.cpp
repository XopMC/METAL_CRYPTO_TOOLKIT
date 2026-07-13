#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "multicoin_base58_bech32_address_to_hex",
        "Convert validated Bitcoin-like Base58Check, Bech32 and CashAddr addresses to binary hex targets.",
        address_tools::decode_multicoin_base58_bech32);
}
