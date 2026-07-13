#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "solana_address_to_hex",
        "Convert Solana Base58 public keys to 32-byte hex targets.",
        address_tools::decode_solana);
}
