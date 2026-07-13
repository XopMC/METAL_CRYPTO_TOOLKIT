#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "cosmos_bnb_address_to_hex",
        "Convert validated Cosmos-family Bech32 addresses to 20-byte payload hex targets.",
        address_tools::decode_cosmos);
}
