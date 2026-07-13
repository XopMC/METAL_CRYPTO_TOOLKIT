#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "tezos_address_to_hex",
        "Convert validated Tezos tz1 and tz2 addresses to 20-byte key-hash hex targets.",
        address_tools::decode_tezos);
}
