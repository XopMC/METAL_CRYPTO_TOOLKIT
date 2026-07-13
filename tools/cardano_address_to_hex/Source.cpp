#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "cardano_address_to_hex",
        "Convert validated Cardano Shelley and Byron addresses to SHA-256 hex targets.",
        address_tools::decode_cardano);
}
