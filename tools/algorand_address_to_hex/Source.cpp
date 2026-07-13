#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "algorand_address_to_hex",
        "Convert validated Algorand addresses to 32-byte public-key hex targets.",
        address_tools::decode_algorand);
}
