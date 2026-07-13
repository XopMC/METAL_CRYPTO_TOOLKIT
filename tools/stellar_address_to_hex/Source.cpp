#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "stellar_address_to_hex",
        "Convert validated Stellar G and muxed M StrKey addresses to 32-byte public-key hex targets.",
        address_tools::decode_stellar);
}
