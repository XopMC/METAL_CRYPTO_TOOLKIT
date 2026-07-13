#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "tron_address_to_hex",
        "Convert validated Tron Base58Check addresses to 20-byte Ethereum-style account hex targets.",
        address_tools::decode_tron);
}
