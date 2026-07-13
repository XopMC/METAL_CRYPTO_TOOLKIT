#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "polkadot_kusama_address_to_hex",
        "Convert validated Substrate SS58 addresses to 32-byte account-ID hex targets.",
        address_tools::decode_ss58);
}
