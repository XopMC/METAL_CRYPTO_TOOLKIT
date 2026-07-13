#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "xrp_address_to_hex",
        "Convert validated XRP Classic addresses to 20-byte account-ID hex targets.",
        address_tools::decode_xrp);
}
