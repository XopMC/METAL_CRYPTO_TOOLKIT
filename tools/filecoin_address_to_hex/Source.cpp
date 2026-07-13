#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "filecoin_address_to_hex",
        "Convert validated Filecoin f/t1 and delegated f/t410 addresses to 20-byte payload hex targets.",
        address_tools::decode_filecoin);
}
