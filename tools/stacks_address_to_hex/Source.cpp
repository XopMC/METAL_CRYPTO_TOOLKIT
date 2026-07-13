#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "stacks_address_to_hex",
        "Convert validated Stacks C32Check addresses to 20-byte hash160 hex targets.",
        address_tools::decode_stacks);
}
