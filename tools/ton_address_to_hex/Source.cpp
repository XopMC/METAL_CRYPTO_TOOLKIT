#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "ton_address_to_hex",
        "Convert validated TON friendly, raw and workchain addresses to 32-byte account-ID hex targets.",
        address_tools::decode_ton);
}
