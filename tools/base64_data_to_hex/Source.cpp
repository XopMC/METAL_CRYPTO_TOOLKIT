#include "AddressCodecs.h"
#include "ToolRunner.h"

int main(int argc, char** argv) {
    return address_tools::run_converter(
        argc, argv, "base64_data_to_hex",
        "Decode strict Base64 or Base64URL values to lowercase hex.",
        address_tools::decode_base64_raw);
}
