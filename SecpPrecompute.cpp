#include "MetalBackend.h"
#include "host_secp/secp256k1.h"
#include "host_secp/secp256k1_field.h"
#include "host_secp/secp256k1_group.h"

#include "SecpPrecompute.h"

#include <limits>

bool build_secp256k1_precompute_table_host(unsigned int bits,
                                           std::vector<secp256k1_ge_storage>& entries,
                                           std::size_t& row_pitch,
                                           unsigned int& windows,
                                           std::string& err) {
    entries.clear();
    row_pitch = 0u;
    windows = 0u;
    err.clear();

    if (bits == 0u || bits > 24u) {
        err = "invalid secp256k1 precompute bits";
        return false;
    }

    windows = (256u / bits) + 1u;
    const std::size_t row_size = std::size_t{1} << (bits - 1u);
    row_pitch = row_size * sizeof(secp256k1_ge_storage);
    if (windows == 0u || row_size == 0u || row_pitch == 0u ||
        row_size > (std::numeric_limits<std::size_t>::max() / windows)) {
        err = "secp256k1 precompute sizing overflow";
        return false;
    }

    entries.assign(row_size * static_cast<std::size_t>(windows), secp256k1_ge_storage{});
    std::vector<secp256k1_gej> gej_temp(row_size);
    std::vector<secp256k1_fe> z_ratio(row_size);

    secp256k1_fe fe_zinv{};
    secp256k1_ge ge_temp{};
    secp256k1_ge ge_window_one = secp256k1_ge_const_g;
    secp256k1_gej gej_window_base{};
    secp256k1_gej_set_ge(&gej_window_base, &ge_window_one);

    secp256k1_fe z0{};
    secp256k1_fe_set_int(&z0, 0);
    z_ratio[0] = z0;

    for (unsigned int row = 0u; row < windows; ++row) {
        std::size_t window_size = (row == windows - 1u)
            ? (std::size_t{1} << (256u % bits))
            : row_size;
        if (window_size == 0u || window_size > row_size) {
            err = "invalid secp256k1 precompute row size";
            return false;
        }

        if (row > 0u) {
            for (unsigned int i = 0u; i < bits; ++i) {
                secp256k1_gej_double_var(&gej_window_base, &gej_window_base, nullptr);
            }
        }
        gej_temp[0] = gej_window_base;
        secp256k1_ge_set_gej(&ge_window_one, &gej_window_base);

        for (std::size_t i = 1u; i < window_size; ++i) {
            secp256k1_gej prev = gej_temp[i - 1u];
            secp256k1_gej next{};
            secp256k1_fe ratio{};
            secp256k1_gej_add_ge_var(&next, &prev, &ge_window_one, &ratio);
            gej_temp[i] = next;
            z_ratio[i] = ratio;
        }

        std::size_t i = window_size - 1u;
        secp256k1_gej last = gej_temp[i];
        secp256k1_fe_inv(&fe_zinv, &last.z);
        secp256k1_ge_set_gej_zinv(&ge_temp, &last, &fe_zinv);

        secp256k1_ge_storage stored{};
        secp256k1_ge_to_storage(&stored, &ge_temp);
        entries[static_cast<std::size_t>(row) * row_size + i] = stored;

        for (; i > 0u; --i) {
            secp256k1_fe ratio = z_ratio[i];
            secp256k1_fe_mul(&fe_zinv, &fe_zinv, &ratio);

            secp256k1_gej prev = gej_temp[i - 1u];
            secp256k1_ge_set_gej_zinv(&ge_temp, &prev, &fe_zinv);
            secp256k1_ge_to_storage(&stored, &ge_temp);
            entries[static_cast<std::size_t>(row) * row_size + (i - 1u)] = stored;
        }
    }

    return true;
}
