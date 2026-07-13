#include "SetCurveCommon.metalh"

kernel void SetCurve(device RuntimeConfig& config [[buffer(0)]],
                     constant uint& secp256 [[buffer(1)]],
                     constant uint& ed25519 [[buffer(2)]],
                     constant uint& electrum_host [[buffer(3)]],
                     constant uint& ton_mnem [[buffer(4)]],
                     constant uint& ton_only [[buffer(5)]],
                     constant uint& old_electrum_host [[buffer(6)]],
                     constant uint& compressed [[buffer(7)]],
                     constant uint& uncompressed [[buffer(8)]],
                     constant uint& segwit [[buffer(9)]],
                     constant uint& p2wsh [[buffer(10)]],
                     constant uint& taproot [[buffer(11)]],
                     constant uint& ethereum [[buffer(12)]],
                     constant uint& xpoint [[buffer(13)]],
                     constant uint& solana [[buffer(14)]],
                     constant uint& ton [[buffer(15)]],
                     constant uint& ton_all [[buffer(16)]],
                     constant uint& dot [[buffer(17)]],
                     constant uint& aptos [[buffer(18)]],
                     constant uint& sui [[buffer(19)]],
                     constant uint& xrp [[buffer(20)]],
                     constant uint& exodus [[buffer(21)]],
                     constant uint& iota [[buffer(22)]],
                     constant uint& ada [[buffer(23)]],
                     constant uint& icp [[buffer(24)]],
                     constant uint& fil [[buffer(25)]],
                     constant uint& xtz [[buffer(26)]],
                     constant uint& endomorphism [[buffer(27)]]) {
    config.secp256 = secp256;
    config.ed25519 = ed25519;
    config.electrum = electrum_host;
    config.tonMnemonic = ton_mnem;
    config.tonOnly = ton_only;
    config.oldElectrum = old_electrum_host;
    config.compressed = compressed;
    config.uncompressed = uncompressed;
    config.endomorphism = endomorphism;
    config.segwit = segwit;
    config.p2wsh = p2wsh;
    config.taproot = taproot;
    config.ethereum = ethereum;
    config.xpoint = xpoint;
    config.solana = solana;
    config.ton = ton;
    config.tonAll = ton_all;
    config.dot = dot;
    config.aptos = aptos;
    config.sui = sui;
    config.xrp = xrp;
    config.exodus = exodus;
    config.iota = iota;
    config.ada = ada;
    config.icp = icp;
    config.fil = fil;
    config.xtz = xtz;

    const bool aptos_secp = aptos != 0u && metal_type_enabled(config.aptosTypeMask, 0x22u, 0x20u, 0x22u);
    const bool aptos_ed = aptos != 0u && (metal_type_enabled(config.aptosTypeMask, 0x20u, 0x20u, 0x22u) ||
                                          metal_type_enabled(config.aptosTypeMask, 0x21u, 0x20u, 0x22u));
    const bool sui_secp = sui != 0u && metal_type_enabled(config.suiTypeMask, 0x70u, 0x70u, 0x71u);
    const bool sui_ed = sui != 0u && metal_type_enabled(config.suiTypeMask, 0x71u, 0x70u, 0x71u);
    const bool xrp_secp = xrp != 0u && metal_type_enabled(config.xrpTypeMask, 0x90u, 0x90u, 0x91u);
    const bool xrp_ed = xrp != 0u && metal_type_enabled(config.xrpTypeMask, 0x91u, 0x90u, 0x91u);
    const bool iota_secp = iota != 0u && metal_type_enabled(config.iotaTypeMask, 0x50u, 0x50u, 0x51u);
    const bool iota_ed = iota != 0u && metal_type_enabled(config.iotaTypeMask, 0x51u, 0x50u, 0x51u);
    const bool icp_ed = icp != 0u && metal_type_enabled(config.icpTypeMask, 0x52u, 0x52u, 0x53u);
    const bool icp_secp = icp != 0u && metal_type_enabled(config.icpTypeMask, 0x53u, 0x52u, 0x53u);
    const bool fil_secp = fil != 0u && (metal_type_enabled(config.filTypeMask, 0x41u, 0x41u, 0x42u) ||
                                        metal_type_enabled(config.filTypeMask, 0x42u, 0x41u, 0x42u));
    const bool xtz_secp = xtz != 0u && metal_type_enabled(config.xtzTypeMask, 0x92u, 0x92u, 0x93u);
    const bool xtz_ed = xtz != 0u && metal_type_enabled(config.xtzTypeMask, 0x93u, 0x92u, 0x93u);
    const bool dot_ed = dot != 0u && (metal_type_enabled(config.dotTypeMask, 0x30u, 0x30u, 0x31u) ||
                                      metal_type_enabled(config.dotTypeMask, 0x31u, 0x30u, 0x31u));
    const bool ton_ed = (ton != 0u || ton_all != 0u) && (config.tonTypeMask != 0u);
    config.secpTargetsAny = (compressed != 0u || uncompressed != 0u || segwit != 0u || p2wsh != 0u ||
                             taproot != 0u || ethereum != 0u || xpoint != 0u || xrp_secp ||
                             aptos_secp || sui_secp || iota_secp || icp_secp || fil_secp || xtz_secp) ? 1u : 0u;
    config.edTargetsAny = (solana != 0u || ton_ed || dot_ed || aptos_ed || sui_ed || xrp_ed ||
                           iota_ed || icp_ed || xtz_ed || ada != 0u) ? 1u : 0u;
}
