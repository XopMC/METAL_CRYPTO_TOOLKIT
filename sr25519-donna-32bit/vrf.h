#ifndef __VRF_H__
#define __VRF_H__



REC_DEVICE Sr25519SignatureResult vrf_sign(thread sr25519_vrf_io inout, thread sr25519_vrf_proof proof, thread sr25519_vrf_proof_batchable proof_batchable, const thread sr25519_keypair keypair, const thread merlin_transcript *t);
REC_DEVICE Sr25519SignatureResult shorten_vrf(thread sr25519_vrf_proof proof, const thread sr25519_vrf_proof_batchable proof_batchable, const thread sr25519_public_key public_key, const thread merlin_transcript *t, const thread sr25519_vrf_output preout);
REC_DEVICE Sr25519SignatureResult vrf_verify(thread sr25519_vrf_io inout, thread sr25519_vrf_proof_batchable proof_batchable, const thread sr25519_public_key public_key, const thread merlin_transcript *t, const thread sr25519_vrf_output preout, const thread sr25519_vrf_proof proof);
void io_make_bytes(thread sr25519_vrf_raw_output raw_output, const thread sr25519_vrf_io inout, const constant uint8_t *context, const size_t context_length);




#endif
