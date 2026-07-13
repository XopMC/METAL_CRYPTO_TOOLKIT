/*
This is based on the merlin lib from the author (hdevalence) https://github.com/hdevalence/libmerlin
*/

#ifndef MERLIN_H
#define MERLIN_H
#define __STDC_WANT_LIB_EXT1__ 1
/* XXX can these be made opaque without malloc? */

typedef struct merlin_strobe128_ {
  /* XXX endianness */
  union {
    uint64_t state[25];
    uint8_t state_bytes[200];
  };
  uint8_t pos;
  uint8_t pos_begin;
  uint8_t cur_flags;
} merlin_strobe128;

typedef struct merlin_transcript_ {
  merlin_strobe128 sctx;
} merlin_transcript;

typedef struct merlin_rng_ {
  merlin_strobe128 sctx;
  uint8_t finalized;
} merlin_rng;

REC_DEVICE void merlin_transcript_init(thread merlin_transcript* mctx, const constant uint8_t* label, size_t label_len);
REC_DEVICE void merlin_transcript_commit_bytes(thread merlin_transcript* mctx, const constant uint8_t* label, size_t label_len, const thread uint8_t* data, size_t data_len);
REC_DEVICE void merlin_transcript_commit_bytes(thread merlin_transcript* mctx, const constant uint8_t* label, size_t label_len, const constant uint8_t* data, size_t data_len);
REC_DEVICE void merlin_transcript_challenge_bytes(thread merlin_transcript* mctx, const constant uint8_t* label, size_t label_len, thread uint8_t* buffer, size_t buffer_len);
REC_DEVICE void merlin_commit_witness_bytes(thread merlin_transcript* mctx, thread uint8_t* dest, size_t dest_len, const constant uint8_t* label, size_t label_len, const thread uint8_t* witness, size_t witness_len);
REC_DEVICE void merlin_rng_init(thread merlin_rng* mrng, const thread merlin_transcript* mctx);
REC_DEVICE void merlin_rng_commit_witness_bytes(thread merlin_rng* mrng, const constant uint8_t* label, size_t label_len, const thread uint8_t* witness, size_t witness_len);
REC_DEVICE void merlin_rng_finalize(thread merlin_rng* mrng, const thread uint8_t entropy[32]);
REC_DEVICE void merlin_rng_random_bytes(thread merlin_rng* mrng, thread uint8_t* buffer, size_t buffer_len);
REC_DEVICE void merlin_rng_wipe(thread merlin_rng* mrng);




#endif
