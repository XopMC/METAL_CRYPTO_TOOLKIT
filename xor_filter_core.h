#ifndef FOURWISE_XOR_BINARY_FUSE_FILTER_XOR_FILTER_LOWMEM_H_
#define FOURWISE_XOR_BINARY_FUSE_FILTER_XOR_FILTER_LOWMEM_H_

#include <vector>
#include <cstring>
#include <sstream>
#include <algorithm>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include "MetalBackend.h"

using namespace std;
#define XOR_MAX_SIZE SIZE_MAX



METAL_DEVICE METAL_HOST class SimpleMixSplit {

public:
// Device helper: SimpleMixSplit.
    METAL_DEVICE METAL_HOST SimpleMixSplit() {
    }

// Device helper: murmur64.
    METAL_DEVICE METAL_HOST inline static uint64_t murmur64(uint64_t h) {
        h ^= h >> 33;
        h *= UINT64_C(0xff51afd7ed558ccd);
        h ^= h >> 33;
        h *= UINT64_C(0xc4ceb9fe1a85ec53);
        h ^= h >> 33;
        return h;
    }
    METAL_DEVICE METAL_HOST inline uint64_t operator()(uint64_t key) const {
        return murmur64(key);
    }

};



// Device helper: calculateSegmentLength.
METAL_DEVICE METAL_HOST static inline size_t calculateSegmentLength(size_t arity, size_t size) {
    size_t segmentLength;
    double baseLog = std::log(3.33);
    if (arity == 3) {
        // We deliberately divide a log by a log so that the reader does not have
        // to ask about the basis of the log.
        segmentLength = (size_t)1 << (int)floor(std::log((double)size) / baseLog + 2.25);
    }
    else if (arity == 4) {
        baseLog = std::log(2.91);
        segmentLength = (size_t)1 << (int)floor(std::log((double)size) / baseLog - 0.5);
    }
    else {
        // not supported
        segmentLength = 65536;
    }
    return segmentLength;
}

// Device helper: calculateSizeFactor.
METAL_DEVICE METAL_HOST static inline double calculateSizeFactor(size_t arity, size_t size) {
    if (size <= 2) { size = 2; }
    double sizeFactor;
    double baseLogSize = size > 0 ? log((double)size) : 0;  // Guard against invalid input.

    // Precompute constants used in the size-factor formula.
    const double log1000000 = log(1000000.0);  // ln(1,000,000) ~= 6.907755278982137
    const double log600000 = log(600000.0);    // ln(600,000) ~= 6.396929655216146

    if (arity == 3) {
        sizeFactor = std::max(1.125, 0.875 + 0.25 * log1000000 / baseLogSize);
    }
    else if (arity == 4) {
        sizeFactor = std::max(1.075, 0.77 + 0.305 * log600000 / baseLogSize);
    }
    else {
        // not supported
        sizeFactor = 2.0;
    }
    return sizeFactor;
}

/**
 * As of July 2021, the lowmem versions of the binary fuse filters are
 * the recommended defaults.
 */
namespace xorbinaryfusefilter_lowmem4wise {

    // status returned by a xor filter operation
    METAL_DEVICE METAL_HOST enum Status {
        Ok = 0,
        NotFound = 1,
        NotEnoughSpace = 2,
        NotSupported = 3,
    };

// Device helper: reduce.
    METAL_DEVICE METAL_HOST inline uint32_t reduce(uint32_t hash, uint32_t n) {
        return (uint32_t)(((uint64_t)hash * n) >> 32);
    }

    template <typename ItemType, typename FingerprintType, typename HashFamily = SimpleMixSplit>
    class XorBinaryFuseFilter {
    public:
        size_t size;
        size_t arrayLength;
        size_t segmentCount;
        size_t segmentCountLength;
        size_t segmentLength;
        size_t segmentLengthMask;
        static constexpr size_t arity = 4;
        FingerprintType* fingerprints;
        HashFamily* hasher;
        size_t hashIndex{ 0 };
        uint64_t Seed;
        /*inline FingerprintType fingerprint(const uint128_t hash) const {
            return (FingerprintType)hash;
        }*/
// Device helper: fingerprint.
        METAL_DEVICE METAL_HOST static inline FingerprintType fingerprint(uint64_t hash)
        {
            return hash ^ (hash >> 32);
        }

// Device helper: rng_splitmix64.
        METAL_DEVICE METAL_HOST static inline uint64_t rng_splitmix64(uint64_t* seed)
        {
            uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
            z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
            return z ^ (z >> 31);
        }


// Device helper: rotateLeft.
        METAL_DEVICE METAL_HOST static inline uint64_t rotateLeft(uint64_t n, unsigned int c) {
            const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
            c &= mask;
            return (n << c) | (n >> ((-c) & mask));
        }

// Device helper: rotateRight.
        METAL_DEVICE METAL_HOST static inline uint64_t rotateRight(uint64_t n, unsigned int c) {
            const unsigned int mask = (CHAR_BIT * sizeof(n) - 1);
            c &= mask;
            return (n >> c) | (n << ((-c) & mask));
        }

        //    //  const binary_fuse_t *filter)
        //    // keep the lower 36 bits
        //    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift



        METAL_DEVICE METAL_HOST explicit XorBinaryFuseFilter() {
            uint64_t rng_counter = 0x726b2b9d438b9d4d;
            Seed = rng_splitmix64(&rng_counter);
            // Keep default host-side bootstrap size above tiny values to avoid
            // undefined shift behavior in calculateSegmentLength() for arity=4.
            size_t size = 99999;
            hasher = new HashFamily();
            this->size = size;
            this->segmentLength = calculateSegmentLength(arity, size);
            if (this->segmentLength > (1 << 18)) {
                this->segmentLength = (1 << 18);
            }
            double sizeFactor = calculateSizeFactor(arity, size);
            size_t capacity = size * sizeFactor;
            size_t segmentCount = (capacity + segmentLength - 1) / segmentLength - (arity - 1);
            this->arrayLength = (segmentCount + arity - 1) * segmentLength;
            this->segmentLengthMask = this->segmentLength - 1;
            this->segmentCount = (this->arrayLength + this->segmentLength - 1) / this->segmentLength;
            this->segmentCount = this->segmentCount <= arity - 1 ? 1 : this->segmentCount - (arity - 1);
            this->arrayLength = (this->segmentCount + arity - 1) * this->segmentLength;
            this->segmentCountLength = this->segmentCount * this->segmentLength;
            fingerprints = new FingerprintType[arrayLength]();
            memset(fingerprints, 0, sizeof(FingerprintType) * arrayLength);
        }


// Device helper: XorBinaryFuseFilter.
        METAL_DEVICE METAL_HOST explicit XorBinaryFuseFilter(const size_t sizes) {
            uint64_t rng_counter = 0x726b2b9d438b9d4d;
            Seed = rng_splitmix64(&rng_counter);
            size_t size = sizes;
            if (size < 99999)
            {
                size = 99999;
            }
            hasher = new HashFamily();
            this->size = size;
            this->segmentLength = calculateSegmentLength(arity, size);
            if (this->segmentLength > (1 << 18)) {
                this->segmentLength = (1 << 18);
            }
            double sizeFactor = calculateSizeFactor(arity, size);
            size_t capacity = size * sizeFactor;
            size_t segmentCount = (capacity + segmentLength - 1) / segmentLength - (arity - 1);
            this->arrayLength = (segmentCount + arity - 1) * segmentLength;
            this->segmentLengthMask = this->segmentLength - 1;
            this->segmentCount = (this->arrayLength + this->segmentLength - 1) / this->segmentLength;
            this->segmentCount = this->segmentCount <= arity - 1 ? 1 : this->segmentCount - (arity - 1);
            this->arrayLength = (this->segmentCount + arity - 1) * this->segmentLength;
            this->segmentCountLength = this->segmentCount * this->segmentLength;
            fingerprints = new FingerprintType[arrayLength]();
            memset(fingerprints, 0, sizeof(FingerprintType) * arrayLength);
        }

// Device helper: ~XorBinaryFuseFilter.
        METAL_DEVICE METAL_HOST ~XorBinaryFuseFilter() {
            delete[] fingerprints;
            delete hasher;
        }

       /* METAL_DEVICE METAL_HOST bool Contain(const ItemType& item) const {
            uint64_t hash = (*hasher)(item + Seed);
            FingerprintType f = fingerprint(hash);
            for (int hi = 0; hi < 4; hi++) {
                size_t h = getHashFromHash(hash, hi);
                f ^= fingerprints[h];
            }
            return f == 0 ? true : false;
        }*/

// Device helper: AllocateGPU.
        METAL_DEVICE bool AllocateGPU(size_t arrayLength)
        {
            delete[] fingerprints;
            fingerprints = new FingerprintType[arrayLength];
            return true;

        }








// Host helper: Info.
        METAL_HOST std::string Info() const {
            std::stringstream ss;
            ss << "4-wise XorBinaryFuseFilter Status:\n"
                << "\t\tKeys stored: " << Size() << "\n";
            return ss.str();
        }

        METAL_DEVICE METAL_HOST size_t Size() const { return size; }

        METAL_DEVICE METAL_HOST size_t SizeInBytes() const { return arrayLength * sizeof(FingerprintType); }


        // Function to load the filter from a file
        METAL_HOST bool LoadFromFile(const std::string& filename) {
            std::ifstream in(filename, std::ios::binary);
            if (!in.is_open()) {
                return false;
            }
            if (!in.read(reinterpret_cast<char*>(&size), sizeof(size))) return false;
            if (!in.read(reinterpret_cast<char*>(&arrayLength), sizeof(arrayLength))) return false;
            if (!in.read(reinterpret_cast<char*>(&segmentCount), sizeof(segmentCount))) return false;
            if (!in.read(reinterpret_cast<char*>(&segmentCountLength), sizeof(segmentCountLength))) return false;
            if (!in.read(reinterpret_cast<char*>(&segmentLength), sizeof(segmentLength))) return false;
            if (!in.read(reinterpret_cast<char*>(&segmentLengthMask), sizeof(segmentLengthMask))) return false;
            if (arrayLength == 0 || arrayLength > XOR_MAX_SIZE) return false;
            delete[] fingerprints;
            fingerprints = nullptr;
            try {
                fingerprints = new FingerprintType[arrayLength];
            }
            catch (...) {
                return false;
            }
            if (!in.read(reinterpret_cast<char*>(fingerprints), sizeof(FingerprintType) * arrayLength)) {
                delete[] fingerprints;
                fingerprints = nullptr;
                return false;
            }
            in.close();
            return true;
        }
    };

} // namespace xorbinaryfusefilter_lowmem4wise

#endif  // FOURWISE_XOR_BINARY_FUSE_FILTER_XOR_FILTER_LOWMEM_H_
