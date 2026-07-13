#ifndef _HASH_LOOKUP_HOST_H
#define _HASH_LOOKUP_HOST_H
#include "MetalBackend.h"
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

typedef struct hash160 {
	uint32_t h[5];

	// hash160: computes 160.
	hash160(const uint32_t hash[5])
	{
		memcpy(h, hash, sizeof(uint32_t) * 5);
	}
}hash160;

class MetalHashLookup {

private:
	uint8_t* _bloomHostData[100];  // CPU-side bloom data, loaded once from files
	size_t   _bloomHostSize[100];  // byte count per slot (0 for "full.blf")
	int      _bloomCount;
	bool     _bloomFilesLoaded;
	std::mutex _mutex;

	metalError_t loadBloomFromFiles(const std::vector<std::string>& targets);
	metalError_t uploadBloomToGPU();

	void cleanup();

public:

	// MetalHashLookup: computes lookup for metal.
	MetalHashLookup() : _bloomCount(0), _bloomFilesLoaded(false)
	{
		// Initialize all host bloom pointers to null.
		for (int a = 0; a < 100; ++a) {
			_bloomHostData[a] = nullptr;
			_bloomHostSize[a] = 0;
		}
	}

	// ~MetalHashLookup: releases resources during object destruction.
	~MetalHashLookup()
	{
		cleanup();
	}

	metalError_t setTargets(const std::vector<std::string>& targets);
};

#endif
