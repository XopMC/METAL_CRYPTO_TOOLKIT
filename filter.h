#pragma once
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "uint128_t.h"
#include <vector>
#include <string>

extern bool useXorCPU;
extern bool useBloomCPU;

extern int bloom_count;
extern int xor_count;

extern uint32_t* fingerprints[25];
extern size_t     size[25];
extern size_t     arrayLength[25];
extern size_t     segmentCount[25];
extern size_t     segmentCountLength[25];
extern size_t     segmentLength[25];
extern size_t     segmentLengthMask[25];

extern unsigned char* blooms[100];


#define BLOOM_SIZE (512*1024*1024)

#define BLOOM_SET_BIT(N) (bloom[(N)>>3] = bloom[(N)>>3] | (1<<((N)&7)))
#define BLOOM_GET_BIT(N) ( ( bloom[(N)>>3]>>((N)&7) )&1)

#define BH00(N) (N[0])
#define BH01(N) (N[1])
#define BH02(N) (N[2])
#define BH03(N) (N[3])
#define BH04(N) (N[4])

#define BH05(N) (N[0]<<16|N[1]>>16)
#define BH06(N) (N[1]<<16|N[2]>>16)
#define BH07(N) (N[2]<<16|N[3]>>16)
#define BH08(N) (N[3]<<16|N[4]>>16)
#define BH09(N) (N[4]<<16|N[0]>>16)

#define BH10(N) (N[0]<< 8|N[1]>>24)
#define BH11(N) (N[1]<< 8|N[2]>>24)
#define BH12(N) (N[2]<< 8|N[3]>>24)
#define BH13(N) (N[3]<< 8|N[4]>>24)
#define BH14(N) (N[4]<< 8|N[0]>>24)

#define BH15(N) (N[0]<<24|N[1]>> 8)
#define BH16(N) (N[1]<<24|N[2]>> 8)
#define BH17(N) (N[2]<<24|N[3]>> 8)
#define BH18(N) (N[3]<<24|N[4]>> 8)
#define BH19(N) (N[4]<<24|N[0]>> 8)




extern const std::vector<std::string> exts_xc;
extern const std::vector<std::string> exts_xu;
extern const std::vector<std::string> exts_xb;
extern const std::vector<std::string> exts_xuc;
extern const std::vector<std::string> exts_xh;

void add_filter_path(const char* p,
	std::vector<std::string>& outFiles,
	bool& useFlag,
	const std::vector<std::string>& allowedExts,
	bool recursive = false);

bool loadXorFilters(const std::vector<std::string>& xorFiles);


bool loadBloomFiltersIntoSharedMemory(const std::vector<std::string>& bloomFiles);



typedef union hash160_u {
	uint8_t uc[32];
	uint32_t      ul[32 >> 2];
	uint64_t ull[32 >> 3];
	uint128_t uu[2];
} hash160_t;

bool find_in_bloom(const hash160_t hash);
