#include "dot.h"
#include <cstdint>
#include <cstring>

// Функция компрессии — основная часть алгоритма Blake2b
void blake2b_compress(uint64_t h[8], const uint8_t block[128], uint64_t t, int is_final) {
	uint64_t v[16];
	uint64_t m[16];

	// Загружаем 128-байтный блок в m (каждые 8 байт интерпретируются в little-endian)
	for (int i = 0; i < 16; i++) {
		m[i] = ((uint64_t)block[i * 8 + 0]) |
			((uint64_t)block[i * 8 + 1] << 8) |
			((uint64_t)block[i * 8 + 2] << 16) |
			((uint64_t)block[i * 8 + 3] << 24) |
			((uint64_t)block[i * 8 + 4] << 32) |
			((uint64_t)block[i * 8 + 5] << 40) |
			((uint64_t)block[i * 8 + 6] << 48) |
			((uint64_t)block[i * 8 + 7] << 56);
	}

	// Начальное значение v = [h, IV]
	static const uint64_t blake2b_IV[8] = {
		0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
		0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
		0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
		0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
	};

	for (int i = 0; i < 8; i++) {
		v[i] = h[i];
	}
	for (int i = 0; i < 8; i++) {
		v[i + 8] = blake2b_IV[i];
	}

	v[12] ^= t; // Обновляем счётчик обработанных байт
	if (is_final)
		v[14] = ~v[14];

	// 12 раундов преобразования
	for (int r = 0; r < 12; r++) {
#define G(a, b, c, d, x, y) {     \
            a = a + b + x;                \
            d = ROTR64_host(d ^ a, 32);        \
            c = c + d;                    \
            b = ROTR64_host(b ^ c, 24);        \
            a = a + b + y;                \
            d = ROTR64_host(d ^ a, 16);        \
            c = c + d;                    \
            b = ROTR64_host(b ^ c, 63);        \
        }
		// Шаг «столбцов»
		G(v[0], v[4], v[8], v[12], m[sigma[r][0]], m[sigma[r][1]]);
		G(v[1], v[5], v[9], v[13], m[sigma[r][2]], m[sigma[r][3]]);
		G(v[2], v[6], v[10], v[14], m[sigma[r][4]], m[sigma[r][5]]);
		G(v[3], v[7], v[11], v[15], m[sigma[r][6]], m[sigma[r][7]]);
		// Шаг «диагоналей»
		G(v[0], v[5], v[10], v[15], m[sigma[r][8]], m[sigma[r][9]]);
		G(v[1], v[6], v[11], v[12], m[sigma[r][10]], m[sigma[r][11]]);
		G(v[2], v[7], v[8], v[13], m[sigma[r][12]], m[sigma[r][13]]);
		G(v[3], v[4], v[9], v[14], m[sigma[r][14]], m[sigma[r][15]]);
#undef G
	}

	// Обновляем состояние h
	for (int i = 0; i < 8; i++) {
		h[i] ^= v[i] ^ v[i + 8];
	}
}

// Упрощённая функция Blake2b. Работает только для inlen < 128 и outlen <= 64.
void blake2b(const uint8_t* input, size_t inlen, uint8_t* out, size_t outlen) {

	uint64_t h[8];
	static const uint64_t blake2b_IV[8] = {
		0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
		0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
		0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
		0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
	};

	// Формируем параметр: для незашифрованного режима (key_length = 0) устанавливаем:
	// digest_length | (key_length << 8) | (fanout << 16) | (depth << 24)
	uint64_t param0 = ((uint64_t)outlen) | ((uint64_t)0 << 8) | ((uint64_t)1 << 16) | ((uint64_t)1 << 24);
	h[0] = blake2b_IV[0] ^ param0;
	for (int i = 1; i < 8; i++) {
		h[i] = blake2b_IV[i];
	}
	//9ef5a7b81cd44abd840433769d9db294a562a5b0b835a1392019e5f303b75b462983e6ad7f520e511f6cc62a8c68059b6b7d4efbabd9831f5921fe0c19cde05b
	//257fd633c88f8be513cb3bfe68cb804c868058320de6a0e0924766d1c6fab491b06a85dfec6c2035949e85dfd8dad2d56ca0d752a73331c48e223cc5553755f8
	// Подготавливаем 128-байтный буфер, заполняем входными данными и дополняем нулями
	uint8_t block[128] = { 0 };
	memcpy(block, input, inlen);

	// t — количество обработанных байт (для наших небольших сообщений достаточно одного блока)
	uint64_t t = inlen;
	blake2b_compress(h, block, t, /*is_final=*/1);

	// Записываем выходной хэш в out (в little-endian)
	for (size_t i = 0; i < outlen; i++) {
		out[i] = (h[i / 8] >> (8 * (i % 8))) & 0xFF;
	}
}
