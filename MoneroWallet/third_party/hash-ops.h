#pragma once

#define HASH_SIZE 32

void hash_extra_blake(const void* data, size_t length, char* hash);
void hash_extra_groestl(const void* data, size_t length, char* hash);
void hash_extra_jh(const void* data, size_t length, char* hash);
void hash_extra_skein(const void* data, size_t length, char* hash);
