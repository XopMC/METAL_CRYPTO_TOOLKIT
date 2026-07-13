#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "util.h"
#include "hash/sha256.h"
#include "base58.h"


// ltrim: performs ltrim.
char* ltrim(char* str, const char* seps) {
	size_t totrim;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	totrim = strspn(str, seps);
	if (totrim > 0) {
		size_t len = strlen(str);
		if (totrim == len) {
			str[0] = '\0';
		}
		else {
			memmove(str, str + totrim, len + 1 - totrim);
		}
	}
	return str;
}

// rtrim: performs rtrim.
char* rtrim(char* str, const char* seps) {
	int i;
	if (seps == NULL) {
		seps = "\t\n\v\f\r ";
	}
	i = strlen(str) - 1;
	while (i >= 0 && strchr(seps, str[i]) != NULL) {
		str[i] = '\0';
		i--;
	}
	return str;
}

// trim: performs trim.
char* trim(char* str, const char* seps) {
	return ltrim(rtrim(str, seps), seps);
}

// indexOf: performs index of.
int indexOf(char* s, const char** array, int length_array) {
	int index = -1, i, continuar = 1;
	for (i = 0; i < length_array && continuar; i++) {
		if (strcmp(s, array[i]) == 0) {
			index = i;
			continuar = 0;
		}
	}
	return index;
}

// nextToken: performs next token.
char* nextToken(Tokenizer* t) {
	if (t->current < t->n) {
		t->current++;
		return t->tokens[t->current - 1];
	}
	else {
		return  NULL;
	}
}
// hasMoreTokens: checks whether more tokens is valid.
int hasMoreTokens(Tokenizer* t) {
	return (t->current < t->n);
}

// stringtokenizer: performs stringtokenizer.
void stringtokenizer(char* data, Tokenizer* t) {
	char* token;
	t->tokens = NULL;
	t->n = 0;
	t->current = 0;
	trim(data, "\t\n\r :");
	std::vector<char*> parsed;
	token = strtok(data, " \t:");
	while (token != NULL) {
		parsed.push_back(token);
		token = strtok(NULL, " \t");
	}
	if (!parsed.empty()) {
		t->tokens = (char**)malloc(sizeof(char*) * parsed.size());
		if (t->tokens == NULL) {
			printf("Out of memory\n");
			exit(0);
		}
		memcpy(t->tokens, parsed.data(), sizeof(char*) * parsed.size());
		t->n = static_cast<int>(parsed.size());
	}
}

// freetokenizer: performs freetokenizer.
void freetokenizer(Tokenizer* t) {
	if (t->n > 0) {
		free(t->tokens);
	}
	memset(t, 0, sizeof(Tokenizer));
}


/*
	Aux function to get the hexvalues of the data
*/
char* tohex(char* ptr, int length) {
	char* buffer;
	static const char HEX[] = "0123456789abcdef";
	buffer = (char*)malloc((length * 2) + 1);
	for (int i = 0; i < length; i++) {
		unsigned char c = (unsigned char)ptr[i];
		buffer[i * 2] = HEX[(c >> 4) & 0x0F];
		buffer[i * 2 + 1] = HEX[c & 0x0F];
	}
	buffer[length * 2] = 0;
	return buffer;
}

// tohex_dst: performs tohex dst.
void tohex_dst(char* ptr, int length, char* dst) {
	static const char HEX[] = "0123456789abcdef";
	for (int i = 0; i < length; i++) {
		unsigned char c = (unsigned char)ptr[i];
		dst[i * 2] = HEX[(c >> 4) & 0x0F];
		dst[i * 2 + 1] = HEX[c & 0x0F];
	}
	dst[length * 2] = 0;
}

// hexs2bin: performs hexs 2 bin.
int hexs2bin(char* hex, unsigned char* out) {
	int len;
	char   b1;
	char   b2;
	int i;

	if (hex == NULL || *hex == '\0' || out == NULL)
		return 0;

	len = strlen(hex);
	if (len % 2 != 0)
		return 0;
	len /= 2;

	for (i = 0; i < len; i++) {
		if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2)) {
			return 0;
		}
		out[i] = (b1 << 4) | b2;
	}
	return len;
}

// hexchr2bin: performs hexchr 2 bin.
int hexchr2bin(const char hex, char* out) {
	if (out == NULL)
		return 0;

	if (hex >= '0' && hex <= '9') {
		*out = hex - '0';
	}
	else if (hex >= 'A' && hex <= 'F') {
		*out = hex - 'A' + 10;
	}
	else if (hex >= 'a' && hex <= 'f') {
		*out = hex - 'a' + 10;
	}
	else {
		return 0;
	}

	return 1;
}

// addItemList: adds item list.
void addItemList(char* data, List* l) {
	l->data = (char**)realloc(l->data, sizeof(char*) * (l->n + 1));
	l->data[l->n] = data;
	l->n++;
}

// isValidHex: checks whether valid hex is valid.
int isValidHex(char* data) {
	char c;
	int len, i, valid = 1;
	len = strlen(data);
	for (i = 0; i < len && valid; i++) {
		c = data[i];
		valid = ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
	}
	return valid;
}



// formatDouble: formats double.
std::string formatDouble(const char* formatStr, double value)
{
	char buf[100] = { 0 };
	snprintf(buf, sizeof(buf), formatStr, value);

	return std::string(buf);
}
