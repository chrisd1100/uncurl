#include "ws.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(__WINDOWS__)
	#include <winsock2.h>
#endif

static char *ENC64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

uint32_t ws_rand(uint32_t *seed)
{
	if (!*seed) *seed = (uint32_t) time(NULL);

	*seed ^= *seed << 13;
	*seed ^= *seed >> 17;
	*seed ^= *seed << 5;

	return *seed;
}

static char *ws_base64(char *buf, int32_t len)
{
	int32_t p = 0;
	int8_t rem, shift, b;

	char *out = calloc(((len + 2) / 3 * 4) + 1, 1);

	for (int32_t x = 0; x < len; x += 3) {
		b = buf[x];
		shift = (b >> 2) & 0x3f;
		out[p++] = ENC64[shift];
		rem = (b << 4) & 0x30;

		if (x + 1 < len) {
			b = buf[x + 1];
			shift = (b >> 4) & 0x0f;
			out[p++] = ENC64[rem | shift];
			rem = (b << 2) & 0x3c;
		} else out[p + 2] = '=';

		if (x + 2 < len) {
			b = buf[x + 2];
			shift = (b >> 6) & 0x03;
			out[p++] = ENC64[rem | shift];
			rem = (b << 0) & 0x3f;
		} else out[p + 1] = '=';

		out[p++] = ENC64[rem];
	}

	return out;
}

char *ws_create_key(uint32_t *seed)
{
	uint32_t buf[4];

	for (int32_t x = 0; x < 4; x++)
		buf[x] = ws_rand(seed);

	return ws_base64((char *) buf, 16);
}

void ws_parse_header0(struct ws_header *h, char *buf)
{
	char b;

	memset(h, 0, sizeof(struct ws_header));

	b = buf[0];
	h->fin = (b & 0x80) ? 1 : 0;
	h->rsv1 = (b & 0x40) ? 1 : 0;
	h->rsv2 = (b & 0x20) ? 1 : 0;
	h->rsv3 = (b & 0x10) ? 1 : 0;
	h->opcode = b & 0x0f;

	b = buf[1];
	h->mask = (b & 0x80) ? 1 : 0;
	h->payload_len = b & 0x7f;

	if (h->payload_len == 126) h->addtl_bytes += 2;
	if (h->payload_len == 127) h->addtl_bytes += 8;
	if (h->mask) h->addtl_bytes += 4;
}

void ws_parse_header1(struct ws_header *h, char *buf)
{
	uint32_t o = 0;

	//payload len of < 126 uses 1 bytes, == 126 uses 2 bytes, == 127 uses 8 bytes
	if (h->payload_len == 126) {
		uint16_t *b16 = (uint16_t *) buf;
		h->payload_len = ntohs(*b16);
		o += 2;

	} else if (h->payload_len == 127) {
		uint64_t *b64 = (uint64_t *) buf;
		h->payload_len = ntohll(*b64);
		o += 8;
	}

	if (h->mask) {
		uint32_t *b32 = (uint32_t *) (buf + o);
		h->masking_key = *b32;
	}
}

void ws_mask(char *buf, uint64_t buf_len, uint32_t mask)
{
	char *key = (char *) &mask;

	for (uint64_t x = 0; x < buf_len; x++)
		buf[x] ^= key[x % 4];
}

char *ws_serialize(struct ws_header *h, uint32_t *seed, char *payload, uint64_t *size)
{
	char *out = calloc(h->payload_len + WS_HEADER_SIZE, 1);
	uint64_t o = 0;

	char b = 0;
	if (h->fin) b |= 0x80;
	if (h->rsv1) b |= 0x40;
	if (h->rsv2) b |= 0x20;
	if (h->rsv3) b |= 0x10;
	b |= (h->opcode & 0x0f);
	out[o++] = b;

	b = 0;
	if (h->mask) b |= 0x80;

	//payload len calculations -- can use 1, 2, or 8 bytes
	if (h->payload_len < 126) {
		uint8_t l = (uint8_t ) h->payload_len;
		b |= l;
		out[o++] = b;

	} else if (h->payload_len >= 126 && h->payload_len <= UINT16_MAX) {
		uint16_t l = htons((uint16_t) h->payload_len);
		b |= 0x7e;
		out[o++] = b;

		memcpy(out + o, &l, 2);
		o += 2;

	} else {
		uint64_t l = htonll((uint64_t) h->payload_len);
		b |= 0x7f;
		out[o++] = b;

		memcpy(out + o, &l, 8);
		o += 8;
	}

	//generate the mask randomly
	if (h->mask) {
		h->masking_key = ws_rand(seed);
		memcpy(out + o, &h->masking_key, 4);
		o += 4;
	}

	//payload goes here
	memcpy(out + o, payload, h->payload_len);

	//mask if necessary
	if (h->mask)
		ws_mask(out + o, h->payload_len, h->masking_key);

	*size = o + h->payload_len;

	return out;
}
