// Copyright (c) 2017-2020 Christopher D. Dickson <cdd@matoya.group>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "ws.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "tls.h"

#if defined(__WINDOWS__)
	#include <winsock2.h>

#elif !defined(__APPLE__) && defined(__UNIXY__)
	#include <arpa/inet.h>
	#include <endian.h>
	#define ntohll be64toh
	#define htonll htobe64
#endif

#define SHA1_LEN 20

static char *ENC64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static char *WSMAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

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

char *ws_create_accept_key(char *key)
{
	size_t buf_len = strlen(key) + strlen(WSMAGIC) + 1;
	char *buf = malloc(buf_len);
	snprintf(buf, buf_len, "%s%s", key, WSMAGIC);

	uint8_t sha1[SHA1_LEN];
	tls_sha1(sha1, buf);
	free(buf);

	return ws_base64((char *) sha1, SHA1_LEN);
}

int8_t ws_validate_key(char *key, char *accept_in)
{
	char *accept_key = ws_create_accept_key(key);
	int8_t r = strcmp(accept_key, accept_in) ? 0 : 1;
	free(accept_key);

	return r;
}

void ws_parse_header0(struct ws_header *h, char *buf)
{
	memset(h, 0, sizeof(struct ws_header));

	char b = buf[0];
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

void ws_mask(char *out, char *in, uint64_t buf_len, uint32_t mask)
{
	char *key = (char *) &mask;

	for (uint64_t x = 0; x < buf_len; x++)
		out[x] = in[x] ^ key[x % 4];
}

void ws_serialize(struct ws_header *h, uint32_t *seed, char *payload, char *out, uint64_t *out_size)
{
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

	//mask if necessary
	if (h->mask) {
		ws_mask(out + o, payload, h->payload_len, h->masking_key);
	} else {
		memcpy(out + o, payload, (size_t) h->payload_len);
	}

	*out_size = o + h->payload_len;
}
