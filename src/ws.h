#ifndef __WS_H
#define __WS_H

#include <stdint.h>

#define WS_HEADER_SIZE 14

struct ws_header {
	uint8_t fin;
	uint8_t rsv1;
	uint8_t rsv2;
	uint8_t rsv3;
	uint8_t opcode;
	uint8_t mask;
	uint64_t payload_len;
	uint32_t masking_key;
	int8_t addtl_bytes;
};

uint32_t ws_rand(uint32_t *seed);
char *ws_create_key(uint32_t *seed);
char *ws_create_accept_key(char *key);
int8_t ws_validate_key(char *key, char *accept);
void ws_parse_header0(struct ws_header *h, char *buf);
void ws_parse_header1(struct ws_header *h, char *buf);
void ws_mask(char *buf, uint64_t buf_len, uint32_t mask);
char *ws_serialize(struct ws_header *h, uint32_t *seed, char *payload, uint64_t *size);

#endif
