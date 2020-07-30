// Copyright (c) 2017-2020 Christopher D. Dickson <cdd@matoya.group>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "net.h"

struct tls_context;
struct tls_state;

int32_t tlss_alloc(struct tls_state **tlss_in);
void tlss_free(struct tls_state *tlss);
int32_t tlss_load_cacert(struct tls_state *tlss, char *cacert, size_t size);
int32_t tlss_load_cacert_file(struct tls_state *tlss, char *cacert_file);
int32_t tlss_load_cert_and_key(struct tls_state *tlss, char *cert, size_t cert_size, char *key, size_t key_size);

void tls_close(struct tls_context *tls);
int32_t tls_connect(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, char *host, bool verify_host, int32_t timeout_ms);
int32_t tls_accept(struct tls_context **tls_in, struct tls_state *tlss,
	struct net_context *nc, int32_t timeout_ms);

int32_t tls_write(void *ctx, char *buf, size_t size);
int32_t tls_read(void *ctx, char *buf, size_t size, int32_t timeout_ms);

void tls_sha1(uint8_t *dest, char *src);
