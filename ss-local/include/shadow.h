//
//  shadow.h
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-14.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#ifndef _SHADOW_H
#define _SHADOW_H

#include <uv.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#define ERROR    -1
#define KEEP_READ 1

#define PASS "hourui.me@gmail.com"

typedef struct {
	uint8_t ver, cmd, rsv, atyp, body[0];
} socks5_s;

typedef struct {
	socks5_s * data;
	size_t len;
} socks5_t;

#define socks5_max_len sizeof(socks5_t) + 255 + 2

typedef struct {
	uint8_t ver, nmethod, method[255];
} handshake_request_t;

typedef struct {
	uint8_t ver, method;
} handshake_reply_t;

typedef struct {
	void * data;
	size_t size, step;
} handshake_t;

typedef struct {

	size_t keyl;
	uint8_t * key;
	uint8_t * iv;
	size_t ivl;
	uint32_t counter;
	const EVP_CIPHER * type;

	struct {
		int init;
		EVP_CIPHER_CTX ctx;
	} encrypt, decrypt;

} cipher_t;

typedef struct {
	void * data;
	size_t size;
	uv_tcp_t * client;
	uv_tcp_t * remote;
	socks5_t * socks5;
	cipher_t * cipher;
} shadow_t;

typedef struct {
	const char * pass, *method;
	char ota;
	struct {
		const char * ip, *port;
	} local, remote;
} conf_t;

cipher_t * cipher_new();
void cipher_free(cipher_t *);
uv_buf_t cipher_encrypt(shadow_t * shadow, const struct uv_buf_t*, size_t);
uv_buf_t cipher_encrypt_OTA(shadow_t * shadow, const struct uv_buf_t*, size_t);
uv_buf_t cipher_decrypt(shadow_t * shadow, const struct uv_buf_t*, size_t);

void client_close_cb(uv_handle_t *);
void client_read_cb(struct uv_stream_s *, long int, const struct uv_buf_t *);
void client_write_cb(uv_write_t *, int);
void client_connect_cb(uv_stream_t *, int);
void client_shutdown_cb(uv_shutdown_t *, int);

void remote_close_cb(uv_handle_t *);
void remote_read_cb(struct uv_stream_s *, long int, const struct uv_buf_t *);
void remote_write_cb(uv_write_t *, int);
void remote_connect_cb(uv_connect_t *, int);
void remote_shutdown_cb(uv_shutdown_t *, int);
shadow_t * shadow_new(void);
void shadow_free(shadow_t *);
void shadow_free_cb(uv_handle_t *);
void shadow_timer_cb(uv_timer_t *, int);
void shadow_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
void handshake_alloc_cb(uv_handle_t* handle, size_t suggested_size,
		uv_buf_t* buf);
void handshake_read_cb(struct uv_stream_s *, long int, const struct uv_buf_t *);
void handshake_write_cb(uv_write_t *, int);
int handshake(uv_stream_t *);

void fakereply_write_cb(uv_write_t *, int);
void shadow_write_cb(uv_write_t *, int);
#endif /* defined(_SHADOW_H) */
