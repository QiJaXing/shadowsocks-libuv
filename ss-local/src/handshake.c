//
//  handshake.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-14.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

extern conf_t conf;

/*
 
 +----+----------+----------+
 |VER | NMETHODS | METHODS  |
 +----+----------+----------+
 | 1  |    1     | 1 to 255 |
 +----+----------+----------+
 X'00' NO AUTHENTICATION REQUIRED
 o  X'01' GSSAPI
 o  X'02' USERNAME/PASSWORD
 o  X'03' to X'7F' IANA ASSIGNED
 o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 o  X'FF' NO ACCEPTABLE METHODS
 
 */

static int
handshake_1st(uv_stream_t *, shadow_t *, handshake_t *);

static int
handshake_2nd(uv_stream_t *, shadow_t *, handshake_t *);

int handshake(uv_stream_t * stream) {
	shadow_t * shadow = stream->data;
	handshake_t * hands = shadow->data;

	switch (hands->step) {
	case 1:
		if (hands->size < 2)
			return KEEP_READ;
		return handshake_1st(stream, shadow, hands);
	case 2:
		if (hands->size < sizeof(socks5_s))
			return KEEP_READ;
		return handshake_2nd(stream, shadow, hands);
	default:
		break;
	}
	uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	return ERROR;
}

static int handshake_1st(uv_stream_t * stream, shadow_t * shadow,
		handshake_t * hands) {
	handshake_request_t * req = hands->data;

	if (hands->size < 2 + req->nmethod)
		return KEEP_READ;

	do {
		if (req->ver != 0x5)
			break;
		uv_read_stop(stream);

		handshake_reply_t * rep = calloc(1, sizeof(handshake_reply_t));
		rep->ver = 0x5;
		rep->method = 0;

//    printf("No.1 %d %d", req->ver, req->nmethod);
//    uint8_t i = 0;
//    for (; i < req->nmethod; i++) {
//      printf(" %d", req->method[i]);
//    }
//    printf("\n");

		uv_buf_t buf;
		buf.len = sizeof(handshake_reply_t);
		buf.base = (char *) rep;

		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = rep;
		fprintf(stderr, "handshake step %d finished!\n", hands->step);
		// move to step 2
		hands->step = 2;

		if (uv_write(write, stream, &buf, 1, handshake_write_cb))
			break;
		return 0;
	} while (0);

	uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	return ERROR;
}

static int handshake_2nd(uv_stream_t * stream, shadow_t * shadow,
		handshake_t * hands) {
	socks5_s * socks = hands->data;

	switch (socks->atyp) {
	case 1:
		// ip(4) + port(2)
		shadow->socks5->len = sizeof(socks5_s) + 4 + 2;
		if (hands->size < shadow->socks5->len)
			return KEEP_READ;
		break;
	case 3:
		// host_len(1)
		shadow->socks5->len = sizeof(socks5_s) + 1;
		if (hands->size < shadow->socks5->len)
			return KEEP_READ;
		// host_len(1) + host(host_len) + port(2)
		shadow->socks5->len += socks->body[0] + 2;
		if (hands->size < shadow->socks5->len)
			return KEEP_READ;
		break;
	case 4:
	default:
		uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
		return ERROR;
	}

	shadow->socks5->data = socks;
	uv_read_stop(stream);

	struct sockaddr_in remote_addr;
	inet_aton(conf.remote.ip, &remote_addr.sin_addr);
	remote_addr.sin_port = htons(atoi(conf.remote.port));
	remote_addr.sin_family = AF_INET;

	uv_tcp_init(stream->loop, shadow->remote);
	// uv_timer_start(shadow->remote, shadow_timer_cb, 60 * 1000, 0);
	uv_connect_t * req = malloc(sizeof(uv_connect_t));
	req->data = shadow;

	if (!uv_tcp_connect(req, shadow->remote,
			(const struct sockaddr*) &remote_addr, remote_connect_cb)) {
		fprintf(stderr, "handshake step %d finished!\n", hands->step);
		return 0;
	}
	uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	return ERROR;
}

// uv_buf_t handshake_alloc_cb(uv_handle_t * handle, size_t suggest_size)
void handshake_alloc_cb(uv_handle_t* handle, size_t suggested_size,
		uv_buf_t* buf) {
	char *base = malloc(socks5_max_len);
	unsigned int len = socks5_max_len;
	*buf = uv_buf_init(base, len);
}
//void handshake_read_cb(uv_stream_t *, long int,  const struct uv_buf_t *);
void handshake_read_cb(uv_stream_t *stream, long int nread,
		const struct uv_buf_t *buf) {
	/*
	 * Callback called when data was read on a stream.
	 nread is > 0 if there is data available or < 0 on error. When we’ve reached EOF, nread will be set to UV_EOF.
	 When nread < 0, the buf parameter might not point to a valid buffer; in that case buf.len and buf.base are both
	 set to 0.
	 Note: nread might be 0, which does not indicate an error or EOF. This is equivalent to EAGAIN or
	 EWOULDBLOCK under read(2).
	 The callee is responsible for stopping closing the stream when an error happens by calling uv_read_stop()
	 or uv_close(). Trying to read from the stream again is undefined.
	 The callee is responsible for freeing the buffer, libuv does not reuse it. The buffer may be a null buffer (where
	 buf->base=NULL and buf->len=0) on error.*/

	shadow_t * shadow = stream->data;
	handshake_t * hands = shadow->data;
	int iret = 0;
	if (nread > 0) {
		memcpy(hands->data + hands->size, buf->base, nread);
		free(buf->base);
		hands->size += nread;
		iret = handshake(stream);
	}
	if (nread < 0 || iret == ERROR)
		uv_close((uv_handle_t *) stream, shadow_free_cb);
}

void handshake_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = write->handle->data;
	handshake_t * hands = shadow->data;

	if (hands->data)
		free(hands->data);
	hands->data = calloc(1, socks5_max_len);
	hands->size = 0;

	if (!status)
		status = uv_read_start((uv_stream_t *) shadow->client,
				handshake_alloc_cb, handshake_read_cb);
	free(write->data);
	free(write);

	if (status)
		uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
}

void fakereply_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = write->handle->data;
	if (shadow->data)
		free(shadow->data);

	shadow->data = NULL;
	shadow->size = 0;

	if (!status)
		uv_read_start((uv_stream_t *) shadow->client, shadow_alloc_cb,
				client_read_cb);

	free(write->data);
	free(write);

	if (status)
		uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
}

