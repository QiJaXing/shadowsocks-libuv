//
//  local.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-15.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

void client_connect_cb(uv_stream_t * listener, int status) {
	if (status < 0)
		return;
	shadow_t * shadow = shadow_new();
	int iret = 0;
	// initiate first handshake
	handshake_t * hands = calloc(1, sizeof(handshake_t));
	hands->step = 1;
	hands->data = calloc(1, socks5_max_len);
	shadow->data = hands;
	do {
		iret = uv_tcp_init(listener->loop, shadow->client);
		if (iret < 0)
			break;
		iret = uv_accept(listener, (uv_stream_t *) shadow->client);
		if (iret < 0)
			break;
		iret = uv_tcp_nodelay(shadow->client, 1);
		if (iret < 0)
			break;
		iret = uv_read_start((uv_stream_t *) shadow->client, handshake_alloc_cb,
				handshake_read_cb);
		if (iret < 0)
			break;
		return;
	} while (0);
	shadow_free(shadow);
	if (iret < 0)
		fprintf(stderr, "client_connect_cb:\t%s:\t%s\n", uv_err_name(iret), uv_strerror(iret));
}

//void client_readd_cb(uv_stream_t * stream, ssize_t nread, uv_buf_t buf)
void client_read_cb(uv_stream_t * stream, long int nread,
		const struct uv_buf_t * buf) {
	shadow_t * shadow = stream->data;
	if (nread == 0)
		return;
	if (nread > 0) {
		int iret;
		uv_buf_t _ = cipher_encrypt(shadow, buf, nread);
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = _.base;
		iret = uv_write(write, (uv_stream_t *) shadow->remote, &_, 1,
				remote_write_cb);
		if (iret >= 0) {
			return;
		} else {
			fprintf(stderr, "client_read_cb, uv_write:\t%s:\t%s\n", uv_err_name(iret), uv_strerror(iret));
		}
	}
	if (nread < 0) {
		fprintf(stderr, "client_read_cb\t%s:\t%s\n", uv_err_name(nread), uv_strerror(nread));
	}
	uv_close((uv_handle_t *) stream, client_close_cb);
}

void client_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = (shadow_t *) write->handle->data;

	if (!status)
		status = uv_read_start((uv_stream_t *) shadow->remote, shadow_alloc_cb,
				remote_read_cb);

	free(write->data);
	free(write);

	if (status)
		uv_close((uv_handle_t *) shadow->client, client_close_cb);
}

void client_shutdown_cb(uv_shutdown_t * shutdown, int status) {
	shadow_t * shadow = (shadow_t *) shutdown->data;
	// shadow_free(shadow);
	uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	free(shutdown);
}

void client_close_cb(uv_handle_t * handle) {
	shadow_t * shadow = (shadow_t *) handle->data;
	uv_read_stop((uv_stream_t *) shadow->remote);

	uv_shutdown_t * shutdown = malloc(sizeof(uv_shutdown_t));
	shutdown->data = shadow;

	if (!uv_shutdown(shutdown, (uv_stream_t *) shadow->remote,
			remote_shutdown_cb))
		return;

	uv_close((uv_handle_t *) shadow->remote, shadow_free_cb);
	free(shutdown);
}

