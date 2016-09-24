//
//  local.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-15.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

void client_connect_cb(uv_stream_t * listener, int status) {
	shadow_t * shadow = shadow_new();
	uv_stream_t * stream = (uv_stream_t *) shadow->client;
	int iret;
	// initiate first handshake
	handshack_t * hands = calloc(1, sizeof(handshack_t));
	hands->step = 1;
	hands->data = calloc(1, socks5_max_len);
	shadow->data = hands;

	// RAND_bytes(shadow->cipher->iv, (int)shadow->cipher->ivl);

	do {
		if (status)
			break;
		iret = uv_tcp_init(listener->loop, shadow->client);
		if (iret < 0)
			break;
		iret = uv_accept(listener, stream);
		if (iret < 0)
			break;
		iret = uv_tcp_nodelay(shadow->client, 1);
		if (iret < 0)
			break;
//    if (uv_tcp_keepalive(shadow->client, 1, 60))          break;
		iret = uv_read_start(stream, handshack_alloc_cb, handshack_readd_cb);
		if (iret < 0)
			break;
		return;

	} while (0);

	shadow_free(shadow);
	fprintf(stderr, "%s:\t%s\n", uv_err_name(iret), uv_strerror(iret));
}

void client_readd_cb(uv_stream_t * stream, ssize_t nread, uv_buf_t buf) {
	shadow_t * shadow = stream->data;
	uv_write_t * write = malloc(sizeof(uv_write_t));

//  printf("%s %ld\n", __FUNCTION__, nread);

	do {
		if (nread <= 0)
			break;
		if (nread == 0)
			return;
		// printf("%s\n", buf.base);
		write->data = buf.base = cipher_encrypt(shadow, &buf.len, buf.base,
				nread);
		// printf("client: %s\n", buf.base);
		if (uv_write(write, (uv_stream_t *) shadow->remote, &buf, 1,
				remote_write_cb))
			break;
		return;
	} while (0);

	printf("client EOF\n");
	uv_close((uv_handle_t *) stream, client_close_cb);
}

void client_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = (shadow_t *) write->handle->data;

	if (!status)
		status = uv_read_start((uv_stream_t *) shadow->remote, shadow_alloc_cb,
				remote_readd_cb);

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

