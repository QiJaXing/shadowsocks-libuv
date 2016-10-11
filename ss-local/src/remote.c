//
//  remote.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-15.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

void remote_connect_cb(uv_connect_t * req, int status) {
	shadow_t * shadow = (shadow_t *) req->data;
	uv_stream_t * stream = (uv_stream_t *) shadow->client;
	if (status < 0)
		uv_close((uv_handle_t *) shadow->remote, remote_close_cb);
	if (status == 0) {
		socks5_s * fake = calloc(1, sizeof(socks5_s) + 6);
		fake->ver = 5;
		fake->cmd = 0;
		fake->rsv = 0;
		fake->atyp = 1;
		uv_buf_t buf;
		buf.len = sizeof(socks5_s) + 6;
		buf.base = (char *) fake;
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = fake;
		status = uv_write(write, stream, &buf, 1, fakereply_write_cb);
	}
	free(req);
}

void remote_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = (shadow_t *) write->handle->data;
	if (!status)
		status = uv_read_start((uv_stream_t *) shadow->remote, shadow_alloc_cb,
				remote_read_cb);
	free(write->data);
	free(write);
	if (status)
		uv_close((uv_handle_t *) shadow->remote, remote_close_cb);
}

//void remote_read_cb(uv_stream_t * stream, ssize_t nread, uv_buf_t buf)
void remote_read_cb(uv_stream_t * stream, long int nread,
		const struct uv_buf_t *buf) {
	shadow_t * shadow = stream->data;
	if (nread == 0)
		return;
	if (nread > 0) {
		int iret;
		uv_buf_t _ = cipher_decrypt(shadow, buf, nread);
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = _.base;
		iret = uv_write(write, (uv_stream_t *) shadow->client, &_, 1,
				shadow_write_cb);
		if (iret >= 0) {
			return;
		} else {
			fprintf(stderr, "remote_read_cb, uv_write\t%s:\t%s\n",
					uv_err_name(iret), uv_strerror(iret));
		}
	}
	uv_close((uv_handle_t *) stream, remote_close_cb);
}

void remote_shutdown_cb(uv_shutdown_t * shutdown, int status) {
	shadow_t * shadow = (shadow_t *) shutdown->data;
// shadow_free(shadow);
	uv_close((uv_handle_t *) shadow->remote, shadow_free_cb);
	free(shutdown);
}

void remote_close_cb(uv_handle_t * handle) {
	shadow_t * shadow = (shadow_t *) handle->data;
	uv_read_stop((uv_stream_t *) shadow->client);

	uv_shutdown_t * shutdown = malloc(sizeof(uv_shutdown_t));
	shutdown->data = shadow;

	if (!uv_shutdown(shutdown, (uv_stream_t *) shadow->client,
			client_shutdown_cb))
		return;

	uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	free(shutdown);
}
