#include <shadow.h>

void remote_connect_cb(uv_connect_t * req, int status) {
	shadow_t * shadow = (shadow_t *) req->data;
	uv_stream_t * stream = (uv_stream_t *) shadow->client;
	if (status < 0)
		uv_close((uv_handle_t *) shadow->remote, remote_close_cb);
	if (status == 0) {
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = malloc(sizeof(uv_buf_t));
		socks5_s * fake = calloc(1, sizeof(socks5_s) + 6);
		fake->ver = 5;
		fake->cmd = 0;
		fake->rsv = 0;
		fake->atyp = 1;
		uv_buf_t* buf = write->data;
		buf->len = sizeof(socks5_s) + 6;
		buf->base = (char *) fake;
		if (uv_write(write, stream, write->data, 1, fakereply_write_cb)) {
			uv_close((uv_handle_t *) shadow->remote, remote_close_cb);
		}
	}
	free(req);
}

void remote_write_cb(uv_write_t * write, int status) {
	shadow_t * shadow = (shadow_t *) write->handle->data;
	if (status == UV_ECANCELED || status == UV_ECONNRESET) {
		if (!uv_is_closing((uv_handle_t *) shadow->remote))
			uv_close((uv_handle_t *) shadow->remote, remote_close_cb);
	}
	if (!status)
		status = uv_read_start((uv_stream_t *) shadow->remote, shadow_alloc_cb,
				remote_read_cb);
	uv_buf_t * _ = (uv_buf_t *) write->data;
	free(_->base);
	free(write->data);
	free(write);

}

void remote_read_cb(uv_stream_t * stream, long int nread, const uv_buf_t *buf) {
	shadow_t * shadow = stream->data;
	int iret=-1;
	if (nread > 0) {
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = malloc(sizeof(uv_buf_t));
		*(uv_buf_t*) write->data = cipher_decrypt(shadow, buf, nread);
		iret = uv_write(write, (uv_stream_t *) shadow->client, write->data, 1,
				shadow_write_cb);
		if (iret < 0) {
			free(((uv_buf_t*) write->data)->base);
			free(write->data);
			free(write);
			fprintf(stderr, "remote_read_cb, uv_write\t%s:\t%s\n",
					uv_err_name(iret), uv_strerror(iret));
		}
	}
	if (buf->base)
		free(buf->base);
	if (nread == 0 || iret >= 0) {
		return;
	}
	uv_close((uv_handle_t *) stream, remote_close_cb);
}

void remote_shutdown_cb(uv_shutdown_t * shutdown, int status) {
	shadow_t * shadow = (shadow_t *) shutdown->data;
	if (!uv_is_closing((uv_handle_t *) shadow->remote)) {
		uv_close((uv_handle_t *) shadow->remote, shadow_free_cb);
	}
	free(shutdown);
}

void remote_close_cb(uv_handle_t * handle) {
	shadow_t * shadow = (shadow_t *) handle->data;
	uv_read_stop((uv_stream_t *) shadow->client);
	uv_shutdown_t shutdown = malloc(sizeof(uv_shutdown_t));
	shutdown->data = shadow;
	uv_shutdown(shutdown, (uv_stream_t *) shadow->client, client_shutdown_cb);
}
