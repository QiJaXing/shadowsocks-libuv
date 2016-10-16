#include <shadow.h>
extern conf_t conf;
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
		fprintf(stderr, "client_connect_cb:\t%s:\t%s\n", uv_err_name(iret),
				uv_strerror(iret));
}

void client_read_cb(uv_stream_t * stream, long int nread, const uv_buf_t * buf) {
	shadow_t * shadow = stream->data;
	int iret = -1;
	if (nread > 0) {
		uv_write_t * write = malloc(sizeof(uv_write_t));
		write->data = malloc(sizeof(uv_buf_t));
		if (conf.ota) {
			*(uv_buf_t*) write->data = cipher_encrypt_OTA(shadow, buf, nread);
		} else {
			*(uv_buf_t*) write->data = cipher_encrypt(shadow, buf, nread);
		}
		iret = uv_write(write, (uv_stream_t *) shadow->remote, write->data, 1,
				remote_write_cb);
		if (iret < 0) {
			free(((uv_buf_t*) write->data)->base);
			free(write->data);
			free(write);
			fprintf(stderr, "client_read_cb, uv_write:\t%s:\t%s\n",
					uv_err_name(iret), uv_strerror(iret));
		}
	}
	if (buf->base)
		free(buf->base);
	if (nread == 0 || iret >= 0) {
		return;
	}
	uv_close((uv_handle_t *) stream, client_close_cb);
}



void client_shutdown_cb(uv_shutdown_t * shutdown, int status) {
	shadow_t * shadow = (shadow_t *) shutdown->data;
	if (!uv_is_closing((uv_handle_t *) shadow->client)) {
		uv_close((uv_handle_t *) shadow->client, shadow_free_cb);
	}
	free(shutdown);
}

void client_close_cb(uv_handle_t * handle) {
	shadow_t * shadow = (shadow_t *) handle->data;
	uv_read_stop((uv_stream_t *) shadow->remote);
	uv_shutdown_t * shutdown = malloc(sizeof(uv_shutdown_t));
	shutdown->data = shadow;
	uv_shutdown(shutdown, (uv_stream_t *) shadow->remote, remote_shutdown_cb);
}

