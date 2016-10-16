#include <shadow.h>

shadow_t *
shadow_new(void) {
	shadow_t * shadow = calloc(1, sizeof(shadow_t));
	shadow->cipher = cipher_new();
	shadow->socks5 = calloc(1, sizeof(socks5_t));
	shadow->client = calloc(1, sizeof(uv_tcp_t));
	shadow->remote = calloc(1, sizeof(uv_tcp_t));
	shadow->remote->data = shadow->client->data = shadow;
	return shadow;
}

void shadow_free(shadow_t * shadow) {
	if (!shadow)
		return;
	if (shadow->data)
		free(shadow->data);
	if (shadow->client)
		free(shadow->client);
	if (shadow->remote)
		free(shadow->remote);
	if (shadow->cipher)
		cipher_free(shadow->cipher);
	if (shadow->socks5) {
		if (shadow->socks5->data)
			free(shadow->socks5->data);
		free(shadow->socks5);
	}
	free(shadow);
	// uv_stop(uv_default_loop());
}

void shadow_free_cb(uv_handle_t * handle) {
	shadow_t * shadow = handle->data;
	shadow_free(shadow);
}
void shadow_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	char *base = malloc(suggested_size);
	unsigned int len = suggested_size;
	*buf = uv_buf_init(base, len);
}

void shadow_write_cb(uv_write_t * write, int status) {
	uv_buf_t * _ = (uv_buf_t *) write->data;
	free(_->base);
	free(write->data);
	free(write);
}
