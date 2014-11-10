//
//  shadow.c
//  shadowsocks-libuv
//
//  Created by Cube on 14-9-14.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

shadow_t *
shadow_new(void)
{
  shadow_t * shadow    = calloc(1, sizeof(shadow_t));
  shadow->cipher       = cipher_new(PASS);
  shadow->socks5       = calloc(1, sizeof(socks5_t));
  shadow->client       = calloc(1, sizeof(uv_tcp_t));
  shadow->remote       = calloc(1, sizeof(uv_tcp_t));
  shadow->remote->data = shadow->client->data = shadow;
  return shadow;
}

void
shadow_free(shadow_t * shadow)
{
  if (!shadow) return;
  if (shadow->data)   free(shadow->data);
  if (shadow->client) free(shadow->client);
  if (shadow->remote) free(shadow->remote);
  if (shadow->cipher) cipher_free(shadow->cipher);
  if (shadow->socks5) {
    if (shadow->socks5->data) free(shadow->socks5->data);
    free(shadow->socks5);
  }
  free(shadow);
}

void
shadow_free_cb(uv_handle_t * handle)
{
  shadow_t * shadow = handle->data;
  shadow_free(shadow);
  // printf("closed\n");
}

uv_buf_t
shadow_alloc_cb(uv_handle_t * handle, size_t suggest_size)
{
  return uv_buf_init(malloc(suggest_size), (unsigned int)(suggest_size));
}

void
shadow_write_cb(uv_write_t * write, int status)
{
  free(write->data);
  free(write);
}
