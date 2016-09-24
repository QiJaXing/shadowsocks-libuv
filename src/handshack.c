//
//  handshack.c
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
handshack_1st(uv_stream_t *, shadow_t *, handshack_t *);

static int
handshack_2nd(uv_stream_t *, shadow_t *, handshack_t *);

int
handshack(uv_stream_t * stream)
{
  shadow_t    * shadow = stream->data;
  handshack_t * hands  = shadow->data;
  
  switch (hands->step) {
    case 1:
      if (hands->size < 2) return KEEP_READ;
      return handshack_1st(stream, shadow, hands);
    case 2:
      if (hands->size < sizeof(socks5_s)) return KEEP_READ;
      return handshack_2nd(stream, shadow, hands);
    default: break;
  }
 
  uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
  return ERROR;
}

static int
handshack_1st(uv_stream_t * stream, shadow_t * shadow, handshack_t * hands)
{
  handshack_request_t * req = hands->data;
  
  if (hands->size < 2 + req->nmethod) return KEEP_READ;
  
  do {
    if (req->ver != 0x5) break;
    uv_read_stop(stream);
    
    handshack_reply_t *
    rep = calloc(1, sizeof(handshack_reply_t));
    rep->ver    = 0x5;
    rep->method = 0;
    
//    printf("No.1 %d %d", req->ver, req->nmethod);
//    uint8_t i = 0;
//    for (; i < req->nmethod; i++) {
//      printf(" %d", req->method[i]);
//    }
//    printf("\n");
    
    uv_buf_t buf;
    buf.len  = sizeof(handshack_reply_t);
    buf.base = (char *)rep;
    
    uv_write_t * write = malloc(sizeof(uv_write_t));
    write->data = rep;
    
    // move to step 2
    hands->step = 2;
    
    if (uv_write(write, stream, &buf, 1, handshack_write_cb)) break;
    return 0;
  } while (0);
  
  uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
  return ERROR;
}

static int
handshack_2nd(uv_stream_t * stream, shadow_t * shadow, handshack_t * hands)
{
  socks5_s * socks = hands->data;
  
  switch (socks->atyp) {
    case 1:
      // ip(4) + port(2)
      shadow->socks5->len = sizeof(socks5_s) + 4 + 2;
      if (hands->size < shadow->socks5->len) return KEEP_READ;
      break;
    case 3:
      // host_len(1)
      shadow->socks5->len  = sizeof(socks5_s) + 1;
      if (hands->size < shadow->socks5->len) return KEEP_READ;
      // host_len(1) + host(host_len) + port(2)
      shadow->socks5->len += socks->body[0] + 2;
      if (hands->size < shadow->socks5->len) return KEEP_READ;
      
//      printf("ver(%d), cmd(%d), rsv(%d), atyp(%d)\n",
//             socks->ver, socks->cmd, socks->rsv, socks->atyp);
//      char * host = memcpy(calloc(1, socks->body[0] + 1), socks->body + 1, socks->body[0]);
//      printf("host(%d): %s\n", socks->body[0], host);
//      uint16_t port;
//      memcpy(&port, socks->body + 1 + socks->body[0], 2);
//      printf("port(%d)\n", ntohs(port));
//      free(host);
      
      break;
      // ipv6 & others
    case 4: default:
      uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
      return ERROR;
  }

  
  shadow->socks5->data = socks;
  uv_read_stop(stream);
  
  struct sockaddr_in remote_addr;
  inet_aton(conf.remote.ip, &remote_addr.sin_addr);
  remote_addr.sin_port   = htons(atoi(conf.remote.port));
  remote_addr.sin_family = AF_INET;
  
  uv_tcp_init(stream->loop, shadow->remote);
  // uv_timer_start(shadow->remote, shadow_timer_cb, 60 * 1000, 0);
  uv_connect_t * req = malloc(sizeof(uv_connect_t));
  req->data          = shadow;
  
  if (!uv_tcp_connect(req, shadow->remote, (const struct sockaddr*)& remote_addr, remote_connect_cb)) return 0;
  uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
  return ERROR;
}


uv_buf_t
handshack_alloc_cb(uv_handle_t * handle, size_t suggest_size)
{
  return uv_buf_init(malloc(socks5_max_len), (unsigned int)(socks5_max_len));
}

void
handshack_readd_cb(uv_stream_t * stream, ssize_t nread, uv_buf_t buf)
{
  shadow_t    * shadow = stream->data;
  handshack_t * hands  = shadow->data;
  
  do {
    if (nread <= 0) break;
    memcpy(hands->data + hands->size, buf.base, nread);
    hands->size += nread;
    handshack(stream);
  } while (0);
  
  free(buf.base);
  if (nread < 0) uv_close((uv_handle_t *)stream, shadow_free_cb);
}

void
handshack_write_cb(uv_write_t * write, int status)
{
  shadow_t    * shadow = write->handle->data;
  handshack_t * hands  = shadow->data;
  
  if (hands->data) free(hands->data);
  hands->data = calloc(1, socks5_max_len);
  hands->size = 0;
  
  if (!status) status = uv_read_start((uv_stream_t *)shadow->client,
                                      handshack_alloc_cb,
                                      handshack_readd_cb);
  free(write->data);
  free(write);
  
  if (status) uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
}

void
fakereply_write_cb(uv_write_t * write, int status)
{ 
  shadow_t * shadow = write->handle->data;
  if (shadow->data) free(shadow->data);
  
  shadow->data = NULL;
  shadow->size = 0;
  
  if (!status) uv_read_start((uv_stream_t *)shadow->client,
                             shadow_alloc_cb,
                             client_readd_cb);
  
  free(write->data);
  free(write);
  
  if (status) uv_close((uv_handle_t *)shadow->client, shadow_free_cb);
}






