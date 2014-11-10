//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

extern conf_t conf;

cipher_t * cipher_new(const char * pass)
{
  OpenSSL_add_all_algorithms();
  
//  const char * name;
//  name = "aes-128-cfb";
//  name = "bf-cfb";
  
  cipher_t *
  cipher       = calloc(1, sizeof(cipher_t));
  cipher->type = EVP_get_cipherbyname(conf.method);
  cipher->keyl = EVP_CIPHER_key_length(cipher->type);
  cipher->key  = malloc(cipher->keyl);
  
  EVP_CIPHER_CTX_init(&cipher->encrypt.ctx);
  EVP_CIPHER_CTX_init(&cipher->decrypt.ctx);
  
  EVP_BytesToKey(cipher->type, EVP_md5(), NULL,
                 (uint8_t *)conf.pass, (int)strlen(conf.pass), 1,
                 cipher->key, NULL);
  
  return cipher;
}

void cipher_free(cipher_t * cipher)
{
  if (!cipher) return;
  if (cipher->key) free(cipher->key);
  free(cipher);
}

char * cipher_encrypt(shadow_t * shadow, size_t * encryptl,
                      char     *  plain, size_t     plainl)
{
  cipher_t * cipher   = shadow->cipher;
  char     * encrypt  = NULL;

  uint8_t * dst;
  
//  int i;
  
  if (!cipher->encrypt.init)
  {
    int       ivl = EVP_CIPHER_iv_length(cipher->type);
    uint8_t * iv  = malloc(ivl);
    RAND_bytes(iv, ivl);
    
    EVP_CipherInit_ex(&cipher->encrypt.ctx, cipher->type, NULL, cipher->key, iv, 1);
    
    size_t prepend = shadow->socks5->len - 3;
    
    uint8_t * src, * ptr;
    src = malloc(prepend + plainl);
    ptr = src + prepend;
    memcpy(src, &shadow->socks5->data->atyp, prepend);
    memcpy(ptr, plain, plainl);
    plainl += prepend;
    
    *encryptl = ivl + plainl;
     encrypt  = malloc(*encryptl);
    memcpy(encrypt, iv, ivl);
     dst      = (uint8_t *)encrypt + ivl;

//    printf("---iv---\n");
//    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
//    printf("\n");
//
//    printf("---key---\n");
//    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
//    printf("\n");
    
    free(iv);
    plain = (char *)src;
    cipher->encrypt.init = 1;
  } else {
    
    *encryptl = plainl;
     encrypt  = malloc(*encryptl);
     dst      = (uint8_t *)encrypt;
  }
  
  int _;
  EVP_CipherUpdate(&cipher->encrypt.ctx, dst, &_, (uint8_t *)plain, (int)plainl);
//  printf("---encrypt count---\n");
//  printf("%d %lu %lu\n", _, *encryptl, plainl);
  
//  printf("---encrypt plain---\n");
//  for (i = 0; i < 20; i++) printf("%02x ", src[i]);
//  printf("\n");
  
//  printf("---encrypt---\n");
//  for (i = 0; i < len; i++) printf("%02x ", dst[i]);
//  printf("\n");
  
  free(plain);
  
  return encrypt;
}

char * cipher_decrypt(shadow_t * shadow,  size_t *   plainl,
                      char     * encrypt, size_t   encryptl)
{
  cipher_t      * cipher = shadow->cipher;
  char          * plain  = NULL;
  
  uint8_t * src;
  
//  int i;
  
  if (!cipher->decrypt.init)
  {
    int       ivl = EVP_CIPHER_iv_length(cipher->type);
    uint8_t * iv  = malloc(ivl);
    memcpy(iv, encrypt, ivl);
    
   *plainl = encryptl - ivl;
    plain  = malloc(*plainl);
    src    = (uint8_t *)encrypt + ivl;
    EVP_CipherInit_ex(&cipher->decrypt.ctx, cipher->type, NULL, cipher->key, iv, 0);
    
//    printf("---iv---\n");
//    for (i = 0; i < ivl; i++) printf("%02x ", iv[i]);
//    printf("\n");
//
//    printf("---key---\n");
//    for (i = 0; i < cipher->keyl; i++) printf("%02x ", cipher->key[i]);
//    printf("\n");
    
    free(iv);
    cipher->decrypt.init = 1;
  } else {
    
   *plainl = encryptl;
    src    = (uint8_t *)encrypt;
    plain  = malloc(*plainl);
    
  }
  
  int _;
  EVP_CipherUpdate(&cipher->decrypt.ctx, (uint8_t *)plain, &_, src, (int)*plainl);
  
//  printf("---decrypt plain---\n");
//  for (i = 0; i < 5; i++) printf("%02x ", (unsigned char)plain[i]);
//  printf("\n");
  
  free(encrypt);
  
  return plain;
}
