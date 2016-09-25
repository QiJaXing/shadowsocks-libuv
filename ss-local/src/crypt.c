//
//  crypt.c
//  shadowsocks-libuv
//
//  Created by Cube on 14/11/9.
//  Copyright (c) 2014年 Cube. All rights reserved.
//

#include <shadow.h>

extern conf_t conf;

cipher_t * cipher_new(const char * pass) {
	OpenSSL_add_all_algorithms();
	cipher_t * cipher = calloc(1, sizeof(cipher_t));
	if(cipher==NULL){
		fprintf(stderr,"can not allocate memory for cipher!\n");
		exit(-1);
	}
	cipher->type = EVP_get_cipherbyname(conf.method);
	if(cipher->type ==NULL){
		fprintf(stderr,"encrypt method %s not supported!\n ",conf.method);
		exit(-2);
	}
	cipher->keyl = EVP_CIPHER_key_length(cipher->type);
	cipher->key = malloc(cipher->keyl);
	EVP_CIPHER_CTX_init(&cipher->encrypt.ctx);
	EVP_CIPHER_CTX_init(&cipher->decrypt.ctx);
	EVP_BytesToKey(cipher->type, EVP_md5(), NULL, (uint8_t *) conf.pass,
			(int) strlen(conf.pass), 1, cipher->key, NULL);
	return cipher;
}

void cipher_free(cipher_t * cipher) {
	if (!cipher)
		return;
	if (cipher->key)
		free(cipher->key);
	free(cipher);
}

uv_buf_t  cipher_encrypt(shadow_t * shadow, const struct uv_buf_t* plain,
		size_t plainl) {
	size_t encryptl;
	cipher_t * cipher = shadow->cipher;
	char * encrypt = NULL;
	uint8_t * dst, *src;
	if (!cipher->encrypt.init) {
		int ivl = EVP_CIPHER_iv_length(cipher->type);
		uint8_t * iv = malloc(ivl);
		RAND_bytes(iv, ivl);
		EVP_CipherInit_ex(&cipher->encrypt.ctx, cipher->type, NULL, cipher->key,
				iv, 1);
		size_t prepend = shadow->socks5->len - 3;
		uint8_t *ptr;
		src = malloc(prepend + plainl);
		ptr = src + prepend;
		memcpy(src, &shadow->socks5->data->atyp, prepend);
		memcpy(ptr, plain->base, plainl);
		plainl += prepend;
		encryptl = ivl + plainl;
		encrypt = malloc(encryptl);
		memcpy(encrypt, iv, ivl);
		dst = (uint8_t *) encrypt + ivl;
		free(iv);
		//plain->base = (char *) src;
		cipher->encrypt.init = 1;
	} else {
		encryptl = plainl;
		encrypt = malloc(encryptl);
		dst = (uint8_t *) encrypt;
		src = (uint8_t *)plain->base;
	}
	int _;
	EVP_CipherUpdate(&cipher->encrypt.ctx, dst, &_, (uint8_t *) plain->base,
			(int) plainl);
	free(plain->base);
	return uv_buf_init(encrypt, encryptl);
}

uv_buf_t cipher_decrypt(shadow_t * shadow, const struct uv_buf_t* encrypt,
		size_t encryptl) {
	size_t plainl;
	cipher_t * cipher = shadow->cipher;
	char * plain = NULL;
	uint8_t * src;
	if (!cipher->decrypt.init) {
		int ivl = EVP_CIPHER_iv_length(cipher->type);
		uint8_t * iv = malloc(ivl);
		memcpy(iv, encrypt, ivl);

		plainl = encryptl - ivl;
		plain = malloc(plainl);
		src = (uint8_t *) encrypt + ivl;
		EVP_CipherInit_ex(&cipher->decrypt.ctx, cipher->type, NULL, cipher->key,
				iv, 0);
		free(iv);
		cipher->decrypt.init = 1;
	} else {
		plainl = encryptl;
		src = (uint8_t *) encrypt;
		plain = malloc(plainl);
	}
	int _;
	EVP_CipherUpdate(&cipher->decrypt.ctx, (uint8_t *) plain, &_, src,
			(int) plainl);
	free(encrypt->base);
	//return plain;
	return uv_buf_init(plain, plainl);
}
