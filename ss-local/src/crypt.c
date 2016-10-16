#include <shadow.h>

extern conf_t conf;

cipher_t * cipher_new() {
	//OpenSSL_add_all_algorithms();
	OpenSSL_add_all_algorithms();
	cipher_t * cipher = calloc(1, sizeof(cipher_t));
	if (cipher == NULL) {
		fprintf(stderr, "can not allocate memory for cipher!\n");
		exit(-1);
	}
	cipher->type = EVP_get_cipherbyname(conf.method);
	if (cipher->type == NULL) {
		fprintf(stderr, "encrypt method %s not supported!\n ", conf.method);
		exit(-2);
	}
	cipher->keyl = EVP_CIPHER_key_length(cipher->type);
	cipher->key = malloc(cipher->keyl);
	cipher->encrypt.ctx = EVP_CIPHER_CTX_new();
	cipher->decrypt.ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(cipher->encrypt.ctx);
	EVP_CIPHER_CTX_init(cipher->decrypt.ctx);
	EVP_BytesToKey(cipher->type, EVP_md5(), NULL, (uint8_t *) conf.pass,
			(int) strlen(conf.pass), 1, cipher->key, NULL);
	return cipher;
}

void cipher_free(cipher_t * cipher) {
	if (!cipher)
		return;
	if (cipher->encrypt.init)
		EVP_CIPHER_CTX_free(cipher->encrypt.ctx);
	if (cipher->decrypt.init)
		EVP_CIPHER_CTX_free(cipher->decrypt.ctx);
	EVP_cleanup();
	if (cipher->key)
		free(cipher->key);
	if (cipher->iv)
		free(cipher->iv);
	free(cipher);
}
uv_buf_t cipher_encrypt_OTA(shadow_t * shadow, const struct uv_buf_t* plain,
		size_t plainl) {
	size_t encryptl, srcl;
	cipher_t * cipher = shadow->cipher;
	uint8_t * dst, *src, *encrypt;
	uint32_t *counter;
	if (!cipher->encrypt.init) {
		shadow->socks5->data->atyp |= 0x10;
		int ivl = EVP_CIPHER_iv_length(cipher->type);
		uint8_t * iv = malloc(ivl + cipher->keyl);
		RAND_bytes(iv, ivl);
		EVP_CipherInit_ex(cipher->encrypt.ctx, cipher->type, NULL, cipher->key,
				iv, 1);
		memcpy(iv + ivl, cipher->key, cipher->keyl);
		size_t prepend = shadow->socks5->len - 3;
		encryptl = ivl + prepend + 10 + sizeof(uint16_t) + 10 + plainl;
		uint8_t *ptr;
		src = malloc(
				prepend + 10 + sizeof(uint16_t) + 10
						+ (plainl > 10 ? plainl : 10));
		ptr = src + prepend;
		memcpy(src, &shadow->socks5->data->atyp, prepend);
		HMAC(EVP_sha1(), iv, ivl + cipher->keyl, (unsigned char*) src, prepend,
				ptr, NULL);
		ptr += 10;
		uint16_t data_len = htons((uint16_t) plainl);
		memcpy(ptr, &data_len, sizeof(uint16_t));
		ptr += sizeof(uint16_t);
		cipher->counter = 0;
		counter = (uint32_t *) (iv + ivl);
		*counter = htonl(cipher->counter);
		HMAC(EVP_sha1(), iv, ivl + sizeof(uint32_t),
				(unsigned char*) plain->base, plainl, ptr, NULL);
		ptr += 10;
		memcpy(ptr, plain->base, plainl);
		encrypt = malloc(encryptl);
		memcpy(encrypt, iv, ivl);
		dst = (uint8_t *) (encrypt + ivl);
		cipher->iv = iv;
		cipher->ivl = ivl;
		cipher->encrypt.init = 1;
		srcl = prepend + 10 + sizeof(uint16_t) + 10 + plainl;
	} else {
		encryptl = plainl + sizeof(uint16_t) + 10;
		dst = (uint8_t *) malloc(encryptl);
		encrypt = dst;
		src = (uint8_t *) malloc(
				plainl > 10 ? encryptl : sizeof(uint16_t) + 20);
		uint16_t data_len = htons((uint16_t) plainl);
		memcpy(src, &data_len, sizeof(uint16_t));
		cipher->counter++;
		counter = (uint32_t *) (cipher->iv + cipher->ivl);
		*counter = htonl(cipher->counter);
		HMAC(EVP_sha1(), cipher->iv, cipher->ivl + sizeof(uint32_t),
				(unsigned char*) plain->base, plainl, src + sizeof(uint16_t),
				NULL);
		memcpy(src + sizeof(uint16_t) + 10, plain->base, plainl);
		srcl = encryptl;
	}
	int _;
	EVP_CipherUpdate(cipher->encrypt.ctx, dst, &_, src, (int) srcl);
	free(src);
	return uv_buf_init((char *) encrypt, encryptl);
}
uv_buf_t cipher_encrypt(shadow_t * shadow, const struct uv_buf_t* plain,
		size_t plainl) {
	size_t encryptl;
	cipher_t * cipher = shadow->cipher;
	char * encrypt = NULL;
	uint8_t * dst, *src;
	if (!cipher->encrypt.init) {
		int ivl = EVP_CIPHER_iv_length(cipher->type);
		uint8_t * iv = malloc(ivl);
		RAND_bytes(iv, ivl);
		EVP_CipherInit_ex(cipher->encrypt.ctx, cipher->type, NULL, cipher->key,
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
		cipher->encrypt.init = 1;
	} else {
		encryptl = plainl;
		encrypt = malloc(encryptl);
		dst = (uint8_t *) encrypt;
		src = (uint8_t *) plain->base;
	}
	int _;
	EVP_CipherUpdate(cipher->encrypt.ctx, dst, &_, src, (int) plainl);
	if (!cipher->encrypt.init) {
		free(src);
	}
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
		memcpy(iv, encrypt->base, ivl);

		plainl = encryptl - ivl;
		plain = malloc(plainl);
		src = (uint8_t *) encrypt->base + ivl;
		EVP_CipherInit_ex(cipher->decrypt.ctx, cipher->type, NULL, cipher->key,
				iv, 0);
		free(iv);
		cipher->decrypt.init = 1;
	} else {
		plainl = encryptl;
		src = (uint8_t *) encrypt->base;
		plain = malloc(plainl);
	}
	int _;
	EVP_CipherUpdate(cipher->decrypt.ctx, (uint8_t *) plain, &_, src,
			(int) plainl);
	return uv_buf_init(plain, plainl);
}
