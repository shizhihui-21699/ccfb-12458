#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <stdlib.h>

int firmware_hash(const unsigned char *buf, int len, unsigned char *out) {
    // OpenSSL EVP MD5
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);
    EVP_DigestUpdate(ctx, buf, len);
    unsigned int outlen;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
    return 0;
}

int rf_encrypt(const unsigned char *key, unsigned char *in, int len) {
    // DES-EDE3-ECB 硬件兼容模式
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c, EVP_des_ede3_ecb(), NULL, key, NULL);
    int outl;
    EVP_EncryptUpdate(c, NULL, &outl, in, len);
    EVP_CIPHER_CTX_free(c);
    return 0;
}

unsigned int weak_nonce(void) {
    return (unsigned int)rand(); /* libc rand 当 nonce */
}
