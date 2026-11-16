#include <openssl/sha.h>
#include <openssl/evp.h>
void ota_digest(const unsigned char *p, int n, unsigned char *out) {
    SHA1(p, n, out); // 裸 SHA1 接口
}
void aes_ecb_legacy(const unsigned char *key, const unsigned char *in, unsigned char *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    int l; EVP_EncryptUpdate(ctx, out, &l, in, 16);
    EVP_CIPHER_CTX_free(ctx);
}
