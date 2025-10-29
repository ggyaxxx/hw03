#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <unistd.h>

#define BLOCK_SIZE 4096

void generate_random_file(const char *filename, size_t size) {
    FILE *f = fopen(filename, "wb");
    unsigned char *data = malloc(size);
    RAND_bytes(data, size);
    fwrite(data, 1, size, f);
    fclose(f);
    free(data);
}

// ---------- AES128-CTR + HMAC ----------
int enc_then_mac_aes128ctr(const char *input_fn, const char *output_fn,
                           unsigned char *enc_key, unsigned char *iv, unsigned char *mac_key) {
    FILE *fin = fopen(input_fn, "rb");
    FILE *fout = fopen(output_fn, "wb");
    if (!fin || !fout) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    HMAC_CTX *hctx = HMAC_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, enc_key, iv);
    HMAC_Init_ex(hctx, mac_key, 16, EVP_sha256(), NULL);

    fwrite(iv, 1, 16, fout);
    HMAC_Update(hctx, iv, 16);

    unsigned char inbuf[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BLOCK_SIZE, fin)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, fout);
        HMAC_Update(hctx, outbuf, outlen);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, fout);
    HMAC_Update(hctx, outbuf, outlen);

    unsigned char tag[32];
    unsigned int taglen;
    HMAC_Final(hctx, tag, &taglen);
    fwrite(tag, 1, taglen, fout);

    fclose(fin); fclose(fout);
    EVP_CIPHER_CTX_free(ctx); HMAC_CTX_free(hctx);
    return 1;
}

// ---------- ChaCha20 + HMAC ----------
int enc_then_mac_chacha20(const char *input_fn, const char *output_fn,
                          unsigned char *enc_key, unsigned char *nonce, unsigned char *mac_key) {
    FILE *fin = fopen(input_fn, "rb");
    FILE *fout = fopen(output_fn, "wb");
    if (!fin || !fout) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    HMAC_CTX *hctx = HMAC_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, enc_key, nonce);
    HMAC_Init_ex(hctx, mac_key, 32, EVP_sha256(), NULL);

    fwrite(nonce, 1, 12, fout);
    HMAC_Update(hctx, nonce, 12);

    unsigned char inbuf[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BLOCK_SIZE, fin)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, fout);
        HMAC_Update(hctx, outbuf, outlen);
    }

    unsigned char tag[32];
    unsigned int taglen;
    HMAC_Final(hctx, tag, &taglen);
    fwrite(tag, 1, taglen, fout);

    fclose(fin); fclose(fout);
    EVP_CIPHER_CTX_free(ctx); HMAC_CTX_free(hctx);
    return 1;
}

// ---------- AES-128-GCM (AEAD) ----------
int enc_aes128gcm(const char *input_fn, const char *output_fn,
                  unsigned char *key, unsigned char *iv) {
    FILE *fin = fopen(input_fn, "rb");
    FILE *fout = fopen(output_fn, "wb");
    if (!fin || !fout) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    fwrite(iv, 1, 12, fout);

    unsigned char inbuf[BLOCK_SIZE];
    unsigned char outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, BLOCK_SIZE, fin)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, fout);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, fout);

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    fwrite(tag, 1, 16, fout);

    fclose(fin); fclose(fout);
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

// ---------- MAIN ----------
int main() {
    OpenSSL_add_all_algorithms();

    char cwd[512];
    getcwd(cwd, sizeof(cwd));
    printf("Current working directory: %s\n", cwd);

    unsigned char aes_key[16], aes_iv[16];
    unsigned char chacha_key[32], chacha_nonce[12];
    unsigned char gcm_key[16], gcm_iv[12];
    unsigned char mac_key[32];

    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));
    RAND_bytes(chacha_key, sizeof(chacha_key));
    RAND_bytes(chacha_nonce, sizeof(chacha_nonce));
    RAND_bytes(gcm_key, sizeof(gcm_key));
    RAND_bytes(gcm_iv, sizeof(gcm_iv));
    RAND_bytes(mac_key, sizeof(mac_key));

    size_t FILE_SIZE = 512 * 1024 * 1024; // 512 MB
    generate_random_file("testfile.bin", FILE_SIZE);
    const char *input = "testfile.bin";

    const char *inputs[] = {"tiny.bin", "medium.bin", "large.bin"};

    printf("=== AES-128-CTR + HMAC ===\n");
    clock_t start = clock();
    enc_then_mac_aes128ctr(input, "aesctr_hmac.enc", aes_key, aes_iv, mac_key);
    clock_t end = clock();
    printf("Time: %.6f s\n", (double)(end - start) / CLOCKS_PER_SEC);

    printf("\n=== ChaCha20 + HMAC ===\n");
    start = clock();
    enc_then_mac_chacha20(input, "chacha_hmac.enc", chacha_key, chacha_nonce, mac_key);
    end = clock();
    printf("Time: %.6f s\n", (double)(end - start) / CLOCKS_PER_SEC);

    printf("\n=== AES-128-GCM (AEAD) ===\n");
    start = clock();
    enc_aes128gcm(input, "aesgcm.enc", gcm_key, gcm_iv);
    end = clock();
    printf("Time: %.6f s\n", (double)(end - start) / CLOCKS_PER_SEC);


    EVP_cleanup();
    return 0;
}
