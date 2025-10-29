#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

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

// ---------- MAIN ----------
int main() {
    OpenSSL_add_all_algorithms();

    unsigned char aes_key[16], aes_iv[16];
    unsigned char chacha_key[32], chacha_nonce[12];
    unsigned char mac_key[32];

    RAND_bytes(aes_key, sizeof(aes_key));
    RAND_bytes(aes_iv, sizeof(aes_iv));
    RAND_bytes(chacha_key, sizeof(chacha_key));
    RAND_bytes(chacha_nonce, sizeof(chacha_nonce));
    RAND_bytes(mac_key, sizeof(mac_key));

    // genera i file di test
    generate_random_file("tiny.bin", 16);
    generate_random_file("medium.bin", 200000);  // 200 KB
    generate_random_file("large.bin", 3 * 1024 * 1024); // 3 MB

    const char *inputs[] = {"tiny.bin", "medium.bin", "large.bin"};

    printf("=== AES-128-CTR + HMAC ===\n");
    for (int i = 0; i < 3; i++) {
        clock_t start = clock();
        enc_then_mac_aes128ctr(inputs[i], "aesctr_hmac.enc", aes_key, aes_iv, mac_key);
        clock_t end = clock();
        printf("%s -> %.6f s\n", inputs[i], (double)(end - start) / CLOCKS_PER_SEC);
    }

    printf("\n=== ChaCha20 + HMAC ===\n");
    for (int i = 0; i < 3; i++) {
        clock_t start = clock();
        enc_then_mac_chacha20(inputs[i], "chacha_hmac.enc", chacha_key, chacha_nonce, mac_key);
        clock_t end = clock();
        printf("%s -> %.6f s\n", inputs[i], (double)(end - start) / CLOCKS_PER_SEC);
    }

    EVP_cleanup();
    return 0;
}
