#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <unistd.h>
#include <openssl/kdf.h>

#define BLOCK_SIZE 4096
#define RUNS 5
void generate_random_file(const char *filename, size_t size) {
    FILE *f = fopen(filename, "wb");
    unsigned char *data = malloc(size);
    RAND_bytes(data, size);
    fwrite(data, 1, size, f);
    fclose(f);
    free(data);
}

void derive_key(unsigned char *master, size_t master_len,
                const char *info, unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(pctx);
    EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(pctx, "salt", 4);
    EVP_PKEY_CTX_set1_hkdf_key(pctx, master, master_len);
    EVP_PKEY_CTX_add1_hkdf_info(pctx, info, strlen(info));
    size_t len = out_len;
    EVP_PKEY_derive(pctx, out, &len);
    EVP_PKEY_CTX_free(pctx);
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

int enc_chacha20_poly1305(const char *input_fn, const char *output_fn,
                          unsigned char *key, unsigned char *nonce) {
    FILE *fin = fopen(input_fn, "rb");
    FILE *fout = fopen(output_fn, "wb");
    if (!fin || !fout) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce);

    unsigned char inbuf[4096];
    unsigned char outbuf[4096];
    int inlen, outlen;
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen);
        fwrite(outbuf, 1, outlen, fout);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    fwrite(outbuf, 1, outlen, fout);

    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    fwrite(tag, 1, 16, fout);

    EVP_CIPHER_CTX_free(ctx);
    fclose(fin); fclose(fout);
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

    unsigned char master_key[32];
    RAND_bytes(master_key, sizeof(master_key));

    // Chiavi e IV/nonce
    unsigned char aes_key[16], aes_iv[16];
    unsigned char chacha_key[32], chacha_nonce[12];
    unsigned char gcm_key[16], gcm_iv[12];
    unsigned char mac_key[32];

    // Derivazione da master key
    derive_key(master_key, sizeof(master_key), "AES_KEY", aes_key, sizeof(aes_key));
    derive_key(master_key, sizeof(master_key), "AES_IV", aes_iv, sizeof(aes_iv));
    derive_key(master_key, sizeof(master_key), "CHACHA_KEY", chacha_key, sizeof(chacha_key));
    derive_key(master_key, sizeof(master_key), "CHACHA_NONCE", chacha_nonce, sizeof(chacha_nonce));
    derive_key(master_key, sizeof(master_key), "GCM_KEY", gcm_key, sizeof(gcm_key));
    derive_key(master_key, sizeof(master_key), "GCM_IV", gcm_iv, sizeof(gcm_iv));
    derive_key(master_key, sizeof(master_key), "MAC_KEY", mac_key, sizeof(mac_key));



    char cwd[512];
    getcwd(cwd, sizeof(cwd));
    printf("Current working directory: %s\n", cwd);

    size_t sizes_MB[] = {10, 100, 512, 1024, 5120};
    int num_sizes = sizeof(sizes_MB) / sizeof(sizes_MB[0]);

    for (int s = 0; s < num_sizes; s++) {
        size_t FILE_SIZE = sizes_MB[s] * 1024 * 1024;
        char input_fn[64];
        snprintf(input_fn, sizeof(input_fn), "test_%dMB.bin", sizes_MB[s]);
        printf("\n--- Generating %s (size = %zu MB) ---\n", input_fn, sizes_MB[s]);
        generate_random_file(input_fn, FILE_SIZE);

        double sum1=0, sum2=0, sum3=0, sum4=0;

        for (int r = 0; r < RUNS; r++) {
            double t1, t2, t3, t4;
            clock_t start, end;

            start = clock();
            enc_then_mac_aes128ctr(input_fn, "aesctr_hmac.enc", aes_key, aes_iv, mac_key);
            end = clock();
            t1 = (double)(end - start) / CLOCKS_PER_SEC;
            sum1 += t1;

            start = clock();
            enc_then_mac_chacha20(input_fn, "chacha_hmac.enc", chacha_key, chacha_nonce, mac_key);
            end = clock();
            t2 = (double)(end - start) / CLOCKS_PER_SEC;
            sum2 += t2;

            start = clock();
            enc_aes128gcm(input_fn, "aesgcm.enc", gcm_key, gcm_iv);
            end = clock();
            t3 = (double)(end - start) / CLOCKS_PER_SEC;
            sum3 += t3;

            start = clock();
            enc_chacha20_poly1305(input_fn, "chacha20poly.enc", chacha_key, chacha_nonce);
            end = clock();
            t4 = (double)(end - start) / CLOCKS_PER_SEC;
            sum4 += t4;

            printf("Run %d: AES-CTR+HMAC %.3f s | ChaCha20+HMAC %.3f s | AES-GCM %.3f s | ChaCha20-Poly1305 %.3f s\n",
                   r + 1, t1, t2, t3, t4);
        }


        printf("\nResults for %d MB (average over %d runs):\n", sizes_MB[s], RUNS);
        printf(" AES-CTR+HMAC: %.3f s\n", sum1 / RUNS);
        printf(" ChaCha20+HMAC: %.3f s\n", sum2 / RUNS);
        printf(" AES-GCM: %.3f s\n", sum3 / RUNS);
        printf(" ChaCha20-Poly1305: %.3f s\n", sum4 / RUNS);
    }



    EVP_cleanup();
    return 0;
}
