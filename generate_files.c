//
// Created by dscrimie on 10/15/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <time.h>
#include <string.h>
int encrypt_file(const char *input_filename, const char *output_filename,
                 const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv) {
    FILE *input_file = fopen(input_filename, "rb");
    FILE *outpu_file = fopen(output_filename, "wb");
    if (!input_file || !outpu_file) {
        perror("Errore apertura file");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();


    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "Errore inizializzazione cifratura.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), input_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Errore cifratura.");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, outpu_file);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Errore finale cifratura.");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, outpu_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(outpu_file);
    return 1;
}

int decrypt_file(const char *input_filename, const char *output_filename,
                 const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");
    if (!in || !out) {
        perror("Errore apertura file");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "Errore inizializzazione decifratura.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int input_lenght, output_lent;

    while ((input_lenght = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &output_lent, inbuf, input_lenght) != 1) {
            fprintf(stderr, "Errore decifratura.");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, output_lent, out);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &output_lent) != 1) {
        fprintf(stderr, "Errore finale decifratura.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, output_lent, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);

    return 1;
}


void generate_random_file(const char *filename, size_t size) {
    FILE *f = fopen(filename, "wb");
    if (!f) {
        perror("Errore nella creazione del file");
        exit(1);
    }

    unsigned char *buffer = malloc(size);
    if (!buffer) {
        perror("Allocazione memoria fallita");
        fclose(f);
        exit(1);
    }

    const char *ext = strrchr(filename, '.');
    int is_text = (ext && strcmp(ext, ".txt") == 0);

    if (is_text) {
        const char set_chars[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789 ";
        size_t charset_size = sizeof(set_chars) - 1;

        for (size_t i = 0; i < size; i++) {
            buffer[i] = set_chars[rand() % charset_size];
        }
    } else {
        if (RAND_bytes(buffer, size) != 1) {
            fprintf(stderr, "Errore nella generazione random bytes.");
            fclose(f);
            free(buffer);
            exit(1);
        }
    }

    fwrite(buffer, 1, size, f);
    fclose(f);
    free(buffer);

    printf("\n File '%s' generato con %zu byte %s.",
           filename, size, is_text ? "di testo casuale" : "casuali binari");
}

int compute_sha256(const char *filename, unsigned char *digest, unsigned int *digest_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Errore apertura file per hash");
        return 0;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Errore creazione contesto hash.");
        fclose(file);
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Errore inizializzazione SHA-256.");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            fprintf(stderr, "Errore aggiornamento SHA-256.");
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            return 0;
        }
    }

    if (EVP_DigestFinal_ex(mdctx, digest, digest_len) != 1) {
        fprintf(stderr, "Errore finale SHA-256.");
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 1;
}

int main() {
    OpenSSL_add_all_algorithms();

    unsigned char key[16]; // 128-bit key
    unsigned char iv[16];  // 128-bit IV (block size)

    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Error or IV generation error");
        return 1;
    }

    printf("Keys and IV generated \n");
    for (int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\n");

    generate_random_file("tiny.txt", 16);
    generate_random_file("medium.txt", 20000);
    generate_random_file("large.bin", 3 * 1024 * 1024);

    clock_t start, end;
    double cpu_time_used;

    const EVP_CIPHER *algorithms[] = {
        EVP_aes_128_cbc(),
        EVP_camellia_128_cbc(),
        EVP_sm4_cbc()
    };

    const char *names[] = {"AES", "Camellia", "SM4"};

    const char *inputs[] = {"tiny.txt", "medium.txt", "large.bin"};
    const char *sizes[] = {"16B", "20KB", "3MB"};

    for (int a = 0; a < 3; a++) {
        for (int f = 0; f < 3; f++) {
            char enc_file[64], dec_file[64];
            sprintf(enc_file, "%s_%s.enc", names[a], inputs[f]);
            sprintf(dec_file, "%s_%s.dec", names[a], inputs[f]);

            printf("\n Testing %s on %s...", names[a], sizes[f]);

            start = clock();
            encrypt_file(inputs[f], enc_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("\n Encryption time: %.6f seconds\n", cpu_time_used);

            start = clock();
            decrypt_file(enc_file, dec_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("\n Decryption time: %.6f seconds\n", cpu_time_used);

            unsigned char hash_orig[EVP_MAX_MD_SIZE], hash_dec[EVP_MAX_MD_SIZE];
            unsigned int len_orig, len_dec;

            if (!compute_sha256(inputs[f], hash_orig, &len_orig) ||
                !compute_sha256(dec_file, hash_dec, &len_dec)) {
                fprintf(stderr, "\n Hash calc error \n");
                continue;
                }

            if (len_orig == len_dec && memcmp(hash_orig, hash_dec, len_orig) == 0)
                printf("Integrity OK \n\n");
            else
                printf("Integrity KO \n\n");
        }
    }
    EVP_cleanup();
    return 0;
}
