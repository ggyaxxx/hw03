//
// Created by dscrimie on 10/15/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <time.h>

int encrypt_file(const char *input_filename, const char *output_filename,
                 const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv) {
    FILE *in = fopen(input_filename, "rb");
    FILE *out = fopen(output_filename, "wb");
    if (!in || !out) {
        perror("Errore apertura file");
        return 0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        fprintf(stderr, "Errore inizializzazione cifratura.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Errore cifratura.\n");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Errore finale cifratura.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
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
    int inlen, outlen;

    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Errore decifratura.\n");
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }

    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Errore finale decifratura.\n");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

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

    if (RAND_bytes(buffer, size) != 1) {
        fprintf(stderr, "Errore nella generazione casuale con OpenSSL.\n");
        fclose(f);
        free(buffer);
        exit(1);
    }

    fwrite(buffer, 1, size, f);
    fclose(f);
    free(buffer);

    printf("✅ File '%s' generato con %zu byte casuali.\n", filename, size);
}

int main() {
    // inizializza l'algoritmo di generazione casuale di OpenSSL
    OpenSSL_add_all_algorithms();

    unsigned char key[16]; // 128-bit key
    unsigned char iv[16];  // 128-bit IV (block size)

    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        fprintf(stderr, "Errore nella generazione della chiave o IV.\n");
        return 1;
    }

    printf("✅ Chiave e IV generati casualmente.\n");
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

    const char *names[] = {"AES-128-CBC", "Camellia-128-CBC", "SM4-CBC"};

    const char *inputs[] = {"tiny.txt", "medium.txt", "large.bin"};
    const char *sizes[] = {"16B", "20KB", "3MB"};

    for (int a = 0; a < 3; a++) {
        for (int f = 0; f < 3; f++) {
            char enc_file[64], dec_file[64];
            sprintf(enc_file, "%s_%s.enc", names[a], inputs[f]);
            sprintf(dec_file, "%s_%s.dec", names[a], inputs[f]);

            printf("\n🔹 Testing %s on %s...\n", names[a], sizes[f]);

            start = clock();
            encrypt_file(inputs[f], enc_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("   Encryption time: %.6f seconds\n", cpu_time_used);

            start = clock();
            decrypt_file(enc_file, dec_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("   Decryption time: %.6f seconds\n", cpu_time_used);
        }
    }



    EVP_cleanup();
    return 0;
}
