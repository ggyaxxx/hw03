//
// Created by dscrimie on 10/15/25.
//
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <sys/stat.h>

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

    EVP_cleanup();
    return 0;
}
