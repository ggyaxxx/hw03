
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <time.h>
#include <string.h>
int enc_file_method(const char *input_fn, const char *output_fn,
                 const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv) {
    FILE *input_file = fopen(input_fn, "rb");
    FILE *outpu_file = fopen(output_fn, "wb");
    EVP_CIPHER_CTX *enc_contxt = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(enc_contxt, cipher, NULL, key, iv);
    int input_length, output_length;
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    unsigned char inbuf[4096];
    while ((input_length = fread(inbuf, 1, sizeof(inbuf), input_file)) > 0) {

        EVP_EncryptUpdate(enc_contxt, outbuf, &output_length, inbuf, input_length);
        fwrite(outbuf, 1, output_length, outpu_file);
    }
    if (EVP_EncryptFinal_ex(enc_contxt, outbuf, &output_length) != 1) {
        fprintf(stderr, "cipher error");
        EVP_CIPHER_CTX_free(enc_contxt);
        return 0;
    }
    fwrite(outbuf, 1, output_length, outpu_file);
    EVP_CIPHER_CTX_free(enc_contxt);
    fclose(input_file);
    fclose(outpu_file);
    return 1;
}

int dec_file_method(const char *input_fn, const char *output_fn,
                 const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv) {
    FILE *input_st = fopen(input_fn, "rb");
    FILE *otput_st = fopen(output_fn, "wb");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv);
    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int input_lenght, output_lent;
    while ((input_lenght = fread(inbuf, 1, sizeof(inbuf), input_st)) > 0) {
       EVP_DecryptUpdate(ctx, outbuf, &output_lent, inbuf, input_lenght);
        fwrite(outbuf, 1, output_lent, otput_st);
    }
    EVP_DecryptFinal_ex(ctx, outbuf, &output_lent);
    fwrite(outbuf, 1, output_lent, otput_st);
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_st);
    fclose(otput_st);

    return 1;
}


void generate_random_file(const char *filename, size_t size) {
    FILE *f = fopen(filename, "wb");
    unsigned char *data_buff = malloc(size);
    const char *ext = strrchr(filename, '.');
    int is_text = (ext && strcmp(ext, ".txt") == 0);
        const char set_chars[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789 ";
        size_t charset_size = sizeof(set_chars) - 1;

        for (size_t i = 0; i < size; i++) {
            data_buff[i] = set_chars[rand() % charset_size];
        }
    fwrite(data_buff, 1, size, f);
    fclose(f);
    free(data_buff);
    printf("\n File '%s' generato with %zu byte %s.",
           filename, size, is_text ? "of casual text" : "casuali bynaries");
}

int calc_sha(const char *file_nm, unsigned char *digest, unsigned int *digest_lengt) {
    FILE *file = fopen(file_nm, "rb");
    EVP_MD_CTX *md_ctxt = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctxt, EVP_sha256(), NULL) ;
    unsigned char buffer[4096];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(md_ctxt, buffer, bytes_read);
    }
    EVP_DigestFinal_ex(md_ctxt, digest, digest_lengt);
    EVP_MD_CTX_free(md_ctxt);
    fclose(file);
    return 1;
}

int main() {
    OpenSSL_add_all_algorithms();
    unsigned char key[16];
    unsigned char iv[16];

    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

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
            enc_file_method(inputs[f], enc_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("\n Encrypt time: %.6f seconds\n", cpu_time_used);
            start = clock();
            dec_file_method(enc_file, dec_file, algorithms[a], key, iv);
            end = clock();
            cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
            printf("\n Decrypt time: %.6f seconds\n", cpu_time_used);
            unsigned char hash_orig[EVP_MAX_MD_SIZE], hash_dec[EVP_MAX_MD_SIZE];
            unsigned int len_orig, len_dec;

            calc_sha(inputs[f], hash_orig, &len_orig);
            calc_sha(dec_file, hash_dec, &len_dec);
            if (len_orig == len_dec && memcmp(hash_orig, hash_dec, len_orig) == 0)
                printf(" Integrity OK \n\n");
            else
                printf(" Integrity KO \n\n");
        }

    }

    EVP_cleanup();
    return 0;
}