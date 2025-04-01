#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <crypto/ml_kem.h>
#include <openssl/ml_kem.h>
#include "hal.h"

#define NWARMUP 50
#define NITERATIONS 300
#define NTESTS 500

static int cmp_uint64_t(const void *a, const void *b)
{
    return (int)((*((const uint64_t *)a)) - (*((const uint64_t *)b)));
}

static void print_median(const char *txt, uint64_t cyc[NTESTS])
{
    printf("%10s cycles = %" PRIu64 "\n", txt, cyc[NTESTS >> 1] / NITERATIONS);
}

static int percentiles[] = {1, 10, 20, 30, 40, 50, 60, 70, 80, 90, 99};

static void print_percentile_legend(void)
{
    unsigned i;
    printf("%21s", "percentile");
    for (i = 0; i < sizeof(percentiles) / sizeof(percentiles[0]); i++)
        printf("%7d", percentiles[i]);
    printf("\n");
}

static void print_percentiles(const char *txt, uint64_t cyc[NTESTS])
{
    unsigned i;
    printf("%10s percentiles:", txt);
    for (i = 0; i < sizeof(percentiles) / sizeof(percentiles[0]); i++)
        printf("%7" PRIu64, (cyc)[NTESTS * percentiles[i] / 100] / NITERATIONS);
    printf("\n");
}

static int bench(void)
{
    unsigned char pk[OSSL_ML_KEM_768_PUBLIC_KEY_BYTES];
    unsigned char sk[2400];
    unsigned char ct[OSSL_ML_KEM_768_CIPHERTEXT_BYTES];
    unsigned char key_a[ML_KEM_SHARED_SECRET_BYTES];
    unsigned char key_b[ML_KEM_SHARED_SECRET_BYTES];

    uint64_t cycles_kg[NTESTS], cycles_enc[NTESTS], cycles_dec[NTESTS];
    unsigned i, j;
    uint64_t t0, t1;

    for (i = 0; i < NTESTS; i++)
    {
        int ret = 1;

        ML_KEM_KEY *sks;

        /* Key-pair generation */
        for (j = 0; j < NWARMUP; j++)
        {
            sks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_genkey(pk, OSSL_ML_KEM_768_PUBLIC_KEY_BYTES, sks);
            ret &= ossl_ml_kem_encode_private_key(sk, sizeof sk, sks);
            OPENSSL_free(sks);
        }

        t0 = get_cyclecounter();
        for (j = 0; j < NITERATIONS; j++)
        {
            sks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_genkey(pk, OSSL_ML_KEM_768_PUBLIC_KEY_BYTES, sks);
            ret &= ossl_ml_kem_encode_private_key(sk, sizeof sk, sks);
            OPENSSL_free(sks);
        }
        t1 = get_cyclecounter();
        cycles_kg[i] = t1 - t0;

        /* Encapsulation */
        for (j = 0; j < NWARMUP; j++)
        {
            ML_KEM_KEY *pks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_parse_public_key(pk, sizeof pk, pks);
            ret &= ossl_ml_kem_encap_rand(ct, OSSL_ML_KEM_768_CIPHERTEXT_BYTES, key_a, ML_KEM_SHARED_SECRET_BYTES, pks);
            OPENSSL_free(pks);
        }
        t0 = get_cyclecounter();
        for (j = 0; j < NITERATIONS; j++)
        {
            ML_KEM_KEY *pks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_parse_public_key(pk, sizeof pk, pks);
            ret &= ossl_ml_kem_encap_rand(ct, OSSL_ML_KEM_768_CIPHERTEXT_BYTES, key_a, ML_KEM_SHARED_SECRET_BYTES, pks);
            OPENSSL_free(pks);
        }
        t1 = get_cyclecounter();
        cycles_enc[i] = t1 - t0;
        sks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
        for (j = 0; j < NWARMUP; j++)
        {
            sks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_parse_private_key(sk, sizeof sk, sks);
            ret &= ossl_ml_kem_decap(key_b, ML_KEM_SHARED_SECRET_BYTES, ct, OSSL_ML_KEM_768_CIPHERTEXT_BYTES, sks);
            OPENSSL_free(sks);
        }
        t0 = get_cyclecounter();
        for (j = 0; j < NITERATIONS; j++)
        {
            sks = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
            ret &= ossl_ml_kem_parse_private_key(sk, sizeof sk, sks);
            ret &= ossl_ml_kem_decap(key_b, ML_KEM_SHARED_SECRET_BYTES, ct, OSSL_ML_KEM_768_CIPHERTEXT_BYTES, sks);
            OPENSSL_free(sks);
        }
        t1 = get_cyclecounter();
        cycles_dec[i] = t1 - t0;

        if (ret == 0)
        {
            printf("ERROR occured!");
            return 1;
        }

        if (memcmp(key_a, key_b, ML_KEM_SHARED_SECRET_BYTES) != 0)
        {
            printf("Shared secret mismatch!\n");
            return 1;
        }
    }

    qsort(cycles_kg, NTESTS, sizeof(uint64_t), cmp_uint64_t);
    qsort(cycles_enc, NTESTS, sizeof(uint64_t), cmp_uint64_t);
    qsort(cycles_dec, NTESTS, sizeof(uint64_t), cmp_uint64_t);

    print_median("keypair", cycles_kg);
    print_median("encaps", cycles_enc);
    print_median("decaps", cycles_dec);

    printf("\n");

    print_percentile_legend();

    print_percentiles("keypair", cycles_kg);
    print_percentiles("encaps", cycles_enc);
    print_percentiles("decaps", cycles_dec);
    return 0;
}

int main(void)
{
    enable_cyclecounter();
    bench();
    disable_cyclecounter();

    return 0;
}
