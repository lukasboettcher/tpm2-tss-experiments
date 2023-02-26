#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#include <tss2/tss2_fapi.h>
#include <stdio.h>
#include <assert.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 512

void tpm2_pcr_mask_to_selection(uint32_t mask, uint16_t bank, TPML_PCR_SELECTION *ret)
{
    *ret = (TPML_PCR_SELECTION){
        .count = 1,
        .pcrSelections[0] = {
            .hash = bank,
            .sizeofSelect = 3,
            .pcrSelect[0] = mask & 0xFF,
            .pcrSelect[1] = (mask >> 8) & 0xFF,
            .pcrSelect[2] = (mask >> 16) & 0xFF,
        }};
}

void print_pcr_values(TPML_DIGEST *pcr_values)
{
    for (size_t i = 0; i < pcr_values->count; i++)
    {
        printf("0x");
        for (size_t j = 0; j < pcr_values->digests[i].size; j++)
        {
            unsigned char x = pcr_values->digests[i].buffer[j];
            printf("%02X", x);
        }
        printf("\n");
    }
};

void set_pcr_mask(int index, uint32_t *mask)
{
    *mask |= 1 << index;
}

void handleErrors() { printf("failed\n"); }

void digest_message(const unsigned char *message, size_t message_len, unsigned char *digest, unsigned int *digest_len)
{
    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        handleErrors();

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        handleErrors();

    if (1 != EVP_DigestUpdate(mdctx, message, message_len))
        handleErrors();

    if (1 != EVP_DigestFinal_ex(mdctx, digest, digest_len))
        handleErrors();

    EVP_MD_CTX_free(mdctx);
}

void digest_file(const char *filename, unsigned char *digest)
{
    size_t bytes = 0;
    unsigned char buffer[BUFFER_SIZE];
    FILE *datafile = fopen(filename, "rb");

    EVP_MD_CTX *mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

    while ((bytes = fread(buffer, 1, BUFFER_SIZE, datafile)))
    {
        EVP_DigestUpdate(mdctx, buffer, bytes);
    }

    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
    fclose(datafile);
}

int main()
{
    TSS2_RC rc;
    ESYS_CONTEXT *ctx = NULL;
    TPML_PCR_SELECTION selection;
    TPML_DIGEST *pcr_values = NULL;
    uint32_t mask = 0;
    TPMI_ALG_HASH bank;
    TPML_DIGEST_VALUES values = {};
    FILE *fp;

    bank = TPM2_ALG_SHA256;
    set_pcr_mask(23, &mask);
    tpm2_pcr_mask_to_selection(mask, bank, &selection);

    rc = Esys_Initialize(&ctx, NULL, NULL);
    assert(rc == TSS2_RC_SUCCESS);

    // read pcr 23 before extending the value
    rc = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &selection, NULL, NULL, &pcr_values);
    assert(rc == TSS2_RC_SUCCESS && "first reading of pcrs failed");
    print_pcr_values(pcr_values);

    // char data[4];
    // size_t data_size = 4;
    // data[0] = 'a';
    // digest_message(data, data_size, (unsigned char *)&values.digests[values.count].digest, NULL);

    // measuring the sha256 digest of a file into pcr 23
    digest_file("/boot/vmlinuz", (unsigned char *)&values.digests[values.count].digest);
    values.digests[values.count++].hashAlg = TPM2_ALG_SHA256;
    rc = Esys_PCR_Extend(ctx, 23, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &values);
    assert(rc == TSS2_RC_SUCCESS && "extending pcr failed");

    // read pcr 23 again after extending the pcr
    rc = Esys_PCR_Read(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &selection, NULL, NULL, &pcr_values);
    assert(rc == TSS2_RC_SUCCESS);
    print_pcr_values(pcr_values);

    // reset special pcr 23 after the procedure is done
    rc = Esys_PCR_Reset(ctx, 23, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    assert(rc == TSS2_RC_SUCCESS);

    Esys_Finalize(&ctx);

    return 0;
}
