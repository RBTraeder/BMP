#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(1)

typedef struct
{
    uint16_t type;
    uint32_t size;
    uint16_t res1;
    uint16_t res2;
    uint32_t offset;
} BMPHead;

typedef struct
{
    uint32_t size;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bCount;
    uint32_t compress;
    uint32_t iSize;
    int32_t xPPM;
    int32_t yPPM;
    uint32_t cUsed;
    uint32_t cImportant;
} BMPIHead;

int IP[] = {2, 6, 3, 1, 4, 8, 5, 7};

int FP[] = {4, 1, 3, 5, 7, 2, 8, 6};

int key[] = {0, 1, 0, 1, 0, 0, 0, 1, 0, 1};

int SK1[] = {0, 0, 0, 0, 0, 0, 0, 0};

int SK2[] = {0, 0, 0, 0, 0, 0, 0, 0};

int KS[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int plaintext[] = {0, 0, 0, 0, 0, 0, 0, 0};

int ciphertext[] = {0, 0, 0, 0, 0, 0, 0, 0};

int IV[] = {1, 0, 1, 1, 1, 0, 1, 1};
int IV2[] = {1, 0, 1, 1, 1, 0, 1, 1};
int IV3[] = {1, 0, 1, 1, 1, 0, 1, 1};
int IV4[] = {1, 0, 1, 1, 1, 0, 1, 1};

int EP[] = {4, 1, 2, 3, 2, 3, 4, 1};

int P4[] = {2, 4, 3, 1};

int S0[4][4] = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
int S1[4][4] = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

int P8[] = {6, 3, 7, 4, 8, 5, 10, 9};

int P10[] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};



 
int main()
{
    char ch;
    int count = 0;
    int i = 0;
    int output[10];
    for (int i = 0; i < 10; i++)
    {
        output[i] = key[P10[i] - 1];
    }

    for (int i = 0; i < 10; i++)
    {
        key[i] = output[i];
    }

    subKey(key, KS, 1);
    copy(key, SK1, 8);

    subKey(KS, key, 2);
    copy(KS, key, 8);
    copy(key, SK2, 8);

    FILE *iFile = fopen("SD.bmp", "rb");
    FILE *oFile = fopen("output.bmp", "wb");

    if (!iFile || !oFile)
    {
        printf("Test \n");
        printf("Error opening files\n");
        return 1;
    }

    BMPHead head;
    BMPIHead iHead;

    fread(&head, sizeof(BMPHead), 1, iFile);
    fread(&iHead, sizeof(BMPIHead), 1, iFile);


    int sizeofPD = iHead.iSize;
    unsigned char *pix = (unsigned char *)malloc(sizeofPD);
    fread(pix, sizeofPD, 1, iFile);

    encryptP(pix, sizeofPD);

    fwrite(&head, sizeof(BMPHead), 1, oFile);
    fwrite(&iHead, sizeof(BMPIHead), 1, oFile);

    fwrite(pix, sizeofPD, 1, oFile);

    fclose(iFile);
    fclose(oFile);

    free(pix);

    FILE* inFile = fopen("output.bmp", "rb");
    FILE* outFile = fopen("decrypt.bmp", "wb");

    if (!inFile || !outFile)
    {
        printf("Test \n");
        printf("Error opening files\n");
        return 1;
    }

    fread(&head, sizeof(BMPHead), 1, inFile);
    fread(&iHead, sizeof(BMPIHead), 1, inFile);

    sizeofPD = iHead.iSize;
    pix = (unsigned char *)malloc(sizeofPD);
    fread(pix, sizeofPD, 1, inFile);


    decryptP(pix, sizeofPD);

    fwrite(&head, sizeof(BMPHead), 1, outFile);
    fwrite(&iHead, sizeof(BMPIHead), 1, outFile);

    fwrite(pix, sizeofPD, 1, outFile);

    fclose(inFile);
    fclose(outFile);

    free(pix);

    return 0;
}

void subKey(int *key, int *keeper, int numBits)
{
    CLS(key, numBits, 10);
    copy(key, keeper, 10);
    p8Perm(key);
}

void copy(int *source, int *destination, int size)
{
    for (int i = 0; i < size; i++)
    {
        destination[i] = source[i];
    }
}

void charToBinary(char c, int *binary)
{
    for (int i = 7; i >= 0; i--)
    {
        binary[i] = (c >> (7 - i)) & 1;
    }
}

char binaryToChar(int *binary)
{
    char ch = 0;
    for (int i = 0; i < 8; i++)
    {
        ch |= binary[i] << (7 - i);
    }
    return ch;
}

void initPerm(int *plaintext)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = plaintext[IP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        plaintext[i] = output[i];
    }
}

void expPerm(int *right)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = right[EP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        right[i] = output[i];
    }
}

void xorArrays(int *arr1, int *arr2, int size, int *result)
{
    for (int i = 0; i < size; i++)
    {
        result[i] = arr1[i] ^ arr2[i];
    }
}

void sBox(int *input, int sBox[4][4], int *output)
{
    int row = input[0] * 2 + input[3];
    int col = input[1] * 2 + input[2];
    int value = sBox[row][col];

    output[0] = (value >> 1) & 1;
    output[1] = value & 1;
}

void combine2BArrays(int *array1, int *array2, int *result)
{
    for (int i=0; i<2; i++)
    {
        result[i] = array1[i];
        result[i+2] = array2[i];
    }
}

void p4Perm(int *input)
{
    int output[4];

    for (int i = 0; i < 4; i++)
    {
        output[i] = input[P4[i] - 1];
    }

    for (int i = 0; i < 4; i++)
    {
        input[i] = output[i];
    }
}

void xorWithLeft(int *lhs, int *input)
{
    for (int i = 0; i < 4; i++)
    {
        lhs[i] ^= input[i];
    }
}

void combineArrays(int *array1, int *array2, int *result)
{
    for (int i = 0; i < 4; i++)
    {
        result[i] = array1[i];
        result[i + 4] = array2[i];
    }
}

void swap(int *array, int size)
{
    for (int i = 0; i < size / 2; i++)
    {
        int temp = array[i];
        array[i] = array[i + size / 2];
        array[i + size / 2] = temp;
    }
}

void finalPerm(int *plaintext)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = plaintext[FP[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        plaintext[i] = output[i];
    }
}

void CLS(int *key, int bits, int keySize)
{
    int left[5];
    int right[5];

    for (int i = 0; i < 5; i++)
    {
        left[i] = key[i];
        right[i] = key[i + 5];
    }

    for (int i = 0; i < bits; i++)
    {
        int tLeft = left[0];
        int tRight = right[0];

        for (int j = 0; j < 4; j++)
        {
            left[j] = left[j + 1];
            right[j] = right[j + 1];
        }

        left[4] = tLeft;
        right[4] = tRight;
    }

    for (int i = 0; i < 5; i++)
    {
        key[i] = left[i];
        key[i + 5] = right[i];
    }
}

void p8Perm(int *key)
{
    int output[8];

    for (int i = 0; i < 8; i++)
    {
        output[i] = key[P8[i] - 1];
    }

    for (int i = 0; i < 8; i++)
    {
        key[i] = output[i];
    }
}

void Encrypt()
{
    int left[4];
    int right[4];
    int result[8];
    int group1[4];
    int group2[4];
    int results[4];
    int combined[8];
    int output1[2]; 
    int output2[2];
    int LHC[4];
    int RHC[4];

    initPerm(plaintext);

    for (int i = 0; i < 2; i++)
    {
        if (i == 0)
        {
            copy(SK1, key, 8);
        }
        else
        {
            copy(SK2, key, 8);
        }

    
        for (int i = 0; i < 4; i++)
        {
            left[i] = plaintext[i];
            right[i] = plaintext[i + 4];
        }

        copy(left, LHC, 4);
        copy(right, RHC, 4);

        expPerm(right);

        xorArrays(right, key, 8, result);

        for (int i = 0; i < 4; i++)
        {
            group1[i] = result[i];
            group2[i] = result[i + 4];
        }

        sBox(group1, S0, output1);
        sBox(group2, S1, output2);


        combine2BArrays(output1, output2, results);

        p4Perm(results);

        xorWithLeft(LHC, results);

        combineArrays(LHC, RHC, combined);

        if (i == 0)
        {
            swap(combined, 8);
            copy(combined, plaintext, 8);
        }
    }

    finalPerm(combined);

    copy(combined, ciphertext, 8);
}

void Decrypt()
{
    int left[4];
    int right[4];
    int result[8];
    int group1[4];
    int group2[4];
    int results[4];
    int combined[8];
    int output1[2]; 
    int output2[2];
    int LHC[4];
    int RHC[4];

    initPerm(ciphertext);

    for (int i = 0; i < 2; i++)
    {
        if (i == 0)
        {
            copy(SK2, key, 8);
        }
        else
        {
            copy(SK1, key, 8);
        }

        for (int i = 0; i < 4; i++)
        {
            left[i] = ciphertext[i];
            right[i] = ciphertext[i + 4];
        }

        copy(left, LHC, 4);
        copy(right, RHC, 4);

        expPerm(right);

        xorArrays(right, key, 8, result);

        for (int i = 0; i < 4; i++)
        {
            group1[i] = result[i];
            group2[i] = result[i + 4];
        }

        sBox(group1, S0, output1);
        sBox(group2, S1, output2);


        combine2BArrays(output1, output2, results);

        p4Perm(results);

        xorWithLeft(LHC, results);

        combineArrays(LHC, RHC, combined);

        if (i == 0)
        {
            swap(combined, 8);
            copy(combined, ciphertext, 8);
        }
    }

    finalPerm(combined);

    copy(combined, plaintext, 8);
}

void encryptP(unsigned char *pix, int size)
{
    for (int i = 0; i < size; i++)
    {
        charToBinary(pix[i], plaintext);
        Encrypt();
        pix[i] = binaryToChar(ciphertext);
    }
}

void decryptP(unsigned char *pix, int size)
{
    for (int i = 0; i < size; i++)
    {
        charToBinary(pix[i], ciphertext);
        Decrypt();
        pix[i] = binaryToChar(plaintext);
    }
}
