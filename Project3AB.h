#ifndef PROJECT3AB_H
#define PROJECT3AB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "sdes.h"

char ADVANCE_TIME[32] = "2023/12/20";
typedef struct
{
    char V[16], SN[16], AI[16], CA[64], A[64], Ap[64], Ta[32], Tb[32], TL[16], S[64];
} Cert;

typedef struct
{
    char AI[16], CA[64], tU[15], nU[15], S[16], RD[32][64], SN[16][64];
} CRL;

typedef struct
{
    char file_loc[128][64], CA[64][64], A[64][64];
} Chain;

char FILEPATH[128] = "";
char CRL_FILEPATH[128] = "CRL.txt";
char CHAIN_FILEPATH[128] = "CHAIN.txt";

void set_CRL_FILEPATH(const char* f_path)
{
    strcpy(CRL_FILEPATH, f_path);
}
void set_FILEPATH(const char* f_path)
{
    strcpy(FILEPATH, f_path);
}
void set_CHAIN_FILEPATH(const char* f_path)
{
    strcpy(CHAIN_FILEPATH, f_path);
}

int IV[] =      {1, 0, 1, 1, 1, 0, 1, 1};
int IV_PERM[] = {1, 0, 1, 1, 1, 0, 1, 1};

void writeCertToFile(const char *filename, const Cert *inputCert)
{
    FILE *writeFile = fopen(filename, "w");
    fprintf(writeFile, "V  [Version]: %s\n",                        inputCert->V );
    fprintf(writeFile, "SN [Certificate Serial Number]: %s\n",      inputCert->SN);
    fprintf(writeFile, "AI [Signature Algorithm Identifier]: %s\n", inputCert->AI);
    fprintf(writeFile, "CA [Issuer Name]: %s\n",                    inputCert->CA);
    fprintf(writeFile, "A  [Subject Name]: %s\n",                   inputCert->A );
    fprintf(writeFile, "Ap [Subject Public Key Info]: %s\n",        inputCert->Ap);
    fprintf(writeFile, "Ta [Valid FROM  yyyy/mm/dd]: %s\n",         inputCert->Ta);
    fprintf(writeFile, "Tb [Valid UNTIL yyyy/mm/dd]: %s\n",         inputCert->Tb);
    fprintf(writeFile, "TL [Trust Level]: %s\n",                    inputCert->TL);
    fprintf(writeFile, "S  [Signature]: %s\n",                      inputCert->S );
    fclose(writeFile);
}
int readCertFromFile(const char *filename, Cert *outputCert)
{
    FILE *readFile = fopen(filename, "r");
    if (readFile == NULL)
    {
        printf(" - Cert \"%s\" could not be opened\n", filename);
        fclose(readFile);
        return -1;
    }
    fscanf(readFile, "V  [Version]: %s\n",                          outputCert->V );
    fscanf(readFile, "SN [Certificate Serial Number]: %s\n",        outputCert->SN);
    fscanf(readFile, "AI [Signature Algorithm Identifier]: %s\n",   outputCert->AI);
    fscanf(readFile, "CA [Issuer Name]: %s\n",                      outputCert->CA);
    fscanf(readFile, "A  [Subject Name]: %s\n",                     outputCert->A );
    fscanf(readFile, "Ap [Subject Public Key Info]: %s\n",          outputCert->Ap);
    fscanf(readFile, "Ta [Valid FROM  yyyy/mm/dd]: %s\n",           outputCert->Ta);
    fscanf(readFile, "Tb [Valid UNTIL yyyy/mm/dd]: %s\n",           outputCert->Tb);
    fscanf(readFile, "TL [Trust Level]: %s\n",                      outputCert->TL);
    fscanf(readFile, "S  [Signature]: %s\n",                        outputCert->S );
    fclose(readFile);
    return 0;
}


void getCurrentDate(char runDate[]) {
    // Get the current time
    time_t currentTime;
    time(&currentTime);

    // Convert the current time to a struct tm
    struct tm* localTime = localtime(&currentTime);

    // Extract month, day, year
    int year = localTime->tm_year + 1900;  // tm_year is years since 1900
    int month = localTime->tm_mon + 1;  // tm_mon is 0-indexed
    int day = localTime->tm_mday;

    // Format and store the date in the runDate array
    snprintf(runDate, 32, "%04d/%02d/%02d", year, month, day);
}
void makeCert1(const char *filename)
{
    Cert cert =
    {
        .V = "1",
        .SN = "12345",
        .AI = "SignAlgorithm",
        .CA = "Issuer-Wim",
        .A = "Subject-Nate",
        .Ap = "abcdefghijklmnopqrstuvwxyz",
        .Ta = "",
        .Tb = "2024/06/15",
        .TL = "3",
        .S  = "Signature"
    };

    // Set current date
    char currentTime[32];
    getCurrentDate(currentTime);
    snprintf(cert.Ta, sizeof(cert.Ta), "%s", currentTime);
    writeCertToFile(filename, &cert);
}
void fileToString(const char *filename, char **certStr)
{
    Cert newCert;
    readCertFromFile(filename, &newCert);

    size_t totalSize = strlen(newCert.V) + strlen(newCert.SN) + strlen(newCert.AI) + strlen(newCert.CA) +
                       strlen(newCert.A) + strlen(newCert.Ap) + strlen(newCert.Ta) +
                       strlen(newCert.Tb) + strlen(newCert.TL) + strlen(newCert.S)+ 10; // +8 for lines +1 for the null terminator

    *certStr = (char *)malloc(totalSize);
    if (*certStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    (*certStr)[0] = '\0';
    strcat(*certStr, newCert.V);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.SN);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.AI);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.CA);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.A);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.Ap);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.Ta);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.Tb);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.TL);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.S);
    strcat(*certStr, "\n");
}

void filetochainstr(const char *filename, const char *chainstr)
{
    Chain chain;
}

void stringToCert(const char *certStr, Cert *cert) {
    const char *delimiter = "\n";
    char *token;
    char tempStr[50];
    token = strtok((char *)certStr, delimiter);

    if (token != NULL) {
        strcpy(cert->V, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->SN, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->AI, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->CA, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->A, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->Ap, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->Ta, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->Tb, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->TL, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->S, token);
    }
}
// 'Y' = Dates are valid  / 'N' = Dates are invalid (uses system time)
char datesValid(Cert *cert1)
{
    char currentTime[32];
    //getCurrentDate(currentTime);
    strcpy(currentTime, ADVANCE_TIME);
    if (strcmp(cert1->Ta, currentTime) > 0)
        return 'N';
    else if (strcmp(cert1->Tb, currentTime) < 0)
        return 'N';
    else
        return 'Y';
}

char hashChar(char c, int* k1, int* k2)
{
    int plaintext[8], ciphertext[8];
    charToAsciiArray(c, plaintext);
    xorArrays(plaintext, IV, 8, plaintext);
    encrypt_sdes(plaintext, ciphertext, k1, k2);
    copy(ciphertext, IV, 8);
    return asciiArrayToChar(ciphertext);
}

char hash(const char *filename)
{
    char rt;
    char *fileString = (char *)malloc(320);
    fileToString(filename, &fileString);

    int strLen = strlen(fileString);

    int sdes_key[10] = {0,0,0,0,0,0,0,0,0,0};
    int k1[8], k2[8];
    generate_SDES_keys(sdes_key, k1, k2);

    for (int i = 0; i < strLen; i++)
        rt = hashChar(fileString[i], k1, k2);
    for (int i = 0; i < 8; i++)
        IV[i] = IV_PERM[i];
    return rt;
}
char pkHash(const char *str)
{
    char rt;
    int strLen = strlen(str);

    int sdes_key[10] = {0,0,0,0,0,0,0,0,0,0};
    int k1[8], k2[8];
    generate_SDES_keys(sdes_key, k1, k2);

    for (int i = 0; i < strLen; i++)
        rt = hashChar(str[i], k1, k2);
    for (int i = 0; i < 8; i++)
        IV[i] = IV_PERM[i];
    return rt;
}
void writeHashFile(const char *filename, const char hashStr)
{
    FILE *writeFile = fopen(filename, "w");
    fprintf(writeFile, "%c", hashStr);
    fclose(writeFile);
    printf(" > Hash File \"%s\" created (hash = '%c')\n", filename, hashStr);
}
char readHashFile(const char *filename)
{
    char rt;
    //printf("     Reading hash file...\n");
    FILE *readFile = fopen(filename, "r");
    if (readFile == NULL)
        printf(" - Hash \"%s\" could not be opened\n", filename);
    fscanf(readFile, " %c", &rt);
    fclose(readFile);
    //printf("     Hash retrieved: '%c'\n", rt);
    return rt;
}
void newRevocationList(const char *filename, const CRL *inputCRL)
{
    FILE *writeFile = fopen(filename, "w");
    fprintf(writeFile, "Certificate Revocation List (CRL)\nAlgorithm Identifier: %s\n", inputCRL->AI);
    fprintf(writeFile, "Issuer Name: %s\n", inputCRL->CA);
    fprintf(writeFile, "This update date: %s\n", inputCRL->tU);
    fprintf(writeFile, "Next update date: %s\n", inputCRL->nU);
    fprintf(writeFile, "Signature: %s\n - Revoked Certificates -\n", inputCRL->S);
    fprintf(writeFile, "Serial #: %s\n", inputCRL->SN[0]);
    fprintf(writeFile, "Revocation Date: %s\n - - -\n", inputCRL->RD[0]);
    fclose(writeFile);
}

void newChainList(const char *filename, const Chain *inputChain)
{
    FILE *writeFile = fopen(filename, "w");
    fprintf(writeFile, "Location: %s\n", inputChain->file_loc);
    fprintf(writeFile, "Issuer: %s\n", inputChain->CA);
    fprintf(writeFile, "Subject: %s\n", inputChain->A);
    fclose(writeFile);
}
// Returns number of entries
int readRevocationList(const char *filename, CRL *outputCRL)
{
    FILE *readFile = fopen(filename, "r");
    fscanf(readFile, "Certificate Revocation List (CRL)\nAlgorithm Identifier: %s\n", outputCRL->AI);
    fscanf(readFile, "Issuer Name: %s\n", outputCRL->CA);
    fscanf(readFile, "This update date: %s\n", outputCRL->tU);
    fscanf(readFile, "Next update date: %s\n", outputCRL->nU);
    fscanf(readFile, "Signature: %s\n - Revoked Certificates -\n", outputCRL->S);
    int i = 0;
    while (fscanf(readFile, "Serial #: %s\n", outputCRL->SN[i]) != EOF)
    {
        fscanf(readFile, "Revocation Date: %s\n - - -\n", outputCRL->RD[i]);
        i++;
        if (i > 63)
            break;
    }
    fclose(readFile);

    return i;
}

int readChainList(const char *filename, Chain *outputChain)
{
     FILE *readFile = fopen(filename, "r");
    int i = 0;
    while (fscanf(readFile, "Subject: %s\n", outputChain->A[i]) != EOF)
    {
        while (fscanf(readFile, "Issuer: %s\n - - -\n", outputChain->CA[i]) != EOF)
        {
            fscanf(readFile, "Location : %s\n - - -\n", outputChain->file_loc[i]);
            i++;
            if (i > 63)
            {
                break;
            }
        }
    }
    fclose(readFile);

    return i;
}

void insertRevocation(const char *filename, const CRL *inputCRL, const int i)
{
    FILE *writeFile = fopen(filename, "a");
    fprintf(writeFile, "Serial #: %s\n", inputCRL->SN[i]);
    fprintf(writeFile, "Revocation Date: %s\n - - -\n", inputCRL->RD[i]);
    fclose(writeFile);
}

void insertChain(const char *filename, const Chain *inputChain, const int i)
{
    FILE *writeFile = fopen(filename, "a");
    fprintf(writeFile, "Location: %s\n", inputChain->file_loc[i]);
    fprintf(writeFile, "Issuer: %s\n - - -\n", inputChain->CA[i]);
    fprintf(writeFile, "Subject: %s\n - - -\n", inputChain->A[i]);
    fclose(writeFile);
}

void writeCRL(const char *filename, const CRL *inputCRL)
{
    newRevocationList(filename, inputCRL);
    int i = 1;
    while (strlen(inputCRL->RD[i]) == 10)
    {
        if (inputCRL->SN[i] != NULL)
            insertRevocation(filename, inputCRL, i);
        else
            break;
        i++;
    }
}

void writeChain(const char *filename, const Chain *inputChain)
{
    newChainList(filename, inputChain);
    int i=1;
    while(strlen(inputChain->file_loc[i]) == 10)
    {
        if (inputChain->CA[i] != NULL)
        {
            if(inputChain->A[i] != NULL)
                insertChain(filename, inputChain, i);
            else
                break;
        }
        else
            break;
    }
}


char validateCRL(const char *filename)
{
    printf("Validating \"%s\" CRL...\n", filename);
    CRL check;
    readRevocationList(filename, &check);

    char rV;
    char currentTime[32];
    getCurrentDate(currentTime);
    if (strcmp(check.tU, currentTime) > 0)
        rV = '3';
    else if (strcmp(check.nU, currentTime) < 0)
        rV = '3';
    else
        rV = 'Y';

    if (rV == 'Y')
        printf(" - CRL Valid\n");
    else if (rV == '3')
        printf(" - CRL Invalid: \"This Update: %s\" \"Next Update: %s\"\n", check.tU, check.nU);
    else
        printf(" - CRL Validation Error\n");

    return rV;
}
// 'Y' = Valid
char verifyCerts(const char *filename, const char *CRL_File, const char *hashfile)
{
    char rV = 'Y', hashCh, filehash;
    //printf("Verifying Cert: \"%s\"...\n", filename);
    Cert cert1;
    if (readCertFromFile(filename, &cert1) != 0)
        rV = '4';
    else if (datesValid(&cert1) == 'N')
        rV = '3';
    else
    {
        hashCh = hash(filename);
        filehash = readHashFile(hashfile);
        if (filehash != hashCh)
            rV = '2';
        else
        {
            // Look for a matching Serial number in the Revocation list
            CRL crl;
            FILE *readFile = fopen(CRL_File, "r");
            if (readFile == NULL)
                printf(" - No \"%s\" detected\n", CRL_File);
            else
            {
                if (validateCRL(CRL_File) == 'Y')
                {
                    int num_entries = readRevocationList(CRL_File, &crl);
                    for (int i = 0; i < num_entries; i++)
                        if (strcmp(crl.SN[i], cert1.SN) == 0)
                            rV = '1';
                }
            }
        }
    }
    if (rV == 'Y')
        printf(" > Certificate Verified!\n");
    else if (rV == '1')
        printf(" > Verification Error %c: Serial Number \"%s\" REVOKED in \"%s\"\n", rV, cert1.SN, CRL_File);
    else if (rV == '2')
        printf(" > Verification Error %c: \"%s\" doesn't match hash (%c != %c)\n", rV, filename, filehash, hashCh);
    else if (rV == '3')
        printf(" > Verification Error %c: Invalid Dates: FROM %s  UNTIL %s\n", rV, cert1.Ta, cert1.Tb);
    else if (rV == '4')
        printf(" > Verification Error %c: Did not open Cert\n", rV);
    else
        printf(" > Verification Error: Unspecified (rV='%c'\n", rV);
    
    return rV;
}
void CRL_FileToString(const char *filename, char **certStr)
{
    CRL newCert;
    int entries = readRevocationList(filename, &newCert);

    size_t totalSize = strlen(newCert.AI) + strlen(newCert.CA) + 
                       strlen(newCert.tU) + strlen(newCert.nU) +
                       strlen(newCert.S) + 5;
    for (int i = 0; i < entries; i++)
        totalSize = totalSize + (strlen(newCert.RD[0]) + strlen(newCert.SN[0]) + 2);
    *certStr = (char *)malloc(totalSize);
    if (*certStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    (*certStr)[0] = '\0';
    strcat(*certStr, newCert.AI);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.CA);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.tU);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.nU);
    strcat(*certStr, "\n");
    strcat(*certStr, newCert.S);
    strcat(*certStr, "\n");
    for (int i = 0; i < entries; i++)
    {
        strcat(*certStr, newCert.SN[i]);
        strcat(*certStr, "\n");
        strcat(*certStr, newCert.RD[i]);
        strcat(*certStr, "\n");
    }
}

void chainfiletostring(const char *filename, char **chainStr)
{
    Chain newChain;
    int entries = readChain(filename, &newChain);

    size_t totalSize;
    for (int i = 0; i < entries; i++)
        totalSize = totalSize + (strlen(newChain.file_loc[0]) + strlen(newChain.CA[0]) + strlen(newChain.A[0]) + 3);
    *chainStr = (char *)malloc(totalSize);
    if (*chainStr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    (*chainStr)[0] = '\0';
    for (int i = 0; i < entries; i++)
    {
        strcat(*chainStr, newChain.file_loc[i]);
        strcat(*chainStr, "\n");
        strcat(*chainStr, newChain.CA[i]);
        strcat(*chainStr, "\n");
        strcat(*chainStr, newChain.A[i]);
        strcat(*chainStr, "\n");
    }
}


void stringToCRL(const char *certStr, CRL *cert) {
    const char *delimiter = "\n";
    char *token;
    char tempStr[50];
    token = strtok((char *)certStr, delimiter);
    if (token != NULL) {
        strcpy(cert->AI, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->CA, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->tU, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->nU, token);
        token = strtok(NULL, delimiter);
    }
    if (token != NULL) {
        strcpy(cert->S, token);
        token = strtok(NULL, delimiter);
    }

    for (int i = 0; i < 64; i++)
    {
        if (token != NULL) {
            strcpy(cert->SN[i], token);
            token = strtok(NULL, delimiter);
        }
        else
            break;
        if (token != NULL) {
            strcpy(cert->RD[i], token);
            token = strtok(NULL, delimiter);
        }
        else
            break;
    }
}

void stringtoChain(const char *ccStr, Chain *chain)
{
    const char *delimiter = "\n";
    char *token;
    char tempStr[50];
    token = strtok((char *)ccStr, delimiter);
    for (int i = 0; i < 64; i++)
    {
        if (token != NULL) {
            strcpy(chain->file_loc[i], token);
            token = strtok(NULL, delimiter);
        }
        else
            break;
        if (token != NULL) {
            strcpy(chain->CA[i], token);
            token = strtok(NULL, delimiter);
        }
        else
            break;
        if (token != NULL) {
            strcpy(chain->A[i], token);
            token = strtok(NULL, delimiter);
        }
        else
            break;
    }
}


void stringToFile_CRL(const char *filename, const char *string)
{
    CRL crl;
    stringToCRL(string, &crl);
    writeCRL(filename, &crl);
    printf(" > \"%s\" created/updated\n", filename);
}
void newChainToFile(const char *chainfile, const char* certfile, const Cert *inputCert)
{
    FILE *writeFile = fopen(chainfile, "w");
    fprintf(writeFile, " - Root\n");
    fprintf(writeFile, "Location: %s\n", certfile);
    fprintf(writeFile, "Issuer: %s\n", inputCert->CA);
    fprintf(writeFile, "Subject: %s\n", inputCert->A);
    fprintf(writeFile, " - - - -\n");
    fclose(writeFile);
}
void insertChainToFile(const char *chainfile, const char* certfile, const Cert *newCert, const Cert *CAcert)
{

    printf(" > Inserting Cert to Chain...\n");
    FILE *writeFile = fopen(chainfile, "a");
    fprintf(writeFile, "Location: %s\n", certfile);
    fprintf(writeFile, "Issuer: %s\n", CAcert->A);
    fprintf(writeFile, "Subject: %s\n", newCert->A);
    fprintf(writeFile, " - - - -\n");
    fclose(writeFile);
    printf(" > Cert Inserted into Chain\n");
    writeCertToFile(certfile, newCert);
}
void alterCertForChain(const char *certFile, const char *CAfile, const char *hashfile)
{
    Cert CAcert, newCert;
    readCertFromFile(CAfile, &CAcert);
    readCertFromFile(certFile, &newCert);
    strcpy(newCert.CA, CAcert.A);
    strcpy(newCert.S, "0");
    newCert.S[0] = pkHash(CAcert.Ap);

    writeCertToFile(certFile, &newCert);
    writeHashFile(hashfile, hash(certFile));
    printf(" > Certificate updated \"%s\"\n", certFile);
}
void nextChain()
{
    char fileName[128];
    printf("Enter '0' to exit, or add a Certificate file name (no extension): ");
    scanf(" %[^\n]", fileName);
    if(strcmp(fileName, "0") != 0)
    {
        char CAcert[128];
        printf("Enter Issuer's Certificate file name (no extension): ");
        scanf(" %[^\n]", CAcert);

        // Allocate memory for hashfile and hashStr
        char hashfile[128];
        char *hashStr = (char *)malloc(320);
        char temp_path[128];
        strcpy(temp_path, FILEPATH);
        strcat(temp_path, fileName);
        strcpy(fileName, temp_path);
        strcpy(hashfile, temp_path);

        strcpy(temp_path, FILEPATH);
        strcat(temp_path, CAcert);
        strcpy(CAcert, temp_path);

        strcat(hashfile, "_hash.txt");
        strcat(fileName, ".txt");
        strcat(CAcert, ".txt");

        alterCertForChain(fileName, CAcert, hashfile);
        Cert cert_1, CA_1;
        if (readCertFromFile(fileName, &cert_1) != 0)
        {
            printf(" > Subject Cert doesn't exist\n");
            return;
        }
        else if (readCertFromFile(CAcert, &CA_1) != 0)
        {
            printf(" > Issuer Cert doesn't exist\n");
            return;
        }
        insertChainToFile(CHAIN_FILEPATH, fileName, &cert_1, &CA_1);
        nextChain();
    }
}
// Returns number of entries
int readChain(const char *chainfile, Chain *outChain)
{
    FILE *readFile = fopen(chainfile, "r");
    fscanf(readFile, " - Root\n");
    int i = 0;
    while (fscanf(readFile, "Location: %s\n", outChain->file_loc[i]) != EOF)
    {
        fscanf(readFile, "Issuer: %s\n", outChain->CA[i]);
        fscanf(readFile, "Subject: %s\n", outChain->A[i]);
        fscanf(readFile, " - - - -\n");
        i++;
        if (i > 63)
            break;
    }
    fclose(readFile);
    return i;
}
int verifyChain(const char *c1, const char *c2, const char *crl, const char *chn)
{
    char trustLevel[2];
    strcpy(trustLevel, "8"); // Default higher than possible TL
    Cert cert1, cert2, l_cert, r_cert;

    // Check Both certs exist
    if (readCertFromFile(c1, &cert1) != 0)
        return 11;
    else if (readCertFromFile(c2, &cert2) != 0)
        return 12;
    readCertFromFile(c1, &l_cert);
    readCertFromFile(c2, &r_cert);
    
    char parentFile1[128];

    Chain chain1;
    int num_certs_in_chain = readChain(chn, &chain1);

    char list_of_parents_of_c1[128][64];
    int num_p_o_c1 = 0;
    int done = 0;

    strcpy(list_of_parents_of_c1[0], c1);
    num_p_o_c1++;

    // Get the parents of C1
    while (done != 1)
    {
        // it's at the root
        if (strcmp(chain1.CA[0], l_cert.A) == 0)
        {
            done = 1; // last possible parent
            break;
        }

        for (int i = 0; i < num_certs_in_chain; i++)
        {
            // Update when it finds a subject that's the current L_cert's issuer
            if (strcmp(chain1.A[i], l_cert.CA) == 0)
            {
                strcpy(list_of_parents_of_c1[num_p_o_c1], chain1.file_loc[i]);
                num_p_o_c1++; // record this file location
                readCertFromFile(chain1.file_loc[i], &l_cert); // Save this file into the l cert
                done = 0; // it found a parent
            }
        }
    }

    char list_of_parents_of_c2[128][64];
    int num_p_o_c2 = 0;
    done = 0;

    strcpy(list_of_parents_of_c2[0], c2);
    num_p_o_c2++;

    // Get the parents of C2
    while (done != 1)
    {
        // it's at the root
        if (strcmp(chain1.CA[0], r_cert.A) == 0)
        {
            done = 1; // last possible parent
            break;
        }

        for (int i = 0; i < num_certs_in_chain; i++)
        {
            // Update when it finds a subject that's the current L_cert's issuer
            if (strcmp(chain1.A[i], r_cert.CA) == 0)
            {
                strcpy(list_of_parents_of_c2[num_p_o_c2], chain1.file_loc[i]);
                num_p_o_c2++; // record this file location
                readCertFromFile(chain1.file_loc[i], &r_cert); // Save this file into the l cert
                done = 0; // it found a parent
            }
        }
    }

    // for (int i = 0; i < num_p_o_c1; i++)
    //     printf("%s\n", list_of_parents_of_c1[i]);
    // printf("\n");
    // for (int i = 0; i < num_p_o_c2; i++)
    //     printf("%s\n", list_of_parents_of_c2[i]);

    done = 0;
    int c1_root_index = 0, c2_root_index = 0;
    for (int i = 0; i < num_p_o_c2; i++)
    {
        for (int j = 0; j < num_p_o_c1; j++)
        {
            if (strcmp(list_of_parents_of_c1[j], list_of_parents_of_c2[i]) == 0)
            {
                c1_root_index = j;
                c2_root_index = i;
                done = 1;
                break;
            }
        }
        if (done == 1)
            break;
    }

    // Get Trust Level
    for (int i = 0; i <= c1_root_index; i++)
    {
        Cert current_cert;
        readCertFromFile(list_of_parents_of_c1[i], &current_cert);

        int namelen = strlen(list_of_parents_of_c1[i]); /* possibly you've saved the length previously */
        char certfile[128];
        strncpy(certfile, list_of_parents_of_c1[i], namelen-4);
        certfile[namelen-4] = '\0';

        char hashfile[128];
        char temp_path[128];
        strcpy(temp_path, FILEPATH);
        strcat(temp_path, certfile);
        strcpy(certfile, temp_path);
        strcpy(hashfile, temp_path);
        strcat(hashfile, "_hash.txt");
        strcat(certfile, ".txt");

        if (verifyCerts(certfile, crl, hashfile) != 'Y')
        {
            strcpy(trustLevel, "N");
            break;
        }

        printf("      \"%s\" Trust Level: %s\n", current_cert.A, current_cert.TL);
        if (strcmp(trustLevel, current_cert.TL) > 0)
            strcpy(trustLevel, current_cert.TL);
    }

    for (int i = c2_root_index-1; i >= 0; i--) // -1 so we dont read the root again
    {
        if (strcmp(trustLevel, "N") == 0)
            break;
        Cert current_cert;
        readCertFromFile(list_of_parents_of_c2[i], &current_cert);

        int namelen = strlen(list_of_parents_of_c2[i]); /* possibly you've saved the length previously */
        char certfile[128];
        strncpy(certfile, list_of_parents_of_c2[i], namelen-4);
        certfile[namelen-4] = '\0';

        char hashfile[128];
        char temp_path[128];
        strcpy(temp_path, FILEPATH);
        strcat(temp_path, certfile);
        strcpy(certfile, temp_path);
        strcpy(hashfile, temp_path);
        strcat(hashfile, "_hash.txt");
        strcat(certfile, ".txt");

        if (verifyCerts(certfile, crl, hashfile) != 'Y')
        {
            strcpy(trustLevel, "N");
            break;
        }

        printf("      \"%s\" Trust Level: %s\n", current_cert.A, current_cert.TL);
        if (strcmp(trustLevel, current_cert.TL) > 0)
            strcpy(trustLevel, current_cert.TL);
    }

    if (strcmp(trustLevel, "N") != 0)
        printf(" > Chain Trust Level \"%s\" to \"%s\": %s\n", cert1.A, cert2.A, trustLevel);
    else
        printf(" > Chain Verification Error!\n");
    return atoi(trustLevel);
}
int prompt()
{
    printf("\n");
    printf("[1] Create Cert\n");
    printf("[2] Validate Cert\n");
    printf("[3] Revoke Cert\n");
    printf("[4] Send Cert    (client)\n");
    printf("[5] Send CRL     (client)\n");
    printf("[6] Receive Cert (server)\n");
    printf("[7] Receive CRL  (server)\n");
    printf("[8] Create Cert Chain\n");
    printf("[9] Verify Cert Chain\n");
    printf("[10] Send Cert Chain\n");
    printf("[11] Recieve Cert Chain\n");
    printf("[0] EXIT\n");

    int choice;
    printf(" Enter Option (0-11): ");
    scanf("%d", &choice);
    printf("\n");
    return choice;
}
void menu_createCert()
{
    char fileName[128];
    char signAlgorithm[16];
    char issuer[64];
    char subject[64];
    char publicKey[64];
    char startDate[32];
    char endDate[32];
    char trustLevel[16];
    char signature[64];

    printf("NOTE: Do not enter spaces for any prompts.\n");
    printf("Enter New File Name: ");
    scanf(" %[^\n]", fileName);

    printf("Enter Sign Algorithm: ");
    scanf(" %[^\n]", signAlgorithm);

    printf("Enter Issuer: ");
    scanf(" %[^\n]", issuer);

    printf("Enter Subject: ");
    scanf(" %[^\n]", subject);

    printf("Enter Public Key: ");
    scanf(" %[^\n]", publicKey);

    printf("Enter End Date (YYYY/MM/DD): ");
    scanf(" %[^\n]", endDate);

    printf("Enter Trust Level: ");
    scanf(" %[^\n]", trustLevel);

    printf("Enter Signature: ");
    scanf(" %[^\n]", signature);

    Cert cert = {
        .V = "1",
        .AI = {0},
        .CA = {0},
        .A = {0},
        .Ap = {0},
        .Ta = {0},
        .Tb = {0},
        .TL = {0},
        .S = {0}
    };

    strcpy(cert.AI, signAlgorithm);
    strcpy(cert.CA, issuer);
    strcpy(cert.A, subject);
    strcpy(cert.Ap, publicKey);
    strcpy(cert.Tb, endDate);
    strcpy(cert.TL, trustLevel);
    strcpy(cert.S, signature);

    // Set current date
    char currentTime[32];
    getCurrentDate(currentTime);
    strncpy(cert.Ta, currentTime, sizeof(cert.Ta) - 1);

    // Randomize Serial Number
    time_t t;
    srand((unsigned) time(&t));
    sprintf(cert.SN, "%05d", rand() % 100000);


    // Allocate memory for hashfile and hashStr
    char hashfile[128];
    char *hashStr = (char *)malloc(320);

    char temp_path[128];
    strcpy(temp_path, FILEPATH);
    strcat(temp_path, fileName);
    strcpy(fileName, temp_path);
    strcpy(hashfile, temp_path);

    strcat(hashfile, "_hash.txt");
    strcat(fileName, ".txt");

    writeCertToFile(fileName, &cert);
    printf(" > Certificate created \"%s\"\n", fileName);

    writeHashFile(hashfile, hash(fileName));
}
void menu_validateCert()
{
    char fileName[128];

    printf("NOTE: Do not enter spaces for any prompts.\n");
    printf("Enter existing Certificate file name (ignore extension): ");
    scanf(" %[^\n]", fileName);
    char temp_path[128];
    strcpy(temp_path, FILEPATH);
    strcat(temp_path, fileName);
    strcpy(fileName, temp_path);
    
    // Allocate memory for hashfile and hashStr
    char hashfile[136];

    strcpy(hashfile, fileName);

    strcat(hashfile, "_hash.txt");
    strcat(fileName, ".txt");

    char *crlfile = CRL_FILEPATH;

    verifyCerts(fileName, crlfile, hashfile);
}
void menu_revokeCert()
{
    char fileName[128];

    printf("NOTE: Do not enter spaces for any prompts.\n");
    printf("Enter existing Certificate file name (no extension): ");
    scanf(" %[^\n]", fileName);
    char temp_path[128];
    strcpy(temp_path, FILEPATH);
    strcat(temp_path, fileName);
    strcpy(fileName, temp_path);
    
    strcat(fileName, ".txt");
    Cert cert1;
    if (readCertFromFile(fileName, &cert1) != 0)
        return;

    FILE *readFile = fopen(CRL_FILEPATH, "r");
    if (readFile == NULL)
    {
        printf("\n > No existing CRL found. Creating new \"CRL.txt\"...\n");
        // Make new CRL file
        CRL crl1 =
        {
            .AI = "AlgIdentifier",
            .CA = {0},
            .tU = "",
            .nU = "2024/01/01",
            .S  = {0},
            .SN[0] = {0},
            .RD[0] = {0},
        };

        // Set current date
        char currentTime[32];
        getCurrentDate(currentTime);
        snprintf(crl1.tU, sizeof(crl1.tU), "%s", currentTime);
        snprintf(crl1.RD[0], sizeof(crl1.RD[0]), "%s", currentTime);

        char issuer[64];
        printf("Enter Certificate Authority (Issuer): ");
        scanf(" %[^\n]", issuer);
        strcpy(crl1.CA, issuer);

        char timetonextUpdate[16];
        printf("Enter Next Update Date (YYYY/MM/DD): ");
        scanf(" %[^\n]", timetonextUpdate);
        strcpy(crl1.nU, timetonextUpdate);

        char signature[32];
        printf("Enter Signature: ");
        scanf(" %[^\n]", signature);
        strcpy(crl1.S, signature);

        strcpy(crl1.SN[0], cert1.SN);

        newRevocationList(CRL_FILEPATH, &crl1);
        printf(" > \"CRL.txt\" created\n");
    }
    else
    {
        CRL crl1;
        int num_entries = readRevocationList(CRL_FILEPATH, &crl1);

        // Set current date
        char currentTime[32];
        getCurrentDate(currentTime);
        snprintf(crl1.tU, sizeof(crl1.tU), "%s", currentTime);
        if (strcmp(crl1.tU, crl1.nU) > 0)
        {
            char timetonextUpdate[16];
            printf("Enter Next Update Date (YYYY/MM/DD): ");
            scanf(" %[^\n]", timetonextUpdate);
            strcpy(crl1.nU, timetonextUpdate);
        }

        snprintf(crl1.RD[num_entries], sizeof(crl1.RD[num_entries]), "%s", currentTime);

        strcpy(crl1.SN[num_entries], cert1.SN);

        insertRevocation(CRL_FILEPATH, &crl1, num_entries);
    }
    fclose(readFile);
    printf(" > Certificate Revoked\n");
}
void menu_createChain()
{
    char fileName[128];
    FILE *chainfile = fopen(CHAIN_FILEPATH, "r");
    if (chainfile == NULL)
    {
        printf("NOTE: Do not enter spaces for any prompts.\n");
        printf("Enter existing Certificate file name (no extension): ");
        scanf(" %[^\n]", fileName);
        char temp_path[128];
        strcpy(temp_path, FILEPATH);
        strcat(temp_path, fileName);
        strcpy(fileName, temp_path);
        
        strcat(fileName, ".txt");
        Cert cert1;
        if (readCertFromFile(fileName, &cert1) != 0)
            return;
        newChainToFile(CHAIN_FILEPATH, fileName, &cert1);
        printf(" > \"CHAIN.TXT\" created\n");
        nextChain();
    }
    else
        nextChain();
    fclose(chainfile);
}
void menu_verifyChain()
{
    char fileName1[128], fileName2[128];

    printf("NOTE: Do not enter spaces for any prompts.\n");
    printf("Enter 1st Certificate file name (ignore extension): ");
    scanf(" %[^\n]", fileName1);
    printf("Enter 2nd Certificate file name (ignore extension): ");
    scanf(" %[^\n]", fileName2);

    char temp_path[128];
    strcpy(temp_path, FILEPATH);
    strcat(temp_path, fileName1);
    strcpy(fileName1, temp_path);

    strcpy(temp_path, FILEPATH);
    strcat(temp_path, fileName2);
    strcpy(fileName2, temp_path);

    strcat(fileName1, ".txt");
    strcat(fileName2, ".txt");

    char *crlfile = CRL_FILEPATH, *chainfile = CHAIN_FILEPATH;

    verifyChain(fileName1, fileName2, crlfile, chainfile);
}
int menu()
{
    int menu_choice = 1;
    menu_choice = prompt();
    switch (menu_choice)
    {
        case 1:
            printf(" > \"Create Cert\" selected\n");
            menu_createCert();
            break;
        case 2:
            printf(" > \"Validate Cert\" selected\n");
            menu_validateCert();
            break;
        case 3:
            printf(" > \"Revoke Cert\" selected\n");
            menu_revokeCert();
            break;
        case 4: // send cert
        case 5: // send CRL
        case 6: // receive cert
        case 7: // receive CRL
            break;
        case 8:
            printf(" > \"Create Cert Chain\" selected\n");
            menu_createChain();
            break;
        case 9:
            printf(" > \"Verify Cert Chain\" selected\n");
            menu_verifyChain();
            break;
        case 10: //send cert chain
        case 11: //recieve cert chain
            break;
        case 0:
            printf(" > Exit Menu\n");
            break;
        default:
            printf(" > Invalid menu choice\n");
    }
    return menu_choice;
}


#endif
