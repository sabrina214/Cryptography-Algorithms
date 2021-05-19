#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void encrypt(char *plainText, char *cipherText, char *key);
void decrypt(char *cipherText, char *key);


void main(int argc, char *args[]) {
    printf("Usage: <object-file> | <object-file> <plain-text> <key>");
    
    char *plainText, *key;
    
    printf("\nEncrypting...\n");
    if (argc == 3) {
        plainText = args[1];
        printf("Plaintext: %s\n", args[1]);
        key = args[2];
    }
    else {
        plainText = (char *)malloc(sizeof(char) * 256);
        printf("Plaintext: ");
        scanf("%s", plainText);
        printf("Key: ");
        scanf("%s", key);
    }
    
    char *cipherText = (char *)malloc(sizeof(plainText));

    encrypt(plainText, cipherText, key);
    printf("Ciphertext: %s\n", cipherText);

    printf("\nDecrypting...\n");
    printf("Ciphertext: %s\n", cipherText);
    decrypt(cipherText, key);
    printf("Plaintext: %s\n", cipherText);
}

void encrypt(char *plainText, char *cipherText, char *key){
    int len = strlen(plainText);   

    for(int i = 0; plainText[i] != '\0'; ++i) {
        int p = (int)(plainText[i]);
        
        if (p >= (int)('a') && p <= (int)('z')) {
            cipherText[i] = ((char)(((int)(plainText[i]) - (int)('a') + (int)(key[i] - (int)('a')) % strlen(key)) % 26)) + (int)('a');
        }
        else if (p >= (int)('A') && p <= (int)('Z')) {
            cipherText[i] = ((char)(((int)(plainText[i]) - (int)('A') + (int)(key[i] - (int)('A')) % strlen(key)) % 26)) + (int)('A');
        }   
    } 
}

void decrypt(char *cipherText, char *key){

    for(int i = 0; cipherText[i] != '\0'; ++i) {
        int p = (int)(cipherText[i]);
        
        if (p >= (int)('a') && p <= (int)('z')) {
            cipherText[i] = ((char)(((int)(cipherText[i]) - (int)('a') - (int)(key[i] - (int)('a')) % strlen(key)) % 26)) + (int)('a');
        }
        else if (p >= (int)('A') && p <= (int)('Z')) {
            cipherText[i] = ((char)(((int)(cipherText[i]) - (int)('A') - (int)(key[i] - (int)('A')) % strlen(key)) % 26)) + (int)('A');
        }   
    } 
}