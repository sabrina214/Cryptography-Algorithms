#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void encrypt(char *plainText, char *cipherText);
void decrypt(char *cipherText, char *decryptedText);

void main(int argc, char *args[]) {
    printf("Usage: <object-file> | <object-file> <plain-text>");
    
    char *plainText;
    
    printf("\nEncrypting...\n");
    if (argc == 2) {
        plainText = args[1];
        printf("Plaintext: %s\n", args[1]);
    }
    else {
        plainText = (char *)malloc(sizeof(char) * 256);
        printf("Plaintext: ");
        scanf("%s", plainText);
    }
    
    char *cipherText = (char *)malloc(sizeof(plainText));

    encrypt(plainText, cipherText);
    printf("Ciphertext: %s\n", cipherText);

    printf("\nDecrypting...\n");
    printf("Ciphertext: %s\n", cipherText);
    char *decryptedText = (char *)malloc(sizeof(plainText));
    decrypt(cipherText, decryptedText);
    printf("Plaintext: %s\n", decryptedText);
}

void encrypt(char *plainText, char *cipherText){
    int len = strlen(plainText);   
    const int key = 3;

    for(int i = 0; plainText[i] != '\0'; ++i) {
        int p = (int)(plainText[i]);
        
        if (p >= (int)('a') && p <= (int)('z')) {
            cipherText[i] = ((char)(((int)(plainText[i]) - (int)('a') + key) % 26)) + (int)('a');
        }
        else if (p >= (int)('A') && p <= (int)('Z')) {
            cipherText[i] = ((char)(((int)(plainText[i]) - (int)('A') + key) % 26)) + (int)('A');
        }   
    } 
}

void decrypt(char *cipherText, char *decryptedText){
    const int key = 23; // additive inverse of key used during encryption

    for(int i = 0; cipherText[i] != '\0'; ++i) {
        int p = (int)(cipherText[i]);
        
        if (p >= (int)('a') && p <= (int)('z')) {
            decryptedText[i] = ((char)(((int)(cipherText[i]) - (int)('a') + key) % 26)) + (int)('a');
        }
        else if (p >= (int)('A') && p <= (int)('Z')) {
            decryptedText[i] = ((char)(((int)(cipherText[i]) - (int)('A') + key) % 26)) + (int)('A');
        }   
    } 
}