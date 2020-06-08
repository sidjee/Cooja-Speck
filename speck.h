#ifndef SPECK_H_
#define SPECK_H_

void encrypt(char* inp, char* op, unsigned long long key[], int mode);

void decrypt(char* inp, char* op, unsigned long long key[],int mode);

#endif