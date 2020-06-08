/*
   In this code, we define two functions:

   1) function encrypt_file() is used to encrypt a file using SPECK cipher
   2) function decrypt_file() is used to decrypt a file using SPECK cipher
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint64_t InitialVec();
void speck_keyschedule(unsigned long long key[], unsigned long long subkey[]);
void speck_encryption_ecb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[]);
void speck_decryption_ecb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[]);
void speck_encryption_cbc(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[]);
void speck_decryption_cbc(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[]);
void speck_encryption_ofb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[]);
void speck_decryption_ofb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[]);

#define LCS(x,n) ( (x << n) | (x >> (64-n)) ) // right-rotate a 64-bit word x by n-bit positions
#define RCS(x,n) ( (x >> n) | (x << (64-n)) ) // right-rotate a 64-bit word x by n-bit positions
#define R(x,y,k) (x=RCS(x,8), x+=y, x^=k, y=LCS(y,3), y^=x)
#define InverseR(x,y,k)  ( y ^=x, y=RCS(y,3), x^=k, x-=y, x=LCS(x,8) )

void write_back(char *blk, int siz, int *len, char *op){
    for(int i1=0; i1<siz; i1++){
        op[i1+(*len)] = blk[i1];
    }
    (*len)+=siz;
}

void read_it(char *blk, int siz, int *off, char *inp){
    for(int i1=0; i1<siz; i1++){
        blk[i1] = inp[(*off)+i1];
    }
    (*off)+=siz;
}

//The key schedule
//input:  key,           an array with 2 64-bit words
//output: 32 round keys, an array with 32 64-bit words
void speck_keyschedule(unsigned long long key[], unsigned long long subkey[])
{
    unsigned long long i,B=key[1],A=key[0];

    for(i=0; i<32; i++)
    {
        subkey[i] = A;
        R(B,A,i);
    }
}

//encrypt a file
//three inputs to this function: the name of the file to be encrypted
//                               the name of the encrypted file,
//                               the key provided by the user
void encrypt(char* inp, char* op, unsigned long long key[], int mode)
{
    int len=0, off=0;
    // op = malloc(strlen(inp)+33);
    unsigned long long subkey[32];
    unsigned long long plaintext[2];
    unsigned long long ciphertext[2];
    unsigned long long vec[2];
    char block[16];           //each time we will read at most 16 byte data into memblock from the file
    unsigned long long input_file_size = strlen(inp);

    speck_keyschedule(key, subkey);

    // Set up IV for CBC or OFB Mode
    if (mode == 2 || mode == 3)
    {
        vec[0]=InitialVec();
        vec[1]=InitialVec();
        ((unsigned long long*)(block))[0] = vec[0];
        ((unsigned long long*)(block))[1] = vec[1];
        write_back(block,16, &len, op);
    }

    // Read in 16 bytes until message block is not full
    for (unsigned long long i = 0; i+16 <= input_file_size; i+=16)
    {
        //read 16 bytes into the array block
        read_it(block,16, &off, inp);

        //convert those 16 byes into two 64-bit words
        //if you are not familiar with pointer, you may use an alternative way for conversion:
        //  plaintext[0] = block[7];
        //  for (int j = 6; j >= 0; j--)  plaintext[0] = (plaintext[0] << 8) | block[j];
        //  plaintext[1] = block[15];
        //  for (int j = 14; j >= 8; j--) plaintext[1] = (plaintext[1] << 8) | block[j];
        plaintext[0] = ((unsigned long long*)(block))[0];
        plaintext[1] = ((unsigned long long*)(block))[1];

        //perform encryption of one block
        if (mode==1)
        {
            speck_encryption_ecb(plaintext, ciphertext, subkey);
        }
        else if (mode ==2)
        {
            speck_encryption_cbc(plaintext, ciphertext, subkey,vec);
        }
        else
        {
            speck_encryption_ofb(plaintext, ciphertext, subkey,vec);
        }

        //convert those two ciphertext words into 16 bytes
        //if you are not familiar with pointer, you may use an alternative way for conversion:
        //  for (int j = 0; j < 8; j++) block[j] = (ciphertext[0] >> 8*j) & 0xff;
        //  for (int j = 0; j < 8; j++) block[j+8] = (ciphertext[1] >> 8*j) & 0xff;
        ((unsigned long long*)(block))[0] = ciphertext[0];
        ((unsigned long long*)(block))[1] = ciphertext[1];

        //write_back the ciphertext block into the output file
        write_back(block,16, &len, op);
    }

    //encrypt the last block
    unsigned int t = input_file_size & 0xf; // it means: t = input_file_size % 16;
    read_it(block,t, &off, inp);

    //Padding for ECB and CBC Mode
    if (mode==1 || mode ==2)
    {
        for (int i = 0; i < 16-t; i++)
        {
            block[t+i] = 16-t; //append the value(s) 16-t into the block so that we get a full block
        }
    }

    //encrypt those 16 bytes in block
    plaintext[0] = ((unsigned long long*)(block))[0];
    plaintext[1] = ((unsigned long long*)(block))[1];

    //perform encryption of one block
    if (mode==1)
    {
        speck_encryption_ecb(plaintext, ciphertext, subkey);
    }
    else if (mode ==2)
    {
        speck_encryption_cbc(plaintext, ciphertext, subkey,vec);
    }
    else
    {
        speck_encryption_ofb(plaintext, ciphertext, subkey,vec);
    }

    ((unsigned long long*)(block))[0] = ciphertext[0];
    ((unsigned long long*)(block))[1] = ciphertext[1];

    if (mode==1 || mode==2)
    {
        write_back(block, 16, &len, op);
    }
    else
    {
        write_back(block, t, &len, op);
    }
    op[len] = '\0';
}

//decrypt a file
//three inputs to this function: the name of the file to be decrypted
//                               the name of the decrypted file,
//                               the key provided by the user
void decrypt(char* inp, char* op, unsigned long long key[],int mode)
{
    int len=0, off=0;
    unsigned long long subkey[32];
    unsigned long long plaintext[2];
    unsigned long long ciphertext[2];
    unsigned long long vec[2];
    unsigned long long i;

    char block[16];           //each time we will read at most 16 byte data into memblock from the file
    unsigned long long input_file_size = strlen(inp);

    speck_keyschedule(key, subkey);

    
    // Set up IV for CBC and OFB 
    if (mode==2 || mode==3)
    {
        read_it(block,16, &off, inp);
        vec[0]=((unsigned long long*)(block))[0];
        vec[1] = ((unsigned long long*)(block))[1];
        i=16; //  Starting reading after the IV (first message block)
    }
    else
    {
        i=0; // If ECB mode, start reading from the beginning
    }

    for (; i+16 <= input_file_size; i+=16)
    {
        //read 16 bytes into the array block
        read_it(block,16, &off, inp);

        //convert those 16 bytes into two 64-bit words
        ciphertext[0] = ((unsigned long long*)(block))[0];
        ciphertext[1] = ((unsigned long long*)(block))[1];

        //perform decryption of one block
        if (mode==1)
        {
            speck_decryption_ecb(plaintext, ciphertext, subkey);
        }
        else if (mode ==2)
        {
            speck_decryption_cbc(plaintext, ciphertext, subkey,vec);
        }
        else
        {
            speck_decryption_ofb(plaintext, ciphertext, subkey,vec);
        }


        //convert those two words into 16 bytes
        ((unsigned long long*)(block))[0] = plaintext[0];
        ((unsigned long long*)(block))[1] = plaintext[1];

        //write_back the plaintext block into the output file
        if (i + 16 < input_file_size)
        {
            write_back(block, 16, &len, op);  //not the last block
        }
        else if (i + 16 == input_file_size)
        {
            if (mode==1 || mode==2){
                write_back(block, 16 - block[15], &len, op);
            }
            else{write_back(block, 16, &len, op);} // For OFB Mode, just write_back in the full block
        }
    }

    if (mode==3) // For OFB mode, there is no padding so have to write_back last partial block (if any)
    {
        read_it(block, input_file_size & 0xf, &off, inp);
        
        //decrypt those 16 bytes in block
        ciphertext[0] = ((unsigned long long*)(block))[0];
        ciphertext[1] = ((unsigned long long*)(block))[1];

        //perform decryption of one block
        speck_decryption_ofb( plaintext, ciphertext, subkey, vec);

        //join both plaintext into a single block
        ((unsigned long long*)(block))[0] = plaintext[0];
        ((unsigned long long*)(block))[1] = plaintext[1];

        //write_back out block
        write_back(block, input_file_size & 0xf, &len, op);
    }
    op[len]='\0';
}




// encrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a plaintext block is an array with 2 64-bit words
// output: a ciphertext block (an array with 2 64-bit words)
void speck_encryption_ofb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[])
{
    unsigned long long i;
    ciphertext[0]=vec[0];
    ciphertext[1]=vec[1];

    for(i=0; i<32; i++)
    {
        R(ciphertext[1], ciphertext[0], subkey[i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }

    vec[0]=ciphertext[0];
    vec[1]=ciphertext[1];

    ciphertext[0]^=plaintext[0];
    ciphertext[1]^=plaintext[1];

}

// decrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a ciphertext block is an array with 2 64-bit words
// output: a plaintext block (an array with 2 64-bit words)
void speck_decryption_ofb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[])
{
    unsigned long long i;
    plaintext[0]=vec[0];
    plaintext[1]=vec[1];

    for(i=0; i<32; i++)
    {
        R(plaintext[1], plaintext[0], subkey[i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }

    vec[0]=plaintext[0];
    vec[1]=plaintext[1];

    plaintext[0]^=ciphertext[0];
    plaintext[1]^=ciphertext[1];
}



// encrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a plaintext block is an array with 2 64-bit words
// output: a ciphertext block (an array with 2 64-bit words)
void speck_encryption_ecb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[])
{
    unsigned long long i;
    ciphertext[0]=plaintext[0];
    ciphertext[1]=plaintext[1];

    for(i=0; i<32; i++)
    {
        R(ciphertext[1], ciphertext[0], subkey[i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }
}

// decrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a ciphertext block is an array with 2 64-bit words
// output: a plaintext block (an array with 2 64-bit words)
void speck_decryption_ecb(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[])
{
    unsigned long long i;
    plaintext[0]=ciphertext[0];
    plaintext[1]=ciphertext[1];

    for(i=0; i<32; i++)
    {
        InverseR(plaintext[1], plaintext[0], subkey[31-i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }
}



// encrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a plaintext block is an array with 2 64-bit words
// output: a ciphertext block (an array with 2 64-bit words)
void speck_encryption_cbc(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[])
{
    unsigned long long i;
    ciphertext[0]=vec[0]^plaintext[0];
    ciphertext[1]=vec[1]^plaintext[1];

    for(i=0; i<32; i++)
    {
        R(ciphertext[1], ciphertext[0], subkey[i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }

    vec[0]=ciphertext[0];
    vec[1]=ciphertext[1];
}

// decrypt one block of message
// inputs: round keys is an array with 32 64-bit words
//         a ciphertext block is an array with 2 64-bit words
// output: a plaintext block (an array with 2 64-bit words)
void speck_decryption_cbc(unsigned long long plaintext[], unsigned long long ciphertext[], unsigned long long subkey[], unsigned long long vec[])
{
    unsigned long long i;
    plaintext[0]=ciphertext[0];
    plaintext[1]=ciphertext[1];

    for(i=0; i<32; i++)
    {
        InverseR(plaintext[1], plaintext[0], subkey[31-i]);
        // cout << endl << ciphertext[0] << "  " << subkey[i] << endl;
    }

    plaintext[0]^=vec[0];
    plaintext[1]^=vec[1];

    vec[0]=ciphertext[0];
    vec[1]=ciphertext[1];
}


uint64_t InitialVec()
{
    // FILE *myFile = fopen("/dev/random", "rb");
    // unsigned long long rand;
    // unsigned long long randomNum = fread(&rand, sizeof(rand), 1, myFile) ;
    // //printf("%d", sizeof(rand)); //Shows 8 bytes for size of number
    // //cout<<rand<<endl;
    // fclose(myFile);
    uint64_t r = 0;
    r = r*((uint64_t)RAND_MAX + 1) + rand();
    r = r*((uint64_t)RAND_MAX + 1) + rand();
    r = r*((uint64_t)RAND_MAX + 1) + rand();
    // for (int i=0; i<64; i += 30) {
    //     r = r*((uint64_t)RAND_MAX + 1) + rand();
    // }
    return r;
}
