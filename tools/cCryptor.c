// Library Imports
#include <string.h>
#include <bearssl.h>
//#include "beaverssl.h"
#include <stdio.h>
#include <stdint.h>
#include "keys.h"
int main(){
    printf("%x\n", HEADER[0]);

    uint8_t frame[48] = {0x94, 0x3b, 0xef, 0xf0, 0x73, 0xc6, 0x1, 0xa2, 0x28, 0x4b, 0x41, 0x84, 0x2c, 0x70, 0x11, 0xeb, 0x49, 0x93, 0x97, 0xd9, 0x71, 0xeb, 0x66, 0x69, 0x3b, 0x83, 0x2a, 0xe3, 0xb2, 0xac, 0x6c, 0xc5, 0xca, 0x93, 0x34, 0x80, 0x7a, 0x64, 0x8e, 0xd5, 0x82, 0xbf, 0xd9, 0x84, 0xcc, 0xe2, 0x44, 0xd8};

    uint8_t data[16] = {};
    uint8_t nonce[16] = {};
    uint8_t tag[16] = {};

    for (int i = 0; i < 16; i++){//Breaks up input
        data[i] = frame[i];
    }

    for (int i = 0; i < 16; i++){
        tag[i] = frame[i + 16];
    }


    for (int i = 0; i < 16; i++){
        nonce[i] = frame[i + 32];
    }



}

