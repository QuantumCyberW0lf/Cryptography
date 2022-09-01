#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>

#define BLOCK_SIZE 0x10
#define WORD_LENGTH 0x04

static const unsigned char SBOX[16][16] =
{
    {0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
    0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
    
    {0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
    0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},

    {0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
    0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},

    {0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
    0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},

    {0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
    0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},

    {0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
    0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},

    {0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
    0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},

    {0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
    0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},

    {0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
    0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},

    {0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
    0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
    
    {0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
    0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},

    {0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
    0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},

    {0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
    0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},

    {0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
    0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},

    {0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
    0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},

    {0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
    0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16},
};

static const unsigned char SBOX_INV[16][16] = 
{
    {0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,
    0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb},

    {0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,
    0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb},

    {0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,
    0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e},

    {0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,
    0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25},

    {0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,
    0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92},

    {0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,
    0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84},

    {0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,
    0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06},

    {0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,
    0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b},

    {0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,
    0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73},

    {0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,
    0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e},

    {0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,
    0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b},

    {0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,
    0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4},

    {0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,
    0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f},

    {0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,
    0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef},

    {0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,
    0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61},

    {0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,
    0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d},
};

const static void err(const unsigned char* func)
{
    fprintf(stderr,"[-] Error: Function %s failed.\n");
    exit(EXIT_FAILURE);
}

const static void fatal_err(void)
{
    fprintf(stderr,"[-] Error [%d] → [%s]\n",errno,strerror(errno));
    exit(EXIT_FAILURE);
}

static void word_rotate(unsigned char* word)
{
    unsigned char tmp;

    tmp = *word;
    *word = *(word+1);
    *(word+1) = *(word+2);
    *(word+2) = *(word+3);
    *(word+3) = tmp;
}

static void word_substitute(unsigned char* word)
{
    for(int i = 0; i < WORD_LENGTH; i++)
        *(word+i) = *(*(SBOX+(*(word+i)>>0x04))+(*(word+i)&0x0f));
}

static void key_schedule(unsigned char** words, const unsigned char* pk)
{
    int k_words = (int)strlen(pk) >> 0x02;
    unsigned char rc = 0x01;

    bcopy((void*)pk,(void*)words,strlen(pk));
    for(int i = k_words; i < WORD_LENGTH*(k_words+0x07);i++)
    {
        bcopy((void*)*(words+i),(void*)*(words+i-1),(size_t)WORD_LENGTH);
        if(!(i % k_words))
        {
            word_rotate(*(words+i));
            word_substitute(*(words+i));
            if(!(i % 36))
                rc = 0x1b;

            *(*(words+i)) ^= rc;
            rc <<= 0x01;
        }
        else if((k_words > 0x06) && ((i % k_words) == 0x04))
            word_substitute(*(words+i));

        *(*(words+i)) ^= *(*(words+i-k_words));
        *(*(words+i)+1) ^= *(*(words+i-k_words)+1);
        *(*(words+i)+2) ^= *(*(words+i-k_words)+2);
        *(*(words+i)+3) ^= *(*(words+i-k_words)+3);
    }
}

static void add_round_key(unsigned char** output,unsigned char** input)
{
    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(output+inner)+outer) ^= *(*(input+outer)+inner);
}

static void bytes_substitute(unsigned char** state)
{
    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(state+outer)+inner)=
                *(*(SBOX+((*(*(state+outer)+inner)&0xf0)>>WORD_LENGTH))+
                        (*(*(state+outer)+inner)&0x0f));
}

static void rows_shift(unsigned char** state)
{
    unsigned char tmp = *(*(state+1));
    *(*(state+1)) = *(*(state+1)+1);
    *(*(state+1)+1) = *(*(state+1)+2);
    *(*(state+1)+2) = *(*(state+1)+3);
    *(*(state+1)+3) = tmp;

    tmp = *(*(state+2));
    *(*(state+2)) = *(*(state+2)+2);
    *(*(state+2)+2) = tmp;

    *(*(state+2)+1) = *(*(state+2)+3);
    *(*(state+2)+3) = tmp;

    tmp = *(*(state+3)+3);
    *(*(state+3)+3) = *(*(state+3)+2);
    *(*(state+3)+2) = *(*(state+3)+1);
    *(*(state+3)+1) = *(*(state+3));
    *(*(state+3)) = tmp;
}

static void gf_mul(unsigned char** output,unsigned char** input_1,unsigned char** input_2)
{
    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(output+outer)+inner) = *(*(input_1+outer)) * *(*(input_2)+inner) +
                *(*(input_1+outer)+1) * *(*(input_2+1)+inner) +
                *(*(input_1+outer)+2) * *(*(input_2+2)+inner) +
                *(*(input_1+outer)+3) * *(*(input_2+3)+inner);
}

unsigned char dot_product(unsigned char vector_1, unsigned char vector_2)
{
    unsigned char res = 0;
    for(unsigned char mask = 0x01; mask; mask <<= 0x01)
    {
        if(vector_2 & mask)
            res ^= vector_1;
        vector_1 = (vector_1 << 0x01)^((vector_1 & 0x80)?0x1b:0x00);
    }
    return res;
}

static void columns_mix(unsigned char** state)
{
    unsigned char* tmp;

    for(int i = 0; i < WORD_LENGTH; i++)
    {
        *tmp = dot_product(0x02,*(*(state)+i))^dot_product(0x03,*(*(state+1)+i))^
            *(*(state+2)+i)^*(*(state+3)+i);
        *(tmp+1) = *(*(state)+i)^dot_product(0x02,*(*(state+1)+i))^
            dot_product(0x03,*(*(state+2)+i))^*(*(state+3)+i);
        *(tmp+2) = *(*(state)+i)^*(*(state+1)+i)^dot_product(0x02,*(*(state+2)+i))^
            dot_product(0x03,*(*(state+3)+i));
        *(tmp+3) = dot_product(0x03,*(*(state)+i))^*(*(state+1)+i)^*(*(state+2)+i)^
            dot_product(0x02,*(*(state+3)+i));

        *(*(state)+i) = *tmp;
        *(*(state+1)+i) = *(tmp+1);
        *(*(state+2)+i) = *(tmp+2);
        *(*(state+3)+i) = *(tmp+3);
    }
}

static void rows_shift_inverse(unsigned char** state)
{
    unsigned char tmp = *(*(state+1)+2);
    *(*(state+1)+2) = *(*(state+1)+1);
    *(*(state+1)+1) = *(*(state+1));
    *(*(state+1)) = *(*(state+1)+3);
    *(*(state+1)+3) = tmp;

    tmp = *(*(state+2));
    *(*(state+2)) = *(*(state+2)+2);
    *(*(state+2)+2) = tmp;
    tmp = *(*(state+2)+1);
    *(*(state+2)+1) = *(*(state+2)+3);
    *(*(state+2)+3) = tmp;

    tmp = *(*(state+3));
    *(*(state+3)) = *(*(state+3)+1);
    *(*(state+3)+1) = *(*(state+3)+2);
    *(*(state+3)+2) = *(*(state+3)+3);
    *(*(state+3)+2) = tmp;
}

static void bytes_substitute_inverse(unsigned char** state)
{
    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(state+outer)+inner) = 
                *(*(SBOX_INV+(*(*(state+outer)+inner)&0xf0>>WORD_LENGTH)+
                        (*(*(state+outer)+inner)&0x0f)));
}

static void columns_mix_inverse(unsigned char** state)
{
    unsigned char* tmp;

    for(int i = 0; i < WORD_LENGTH; i++)
    {
        *tmp = dot_product(0x02,*(*(state)+i))^dot_product(0x0b,*(*(state+1)+i))^
            dot_product(0x0d,*(*(state+2)+i))^dot_product(0x09,*(*(state+3)+i));
        *(tmp+1) = dot_product(0x09,*(*(state)+i))^dot_product(0x0e,*(*(state+1)+i))^
            dot_product(0x0b,*(*(state+2)+i))^dot_product(0x0d,*(*(state+3)+i));
        *(tmp+2) = dot_product(0x0d,*(*(state)+i))^dot_product(0x09,*(*(state+1)+i))^
            dot_product(0x0e,*(*(state+2)+i))^dot_product(0x0b,*(*(state+3)+i));
        *(tmp+3) = dot_product(0x0b,*(*(state)+i))^dot_product(0x0d,*(*(state+1)+i))^
                dot_product(0x09,*(*(state+2)+i))^dot_product(0x0e,*(*(state+3)+i));

        *(*(state)+i) = *tmp;
        *(*(state+1)+i) = *(tmp+1);
        *(*(state+2)+i) = *(tmp+2);
        *(*(state+3)+i) = *(tmp+3);
    }
}

static void block_enc(unsigned char* output,const unsigned char* input,const unsigned char* pk)
{
    int round_num;
    unsigned char** state, **words;

    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(state+outer)+inner) = *(input+outer+WORD_LENGTH*inner);

    round_num = ((int)strlen(pk) >> 0x02)+0x06;
    key_schedule(words,pk);
    add_round_key(state,&(*(words)));

    for(int i = 0; i < round_num; i++)
    {
        bytes_substitute(state);
        rows_shift(state);
        if(i < round_num - 1)
            columns_mix(state);

        add_round_key(state,&(*(words+(i+1)*WORD_LENGTH)));
    }

    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(output+outer+inner*WORD_LENGTH) = *(*(state+outer)+inner);
}

static void block_dec(unsigned char* output,const unsigned char* input,const unsigned char* pk)
{
    int round_num;
    unsigned char** state;
    unsigned char** words;

    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(*(state+outer)+inner) = *(input+outer+inner*WORD_LENGTH);

    round_num = ((int)strlen(pk) >> 0x02) + 0x06;
    key_schedule(words,pk);
    add_round_key(state,&(*(words+round_num*WORD_LENGTH)));
    
    for(int i = round_num; i > 0; i--)
    {
        rows_shift_inverse(state);
        bytes_substitute_inverse(state);

        add_round_key(state,&(*(words + (i-1)*WORD_LENGTH)));
        if(i > 1)
            columns_mix_inverse(state);
    }

    for(int outer = 0; outer < WORD_LENGTH; outer++)
        for(int inner = 0; inner < WORD_LENGTH; inner++)
            *(output+outer+inner*WORD_LENGTH) = *(*(state+outer)+inner);
}

static void _xor(unsigned char* output, const unsigned char* input, int len)
{
    while(len--)
        *output++ ^= *input++;
}

static void enc(unsigned char* ciphertext,const unsigned char* plaintext, const unsigned char* iv,
        const unsigned char* pk)
{
    unsigned char buff[BLOCK_SIZE];
    int len = (int)strlen(plaintext);
    while(len>=BLOCK_SIZE)
    {
        bcopy(plaintext,buff,(size_t)BLOCK_SIZE);
        _xor(buff,iv,BLOCK_SIZE);
        block_enc(ciphertext,buff,pk);
        bcopy((void*)ciphertext,(void*)iv,(size_t)BLOCK_SIZE);
        plaintext += BLOCK_SIZE;
        ciphertext += BLOCK_SIZE;
        len -= BLOCK_SIZE;
    }

}

static void dec(unsigned char* output,const unsigned char* input,const unsigned char* iv,
        const unsigned char* pk)
{
    int len = (int)strlen((char*)input);
    while(len>=BLOCK_SIZE)
    {
        block_dec(output,input,pk);
        _xor(output,iv,BLOCK_SIZE);
        bcopy((void*)input,(void*)iv,(size_t)BLOCK_SIZE);
        input += BLOCK_SIZE;
        output += BLOCK_SIZE;
        len -= BLOCK_SIZE;
    }
}

/**
 * It's better to use openssl. We just implement in a very simple way and not securely
 */

static void gen(unsigned char* output,size_t len)
{
    int fd;
    ssize_t data;

    fd = open("/dev/urandom",O_RDONLY,0);
    if(fd == -1)
        fatal_err();

    data = read(fd,(void*)output,len);
    if(data == -1)
        fatal_err();
    else if(data != len)
        err("read");
    
    if(close(fd) == -1)
        fatal_err();
}

void output(const unsigned char* ptr,int len)
{
    while(len--)
        printf("0x%.02X",*ptr++);
    putchar(0xa);        
}

