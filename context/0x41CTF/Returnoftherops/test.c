#include <openssl/md5.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void)
{
    MD5_CTX ctx;
    time_t t;
    unsigned char outmd[16];
    char string[5];
    memset(string,0,sizeof(string));
    t = time(0);
    for(int times = 0;times < 90;++times)
    {
        srand(t);
        for (int i = 0;i<4;++i)
        {
            string[i] = rand() % 26 + 97;
        }
        puts("--------");
        puts(string);
        memset(outmd,0,sizeof(outmd));
        MD5_Init(&ctx);
        MD5_Update(&ctx,string,4);
        MD5_Final(outmd,&ctx);
        // puts(outmd);
        for(int j = 0;j<16;++j)
        {
            printf("%02x",outmd[j]);
        }
        printf("\n");
        getchar();
        t ++;
    }
    return 0;
    

}