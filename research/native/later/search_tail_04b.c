#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>
#define R(v,n) (((v)<<(n))|((v)>>(32-(n))))
#define Q(a,b,c,d) x[a]^=R(x[d]+x[c],7);x[b]^=R(x[a]+x[d],9);x[c]^=R(x[b]+x[a],13);x[d]^=R(x[c]+x[b],18)
static void salsa(uint32_t *s,uint8_t *out){uint32_t x[16];memcpy(x,s,64);
for(int j=0;j<10;j++){Q(4,8,12,0);Q(9,13,1,5);Q(14,2,6,10);Q(3,7,11,15);Q(1,2,3,0);Q(6,7,4,5);Q(11,8,9,10);Q(12,13,14,15);}
for(int i=0;i<16;i++){uint32_t v=x[i]+s[i];memcpy(out+4*i,&v,4);}}
int main(int argc,char**argv){
if(argc!=2)return 1;FILE*f=fopen(argv[1],"rb");if(!f)return 2;
uint32_t fl,cov,ml;fread(&fl,4,1,f);fread(&cov,4,1,f);fread(&ml,4,1,f);
uint8_t fei[512],ks[512],cipher[64],magic[64],mask[64];
fread(fei,1,fl,f);fread(ks,1,cov,f);fread(cipher,1,64,f);fread(magic,1,64,f);fread(mask,1,64,f);fclose(f);
int gap=(int)fl-(int)cov;if(gap<1||gap>4||fl>512||cov>512||ml>64)return 3;
uint64_t total=1ULL<<(8*gap);
#pragma omp parallel for schedule(static)
for(uint64_t g=0;g<total;g++){
uint8_t key[64],out[64];uint32_t s[16];int off=fl-64;
for(int j=0;j<64;j++){int i=off+j;key[j]=fei[i]^(i<(int)cov?ks[i]:(uint8_t)(g>>(8*(i-cov))));}
memcpy(s,key,64);salsa(s,out);int ok=1;
for(uint32_t i=0;i<ml;i++){if(mask[i]&&((cipher[i]^out[i])!=magic[i])){ok=0;break;}}
if(ok){
#pragma omp critical
{printf("%llx\n",(unsigned long long)g);fflush(stdout);}}
}return 0;}
