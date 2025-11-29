#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

static const uint32_t key_table[8] = {
    0xDEADBEEFu,
    0x02C0FFEEu,
    0xBAADF00Du,
    0xDEADC0DEu,
    0xC0FFEE00u,
    0x1337C0DEu,
    0xC0DEC0DEu,
    0xFEEDFACEu
};

static void xor_block(char *dst, const unsigned char *src, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) dst[i] = (char)(src[i] ^ key);
}

static volatile uint32_t dummy_sink;

static uint32_t get_segment_value(int seg) {
    static unsigned char dec_idx[4];
    static int init = 0;
    static const unsigned char raw[4] = { 0x7B,0x79,0x7F,0x7D };
    if (!init) {
        for (int i = 0; i < 4; i++) dec_idx[i] = raw[i] ^ 0x7A;
        init = 1;
    }
    return key_table[ dec_idx[seg] & 7 ];
}

static uint32_t f_ae04(void) {
    uint32_t a = get_segment_value(0);
    uint32_t b = get_segment_value(1);
    uint32_t c = get_segment_value(2);
    uint32_t d = get_segment_value(3);

    uint32_t s1 = ((a + b ^ 0x13572468u)) ^ 0xD9A99ED6u;
    uint32_t t2 = (c + 0x11111111u) + (d + 0x22222222u);
    uint32_t s2 = t2 - 0x33333333u;

    uint32_t u1 = s1;
    uint32_t u2 = s2 ^ 0xCAFEBABEu;
    return u1 ^ u2;
}

static uint32_t f_93bd(void){
    return (key_table[0]^key_table[2]) + 0x12345678u;
}

static uint32_t f_5c29(void){
    uint32_t t=(key_table[1]^0xAAAAAAAAu)+(key_table[7]^0x55555555u);
    return ((t<<7)|(t>>(25)))^0xDEADBEEFu;
}

static uint32_t (*rtx_lut[])(void) = {
    f_93bd,
    f_5c29,
    f_ae04
};

static unsigned char s_a_enc[]={
 'h'^0x37,'i'^0x37,'d'^0x37,'d'^0x37,'e'^0x37,'n'^0x37,'_'^0x37,
 'p'^0x37,'a'^0x37,'s'^0x37,'s'^0x37,'w'^0x37,'o'^0x37,'r'^0x37,'d'^0x37,
 '\0'^0x37
};
static char *get_a_token(void){
    static char buf[sizeof(s_a_enc)];
    static int ok=0;
    if(!ok){ xor_block(buf,s_a_enc,sizeof(s_a_enc),0x37); ok=1; }
    return buf;
}

static unsigned char s_b_enc[]={
 's'^0x5A,'u'^0x5A,'b'^0x5A,'j'^0x5A,'e'^0x5A,'c'^0x5A,'t'^0x5A,'_'^0x5A,
 't'^0x5A,'h'^0x5A,'i'^0x5A,'r'^0x5A,'t'^0x5A,'y'^0x5A,'_'^0x5A,
 's'^0x5A,'e'^0x5A,'v'^0x5A,'e'^0x5A,'n'^0x5A,'\0'^0x5A
};
static char *get_b_token(void){
    static char buf[sizeof(s_b_enc)];
    static int ok=0;
    if(!ok){ xor_block(buf,s_b_enc,sizeof(s_b_enc),0x5A); ok=1; }
    return buf;
}

static unsigned char s_c_enc[]={
 'd'^0x13,'e'^0x13,'p'^0x13,'t'^0x13,'_'^0x13,
 'o'^0x13,'f'^0x13,'_'^0x13,'c'^0x13,'y'^0x13,
 'b'^0x13,'e'^0x13,'r'^0x13,'_'^0x13,'d'^0x13,
 'f'^0x13,'\0'^0x13
};
static char *get_c_token(void){
    static char buf[sizeof(s_c_enc)];
    static int ok=0;
    if(!ok){ xor_block(buf,s_c_enc,sizeof(s_c_enc),0x13); ok=1; }
    return buf;
}

static int detect_debugger(void){
    if(ptrace(PTRACE_TRACEME,0,0,0)==-1) return 1;
    raise(SIGSTOP);
    return 0;
}

static int stage_a(void){
    char buf[64];
    printf("[A] Key: ");
    if(!fgets(buf,64,stdin)) return 1;
    buf[strcspn(buf,"\n")]=0;

    if(strcmp(buf,get_a_token())==0){
        printf("%08X\n", get_segment_value(0));
        return 0;
    }
    puts("denied");
    return 1;
}

static int stage_b(void){
    char buf[64];
    printf("[B] Key: ");
    if(!fgets(buf,64,stdin)) return 1;
    buf[strcspn(buf,"\n")]=0;

    if(strcmp(buf,get_b_token())==0){
        printf("%08X\n", get_segment_value(1));
        return 0;
    }
    puts("denied");
    return 1;
}

static int stage_c(void){
    if(detect_debugger()){
        puts("debugger detected");
        return 1;
    }
    char buf[64];
    printf("[C] Key: ");
    if(!fgets(buf,64,stdin)) return 1;
    buf[strcspn(buf,"\n")]=0;

    if(strcmp(buf,get_c_token())==0){
        printf("%08X\n", get_segment_value(2));
        return 0;
    }
    puts("denied");
    return 1;
}


static uint32_t hash_d(const char *s) {
    uint32_t h = 0x1234ABCDu;
    while (*s) {
        unsigned char ch = (unsigned char)*s++;
        h ^= ch;
        h = (h << 5) | (h >> 27);
        h += 0x9E3779B9u;
    }
    return h;
}

static int stage_d(void){
    char buf[64];
    printf("[D] Key: ");
    if(!fgets(buf,sizeof(buf),stdin)) return 1;
    buf[strcspn(buf,"\n")] = 0;

    if (hash_d(buf) == 0x38E7C41Cu) {
        printf("%08X\n", get_segment_value(3));
        return 0;
    }
    puts("denied");
    return 1;
}

int main(int argc,char *argv[]){
    if(argc < 2){
        puts("usage: ./problem [1|2|3|4]");
        return 1;
    }

    dummy_sink ^= f_93bd();
    dummy_sink ^= f_5c29();
    dummy_sink ^= f_ae04();

    int mode = atoi(argv[1]);

    switch(mode){
        case 1: return stage_a();
        case 2: return stage_b();
        case 3: return stage_c();
        case 4: return stage_d();
        default:
            puts("Invalid mode");
            return 1;
    }
}
