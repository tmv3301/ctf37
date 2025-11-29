#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>

static volatile uint32_t key_table_enc[8] = {
    0x7B081B4Au,
    0xA7655A4Bu,
    0x1F0855A8u,
    0x7B08657Bu,
    0x655A4BA5u,
    0xB692657Bu,
    0x657B657Bu,
    0x5B485F6Bu
};

static volatile uint32_t dummy_sink;

static uint32_t get_segment_value(int seg) {
    static unsigned char dec_idx[4];
    static int init = 0;
    static const unsigned char raw[4] = { 0x7B, 0x79, 0x7F, 0x7D };

    if (!init) {
        for (int i = 0; i < 4; i++) {
            dec_idx[i] = (unsigned char)(raw[i] ^ 0x7A);
        }
        init = 1;
    }

    uint32_t mask = 0xA5A5A5A5u;
    uint32_t enc = key_table_enc[ dec_idx[seg] & 7 ];
    return enc ^ mask;
}

volatile uint32_t num1 = 0x13572468u;
volatile uint32_t num2 = 0x11111111u;
volatile uint32_t num3 = 0x22222222u;
volatile uint32_t num4 = 0xCAFEBABEu;

static uint32_t f_ae04(void) {
    uint32_t a = get_segment_value(0);
    uint32_t b = get_segment_value(1);
    uint32_t c = get_segment_value(2);
    uint32_t d = get_segment_value(3);

    uint32_t s1 = ((a + b ^ num1)) ^ 0xD9A99ED6u;
    uint32_t t2 = (c + num2) + (d + num3);
    uint32_t s2 = t2 - 0x33333333u;

    uint32_t u1 = s1;
    uint32_t u2 = s2 ^ num4;
    return u1 ^ u2;
}

static uint32_t f_93bd(void) {
    const uint32_t mask = 0xA5A5A5A5u;
    uint32_t k0 = key_table_enc[0] ^ mask;
    uint32_t k2 = key_table_enc[2] ^ mask;
    return (k0 ^ k2) + 0x12345678u;
}

static uint32_t f_5c29(void) {
    const uint32_t mask = 0xA5A5A5A5u;
    uint32_t k1 = key_table_enc[1] ^ mask;
    uint32_t k7 = key_table_enc[7] ^ mask;

    uint32_t t = (k1 ^ 0xAAAAAAAAu) + (k7 ^ 0x55555555u);
    return ((t << 7) | (t >> 25)) ^ 0xDEADBEEFu;
}

static uint32_t (*rtx_lut[])(void) = {
    f_93bd,
    f_5c29,
    f_ae04
};

static void xor_block(char *dst, const unsigned char *src,
                      size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)(src[i] ^ key);
    }
}

static unsigned char s_a_enc[] = {
    'h'^0x37,'i'^0x37,'d'^0x37,'d'^0x37,'e'^0x37,'n'^0x37,'_'^0x37,
    'p'^0x37,'a'^0x37,'s'^0x37,'s'^0x37,'w'^0x37,'o'^0x37,'r'^0x37,'d'^0x37,
    '\0'^0x37
};

static char *get_a_token(void) {
    static char buf[sizeof(s_a_enc)];
    static int ok = 0;
    if (!ok) {
        xor_block(buf, s_a_enc, sizeof(s_a_enc), 0x37);
        ok = 1;
    }
    return buf;
}

static unsigned char s_b_enc[] = {
    'c'^0x5A,'o'^0x5A,'u'^0x5A,'r'^0x5A,'s'^0x5A,'e'^0x5A,'_'^0x5A,
    't'^0x5A,'h'^0x5A,'i'^0x5A,'r'^0x5A,'t'^0x5A,'y'^0x5A,'_'^0x5A,
    's'^0x5A,'e'^0x5A,'v'^0x5A,'e'^0x5A,'n'^0x5A,
    '\0'^0x5A
};

static char *get_b_token(void) {
    static char buf[sizeof(s_b_enc)];
    static int ok = 0;
    if (!ok) {
        xor_block(buf, s_b_enc, sizeof(s_b_enc), 0x5A);
        ok = 1;
    }
    return buf;
}

static unsigned char s_c_enc[] = {
    'd'^0x13,'e'^0x13,'p'^0x13,'t'^0x13,'_'^0x13,
    'o'^0x13,'f'^0x13,'_'^0x13,'c'^0x13,'y'^0x13,
    'b'^0x13,'e'^0x13,'r'^0x13,'_'^0x13,'d'^0x13,
    'f'^0x13,
    '\0'^0x13
};

static char *get_c_token(void) {
    static char buf[sizeof(s_c_enc)];
    static int ok = 0;
    if (!ok) {
        xor_block(buf, s_c_enc, sizeof(s_c_enc), 0x13);
        ok = 1;
    }
    return buf;
}

static int detect_debugger(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        return 1;
    }
    raise(SIGSTOP);
    return 0;
}

static const uint32_t g0 = 0xA17F23C4u;
static const uint32_t g1 = 0x5E2AC9D1u;
static const uint32_t g2 = 0x9B008173u;

static const unsigned char d_enc[] = {
    0x66,0xFD,0x20,0x94,0x6C,0xCD,0x27,0x9F,0x64,
    0xE4,0x0D,0x82,0x68,0xF1,0x27,0x83,0x64,0xE6,0x2B
};

static int stage_a(void) {
    char buf[64];

    printf("[A] Key: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;

    if (strcmp(buf, get_a_token()) == 0) {
        printf("%08X\n", get_segment_value(0));
        return 0;
    }
    puts("denied");
    return 1;
}

static int stage_b(void) {
    char buf[64];

    printf("[B] Key: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;

    if (strcmp(buf, get_b_token()) == 0) {
        printf("%08X\n", get_segment_value(1));
        return 0;
    }
    puts("denied");
    return 1;
}

static int stage_c(void) {
    if (detect_debugger()) {
        puts("debugger detected");
        return 1;
    }

    char buf[64];

    printf("[C] Key: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;

    if (strcmp(buf, get_c_token()) == 0) {
        printf("%08X\n", get_segment_value(2));
        return 0;
    }
    puts("denied");
    return 1;
}

static int stage_d(void) {
    char buf[64];

    printf("[D] Key: ");
    if (!fgets(buf, sizeof(buf), stdin)) return 1;
    buf[strcspn(buf, "\n")] = 0;

    size_t len = strlen(buf);
    if (len != sizeof(d_enc)) {
        puts("denied");
        return 1;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)buf[i];
        uint32_t m = ((g0 >> (8 * (i % 4))) ^
                      (g1 >> (8 * ((i + 1) % 4))) ^
                      (g2 >> (8 * ((i + 2) % 4)))) & 0xFFu;

        if ((unsigned char)(ch ^ m) != d_enc[i]) {
            puts("denied");
            return 1;
        }
    }

    printf("%08X\n", get_segment_value(3));
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        puts("usage: ./problem [1|2|3|4]");
        return 1;
    }

    dummy_sink ^= rtx_lut[0]();
    dummy_sink ^= rtx_lut[1]();
    dummy_sink ^= rtx_lut[2]();

    int mode = atoi(argv[1]);

    switch (mode) {
        case 1: return stage_a();
        case 2: return stage_b();
        case 3: return stage_c();
        case 4: return stage_d();
        default:
            puts("Invalid mode");
            return 1;
    }
}
