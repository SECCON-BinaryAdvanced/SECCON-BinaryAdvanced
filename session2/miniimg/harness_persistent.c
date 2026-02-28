#include <stdint.h>
#include "miniimg.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < (int)sizeof(MiniImgHeader)) continue;
        MiniImg *img = miniimg_parse(buf, len);
        if (img) { miniimg_invert(img); miniimg_flip_h(img); miniimg_free(img); }
    }
    return 0;
}
