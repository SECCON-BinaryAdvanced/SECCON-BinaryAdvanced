#include <stdint.h>
#include <string.h>
#include "miniimg.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < (int)sizeof(MiniImgHeader) + 8) continue;
        int img_len = len - 8;
        uint16_t cx, cy, cw, ch;
        memcpy(&cx, buf + img_len, 2); memcpy(&cy, buf + img_len + 2, 2);
        memcpy(&cw, buf + img_len + 4, 2); memcpy(&ch, buf + img_len + 6, 2);
        MiniImg *img = miniimg_parse(buf, img_len);
        if (img) { miniimg_crop(img, cx, cy, cw, ch); miniimg_free(img); }
    }
    return 0;
}
