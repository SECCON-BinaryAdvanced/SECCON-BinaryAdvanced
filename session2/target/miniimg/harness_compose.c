#include <stdint.h>
#include <string.h>
#include "miniimg.h"
__AFL_FUZZ_INIT();
int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        if (len < 6 + (int)sizeof(MiniImgHeader) * 2) continue;
        uint16_t split, ox, oy;
        memcpy(&split, buf, 2); memcpy(&ox, buf + 2, 2); memcpy(&oy, buf + 4, 2);
        const uint8_t *data = buf + 6;
        int data_len = len - 6;
        if (split >= (uint16_t)data_len) split = data_len / 2;
        if (split < sizeof(MiniImgHeader)) split = sizeof(MiniImgHeader);
        MiniImg *base = miniimg_parse(data, split);
        MiniImg *overlay = miniimg_parse(data + split, data_len - split);
        if (base && overlay) miniimg_compose(base, overlay, ox, oy);
        if (base) miniimg_free(base);
        if (overlay) miniimg_free(overlay);
    }
    return 0;
}
