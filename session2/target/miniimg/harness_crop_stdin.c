#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "miniimg.h"

int main(void)
{
    uint8_t buf[4096];
    size_t len = fread(buf, 1, sizeof(buf), stdin);

    if (len < sizeof(MiniImgHeader) + 8)
        return 1;

    int img_len = len - 8;
    uint16_t cx, cy, cw, ch;
    memcpy(&cx, buf + img_len,     2);
    memcpy(&cy, buf + img_len + 2, 2);
    memcpy(&cw, buf + img_len + 4, 2);
    memcpy(&ch, buf + img_len + 6, 2);

    MiniImg *img = miniimg_parse(buf, img_len);
    if (img) {
        miniimg_crop(img, cx, cy, cw, ch);
        miniimg_free(img);
    }
    return 0;
}
