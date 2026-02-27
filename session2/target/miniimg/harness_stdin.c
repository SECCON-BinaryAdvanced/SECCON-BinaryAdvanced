#include <stdio.h>
#include <stdint.h>
#include "miniimg.h"
int main(void) {
    uint8_t buf[4096];
    size_t len = fread(buf, 1, sizeof(buf), stdin);
    if (len == 0) return 1;
    MiniImg *img = miniimg_parse(buf, len);
    if (img) { miniimg_invert(img); miniimg_flip_h(img); miniimg_free(img); }
    return 0;
}
