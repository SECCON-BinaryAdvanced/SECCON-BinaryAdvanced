#include <stdint.h>
#include <stddef.h>
#include "miniimg.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MiniImg *img = miniimg_parse(data, size);
    if (img) { miniimg_invert(img); miniimg_flip_h(img); miniimg_free(img); }
    return 0;
}
