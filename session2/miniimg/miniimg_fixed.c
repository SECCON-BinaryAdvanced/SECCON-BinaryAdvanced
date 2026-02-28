/*
 * miniimg.c - Mini Image Format Parser Library (実装)
 *
 * 注意: この実装には意図的なバグが含まれています。
 *       ファジング演習でバグを発見してください。
 */

#include "miniimg.h"
#include <stdlib.h>
#include <string.h>

MiniImg *miniimg_parse(const uint8_t *data, size_t size)
{
    if (size < sizeof(MiniImgHeader))
        return NULL;

    const MiniImgHeader *hdr = (const MiniImgHeader *)data;

    /* マジックナンバーの検証 */
    if (memcmp(hdr->magic, MINIIMG_MAGIC, 4) != 0)
        return NULL;

    /* 圧縮形式の検証 (非圧縮のみサポート) */
    if (hdr->compression != 0)
        return NULL;

    uint16_t w  = hdr->width;
    uint16_t h  = hdr->height;
    uint8_t  ch = hdr->channels;

    if (w == 0 || h == 0)
        return NULL;

    size_t pixel_size = (size_t)w * h * ch;

    const uint8_t *pixel_data = data + sizeof(MiniImgHeader);
    size_t remaining = size - sizeof(MiniImgHeader);

    /* ピクセルデータの存在だけを確認 (不十分な検証) */
    if (remaining < pixel_size)
        return NULL;

    MiniImg *img = (MiniImg *)malloc(sizeof(MiniImg));
    if (!img)
        return NULL;

    img->width    = w;
    img->height   = h;
    img->channels = ch;
    img->pixels   = (uint8_t *)malloc(pixel_size);
    if (!img->pixels) {
        free(img);
        return NULL;
    }

    /* ピクセルデータのコピー */
    memcpy(img->pixels, pixel_data, pixel_size);

    return img;
}

int miniimg_invert(MiniImg *img)
{
    if (!img || !img->pixels)
        return -1;

    size_t total = (size_t)img->width * img->height * img->channels;
    for (size_t i = 0; i < total; i++)
        img->pixels[i] = 255 - img->pixels[i];

    return 0;
}

int miniimg_flip_h(MiniImg *img)
{
    if (!img || !img->pixels)
        return -1;

    size_t row_size = (size_t)img->width * img->channels;
    uint8_t *tmp = (uint8_t *)malloc(img->channels);
    if (!tmp)
        return -1;

    for (uint16_t y = 0; y < img->height; y++) {
        uint8_t *row = img->pixels + y * row_size;
        for (uint16_t x = 0; x < img->width / 2; x++) {
            uint8_t *left  = row + x * img->channels;
            uint8_t *right = row + (img->width - 1 - x) * img->channels;
            memcpy(tmp, left, img->channels);
            memcpy(left, right, img->channels);
            memcpy(right, tmp, img->channels);
        }
    }

    free(tmp);
    return 0;
}

int miniimg_crop(MiniImg *img, uint16_t x, uint16_t y, uint16_t cw, uint16_t ch)
{
    if (!img || !img->pixels)
        return -1;
    if (cw == 0 || ch == 0)
        return -1;

    /* BUG: x + cw > width, y + ch > height を検証していない */

    size_t new_size = (size_t)cw * ch * img->channels;
    uint8_t *new_pixels = (uint8_t *)malloc(new_size);
    if (!new_pixels)
        return -1;

    size_t src_stride = (size_t)img->width * img->channels;
    size_t dst_stride = (size_t)cw * img->channels;

    for (uint16_t row = 0; row < ch; row++) {
        uint8_t *src = img->pixels + (size_t)(y + row) * src_stride
                       + (size_t)x * img->channels;
        uint8_t *dst = new_pixels + (size_t)row * dst_stride;
        memcpy(dst, src, dst_stride);
    }

    free(img->pixels);
    img->pixels = new_pixels;
    img->width  = cw;
    img->height = ch;

    return 0;
}

int miniimg_compose(MiniImg *base, const MiniImg *overlay,
                    uint16_t ox, uint16_t oy)
{
    if (!base || !base->pixels || !overlay || !overlay->pixels)
        return -1;
    if (base->channels != overlay->channels)
        return -1;

    uint8_t ch = base->channels;

    /* BUG: overlay が base の範囲を超える場合の検証がない */

    for (uint16_t y = 0; y < overlay->height; y++) {
        uint8_t *src = overlay->pixels + (size_t)y * overlay->width * ch;
        uint8_t *dst = base->pixels
                       + (size_t)(oy + y) * base->width * ch
                       + (size_t)ox * ch;
        memcpy(dst, src, (size_t)overlay->width * ch);
    }

    return 0;
}

void miniimg_free(MiniImg *img)
{
    if (img) {
        free(img->pixels);
        free(img);
    }
}
