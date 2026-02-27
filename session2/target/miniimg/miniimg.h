/*
 * miniimg.h - Mini Image Format Parser Library
 *
 * MIMG形式: 演習用の架空画像フォーマット
 *
 * フォーマット仕様:
 *   [magic: 4byte "MIMG"]
 *   [width: uint16_t LE]
 *   [height: uint16_t LE]
 *   [channels: uint8_t (1=gray, 3=RGB, 4=RGBA)]
 *   [compression: uint8_t (0=none)]
 *   [pixel data: width * height * channels bytes]
 */

#ifndef MINIIMG_H
#define MINIIMG_H

#include <stdint.h>
#include <stddef.h>

#define MINIIMG_MAGIC "MIMG"

typedef struct {
    char     magic[4];       /* "MIMG" */
    uint16_t width;
    uint16_t height;
    uint8_t  channels;       /* 1, 3, or 4 */
    uint8_t  compression;    /* 0 = none */
} MiniImgHeader;

typedef struct {
    uint16_t width;
    uint16_t height;
    uint8_t  channels;
    uint8_t  *pixels;
} MiniImg;

/* バッファからMIMG画像をパースする。失敗時はNULLを返す */
MiniImg *miniimg_parse(const uint8_t *data, size_t size);

/* 画像の色を反転する */
int miniimg_invert(MiniImg *img);

/* 画像を水平方向に反転する */
int miniimg_flip_h(MiniImg *img);

/* 画像をクロップする: (x, y) を起点に w x h の領域を切り出す */
int miniimg_crop(MiniImg *img, uint16_t x, uint16_t y, uint16_t w, uint16_t h);

/* 画像を合成する: base の (ox, oy) 位置に overlay を上書きする */
int miniimg_compose(MiniImg *base, const MiniImg *overlay,
                    uint16_t ox, uint16_t oy);

/* 画像リソースを解放する */
void miniimg_free(MiniImg *img);

#endif /* MINIIMG_H */
