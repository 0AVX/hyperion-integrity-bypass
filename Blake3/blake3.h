#ifndef BLAKE3_H
#define BLAKE3_H 1

#include <stdint.h>

struct blake3 {
	unsigned char input[64];      /* current input bytes */
	unsigned bytes;               /* bytes in current input block */
	unsigned block;               /* block index in chunk */
	uint64_t chunk;               /* chunk index */
	uint32_t *cv, cv_buf[54 * 8]; /* chain value stack */
};

void blake3_init(struct blake3 *);
void blake3_update(struct blake3 *, const void *, size_t);
void blake3_out(struct blake3 *, unsigned char *restrict, size_t);

static const uint32_t iv[] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

#endif
