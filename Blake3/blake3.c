#include <stdint.h>
#include <string.h>
#include "blake3.h"

#define CHUNK_START (1u << 0)
#define CHUNK_END   (1u << 1)
#define PARENT      (1u << 2)
#define ROOT        (1u << 3)

static void
compress(uint32_t *out, const uint32_t m[16], const uint32_t h[8], uint64_t t, uint32_t b, uint32_t d)
{
	static const unsigned char s[][16] = {
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
		{3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
		{10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
		{12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
		{9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
		{11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
	};
	uint32_t v[16] = {
		h[0], h[1], h[2], h[3],
		h[4], h[5], h[6], h[7],
		iv[0], iv[1], iv[2], iv[3],
		t, t >> 32, b, d,
	};
	unsigned i;

#define G(i, j, a, b, c, d) \
	a = a + b + m[s[i][j * 2]]; \
	d = d ^ a; \
	d = d >> 16 | d << 16; \
	c = c + d; \
	b = b ^ c; \
	b = b >> 12 | b << 20; \
	a = a + b + m[s[i][j * 2 + 1]]; \
	d = d ^ a; \
	d = d >> 8 | d << 24; \
	c = c + d; \
	b = b ^ c; \
	b = b >> 7 | b << 25;

#define ROUND(i) \
	G(i, 0, v[0], v[4], v[8],  v[12]) \
	G(i, 1, v[1], v[5], v[9],  v[13]) \
	G(i, 2, v[2], v[6], v[10], v[14]) \
	G(i, 3, v[3], v[7], v[11], v[15]) \
	G(i, 4, v[0], v[5], v[10], v[15]) \
	G(i, 5, v[1], v[6], v[11], v[12]) \
	G(i, 6, v[2], v[7], v[8],  v[13]) \
	G(i, 7, v[3], v[4], v[9],  v[14])

	ROUND(0) ROUND(1) ROUND(2) ROUND(3)
	ROUND(4) ROUND(5) ROUND(6)

#undef G
#undef ROUND

	if (d & ROOT) {
		for (i = 8; i < 16; ++i)
			out[i] = v[i] ^ h[i - 8];
	}
	for (i = 0; i < 8; ++i)
		out[i] = v[i] ^ v[i + 8];
}

static void
load(uint32_t d[16], const unsigned char s[64]) {
	uint32_t *end;

	for (end = d + 16; d < end; ++d, s += 4) {
		*d = (uint32_t)s[0]       | (uint32_t)s[1] <<  8
		   | (uint32_t)s[2] << 16 | (uint32_t)s[3] << 24;
	}
}

static void
block(struct blake3 *ctx, const unsigned char *buf)
{
	uint32_t m[16], flags, *cv = ctx->cv;
	uint64_t t;

	flags = 0;
	switch (ctx->block) {
	case 0:  flags |= CHUNK_START; break;
	case 15: flags |= CHUNK_END;   break;
	}
	load(m, buf);
	compress(cv, m, cv, ctx->chunk, 64, flags);
	if (++ctx->block == 16) {
		ctx->block = 0;
		for (t = ++ctx->chunk; (t & 1) == 0; t >>= 1) {
			cv -= 8;
			compress(cv, cv, iv, 0, 64, PARENT);
		}
		cv += 8;
		memcpy(cv, iv, sizeof(iv));
	}
	ctx->cv = cv;
}

void
blake3_init(struct blake3 *ctx)
{
	ctx->bytes = 0;
	ctx->block = 0;
	ctx->chunk = 0;
	ctx->cv = ctx->cv_buf;
	memcpy(ctx->cv, iv, sizeof(iv));
}

void
blake3_update(struct blake3 *ctx, const void *buf, size_t len)
{
	const unsigned char *pos = buf;
	size_t n;

	if (ctx->bytes) {
		n = 64 - ctx->bytes;
		if (len < n)
			n = len;
		memcpy(ctx->input + ctx->bytes, pos, n);
		pos += n, len -= n;
		ctx->bytes += n;
		if (!len)
			return;
		block(ctx, ctx->input);
	}
	for (; len > 64; pos += 64, len -= 64)
		block(ctx, pos);
	ctx->bytes = len;
	memcpy(ctx->input, pos, len);
}

void
blake3_out(struct blake3 *ctx, unsigned char *restrict out, size_t len)
{
	uint32_t flags, b, x, *in, *cv, m[16], root[16];
	size_t i;

	cv = ctx->cv;
	memset(ctx->input + ctx->bytes, 0, 64 - ctx->bytes);
	load(m, ctx->input);
	flags = CHUNK_END;
	if (ctx->block == 0)
		flags |= CHUNK_START;
	if (cv == ctx->cv_buf) {
		b = ctx->bytes;
		in = m;
	} else {
		compress(cv, m, cv, ctx->chunk, ctx->bytes, flags);
		flags = PARENT;
		while ((cv -= 8) != ctx->cv_buf)
			compress(cv, cv, iv, 0, 64, flags);
		b = 64;
		in = cv;
		cv = (uint32_t *)iv;
	}
	flags |= ROOT;
	for (i = 0; i < len; ++i, ++out, x >>= 8) {
		if ((i & 63) == 0)
			compress(root, in, cv, i >> 6, b, flags);
		if ((i & 3) == 0)
			x = root[i >> 2 & 15];
		*out = x & 0xff;
	}
}
