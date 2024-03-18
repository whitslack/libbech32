#define _GNU_SOURCE

#ifdef INCLUDED_FOR_BLECH32
#	define BECH32_CHECKSUM_SIZE BLECH32_CHECKSUM_SIZE
#	define BECH32_HRP_MIN_SIZE BLECH32_HRP_MIN_SIZE
#	define BECH32_MAX_SIZE BLECH32_MAX_SIZE
#	define BECH32_HRP_MAX_SIZE BLECH32_HRP_MAX_SIZE
#	define BECH32_MIN_SIZE BLECH32_MIN_SIZE
#	define WITNESS_PROGRAM_MIN_SIZE BLINDING_PROGRAM_MIN_SIZE
#	define WITNESS_PROGRAM_MAX_SIZE BLINDING_PROGRAM_MAX_SIZE
#	define WITNESS_PROGRAM_PKH_SIZE BLINDING_PROGRAM_PKH_SIZE
#	define WITNESS_PROGRAM_SH_SIZE BLINDING_PROGRAM_SH_SIZE
#	define SEGWIT_ADDRESS_MIN_SIZE BLINDING_ADDRESS_MIN_SIZE
#	define polymod blech32_polymod
#	define polymod_hrp blech32_polymod_hrp
#	define encode blech32_encode
#	define decode blech32_decode
#else
#	ifndef DISABLE_BLECH32
#		define INCLUDED_FOR_BLECH32
#		include "libbech32.c"
#		undef INCLUDED_FOR_BLECH32
#		undef BECH32_H_INCLUDED
#		define DISABLE_BLECH32
#		define BECH32_H_SECOND_PASS
#		define LIBBECH32_C_SECOND_PASS
#	endif
#	undef decode
#	undef encode
#	undef polymod_hrp
#	undef polymod
#	undef SEGWIT_ADDRESS_MIN_SIZE
#	undef WITNESS_PROGRAM_SH_SIZE
#	undef WITNESS_PROGRAM_PKH_SIZE
#	undef WITNESS_PROGRAM_MAX_SIZE
#	undef WITNESS_PROGRAM_MIN_SIZE
#	undef BECH32_MIN_SIZE
#	undef BECH32_HRP_MAX_SIZE
#	undef BECH32_MAX_SIZE
#	undef BECH32_HRP_MIN_SIZE
#	undef BECH32_CHECKSUM_SIZE
#endif

#include "bech32.h"

#ifndef LIBBECH32_C_SECOND_PASS

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define _likely(...) __builtin_expect(!!(__VA_ARGS__), 1)
#define _unlikely(...) __builtin_expect(!!(__VA_ARGS__), 0)

#define _const __attribute__ ((__const__))
#define _pure __attribute__ ((__pure__))

#endif // !defined(LIBBECH32_C_SECOND_PASS)


#ifndef INCLUDED_FOR_BLECH32
static inline bech32_checksum_t _const polymod(bech32_checksum_t chk) {
	static const uint_least32_t LUT[32] = {
#define _(i) ( \
			(((i) & 1 << 0) ? UINT32_C(0x3b6a57b2) : 0) ^ \
			(((i) & 1 << 1) ? UINT32_C(0x26508e6d) : 0) ^ \
			(((i) & 1 << 2) ? UINT32_C(0x1ea119fa) : 0) ^ \
			(((i) & 1 << 3) ? UINT32_C(0x3d4233dd) : 0) ^ \
			(((i) & 1 << 4) ? UINT32_C(0x2a1462b3) : 0))
		_( 0), _( 1), _( 2), _( 3), _( 4), _( 5), _( 6), _( 7), _( 8), _( 9), _(10), _(11), _(12), _(13), _(14), _(15),
		_(16), _(17), _(18), _(19), _(20), _(21), _(22), _(23), _(24), _(25), _(26), _(27), _(28), _(29), _(30), _(31)
#undef _
	};
	return (chk & UINT32_C(0x1FFFFFF)) << 5 ^ LUT[chk >> 25];
}
#else
static inline blech32_checksum_t _const polymod(blech32_checksum_t chk) {
	static const uint_least64_t LUT[32] = {
#define _(i) ( \
			(((i) & 1 << 0) ? UINT64_C(0x7d52fba40bd886) : 0) ^ \
			(((i) & 1 << 1) ? UINT64_C(0x5e8dbf1a03950c) : 0) ^ \
			(((i) & 1 << 2) ? UINT64_C(0x1c3a3c74072a18) : 0) ^ \
			(((i) & 1 << 3) ? UINT64_C(0x385d72fa0e5139) : 0) ^ \
			(((i) & 1 << 4) ? UINT64_C(0x7093e5a608865b) : 0))
		_( 0), _( 1), _( 2), _( 3), _( 4), _( 5), _( 6), _( 7), _( 8), _( 9), _(10), _(11), _(12), _(13), _(14), _(15),
		_(16), _(17), _(18), _(19), _(20), _(21), _(22), _(23), _(24), _(25), _(26), _(27), _(28), _(29), _(30), _(31)
#undef _
	};
	return (chk & UINT64_C(0x7FFFFFFFFFFFFF)) << 5 ^ LUT[chk >> 55];
}
#endif

static inline bech32_checksum_t _pure polymod_hrp(bech32_checksum_t chk, const char *hrp, size_t n_hrp) {
	for (size_t i = 0; i < n_hrp; ++i)
		chk = polymod(chk) ^ (hrp[i] >> 5 | (hrp[i] >= 'A' && hrp[i] <= 'Z'));
	chk = polymod(chk);
	for (size_t i = 0; i < n_hrp; ++i)
		chk = polymod(chk) ^ hrp[i] & 0x1F;
	return chk;
}

#ifndef LIBBECH32_C_SECOND_PASS
// No data-dependent branches! Assumes string contains only character codes 0-127.
static inline bool _pure is_mixed_case(const char *in, size_t n_in) {
#if SIZE_MAX >= UINT64_MAX || defined(__x86_64__/*support x32*/)
	uint_fast64_t flags = 0;
	for (size_t i = 0; i < n_in; ++i)
		flags |= (uint_fast64_t) 1 << (in[i] - 1 >> 1 & 0x3F);
	return (flags & UINT64_C(0x1FFF00000000)) && (flags & UINT64_C(0x1FFF000000000000));
#else
	uint_fast32_t flags = 0;
	for (size_t i = 0; i < n_in; ++i)
		flags |= (uint_fast32_t) in[i] >> 6 << (in[i] - 1 >> 1 & 0x1F);
	return (flags & 0x1FFF) && (flags & UINT32_C(0x1FFF0000));
#endif
}
#endif // !defined(LIBBECH32_C_SECOND_PASS)


size_t bech32_encoded_size(size_t n_hrp, size_t nbits_in, size_t n_pad) {
	size_t n_out;
	if (_unlikely(__builtin_uaddl_overflow(nbits_in, 4, &nbits_in) ||
			__builtin_uaddl_overflow(n_hrp, 1/*separator*/ + nbits_in / 5 + BECH32_CHECKSUM_SIZE, &n_out) ||
			__builtin_uaddl_overflow(n_out, n_pad, &n_out)))
		return SIZE_MAX;
	return n_out;
}

#ifndef LIBBECH32_C_SECOND_PASS
static const char ENCODE[32] = {
	'q', 'p', 'z', 'r', 'y', '9', 'x', '8', 'g', 'f', '2', 't', 'v', 'd', 'w', '0',
	's', '3', 'j', 'n', '5', '4', 'k', 'h', 'c', 'e', '6', 'm', 'u', 'a', '7', 'l'
};
#endif
static void encode(struct bech32_encoder_state *restrict state) {
	while (state->nbits >= 5) {
		bech32_checksum_t v = state->bits >> (state->nbits -= 5) & 0x1F;
		state->chk = polymod(state->chk) ^ v;
		*state->out++ = ENCODE[v], --state->n_out;
	}
}

enum bech32_error bech32_encode_begin(struct bech32_encoder_state *restrict state, char *restrict out, size_t n_out, const char *restrict hrp, size_t n_hrp) {
	if (_unlikely(n_hrp < BECH32_HRP_MIN_SIZE))
		return BECH32_HRP_TOO_SHORT;
	if (_unlikely(n_hrp > BECH32_HRP_MAX_SIZE))
		return BECH32_HRP_TOO_LONG;
	for (size_t i = 0; i < n_hrp; ++i)
		if (_unlikely(hrp[i] < 0x21 || hrp[i] >= 0x7F))
			return BECH32_HRP_ILLEGAL_CHAR;
	if (_unlikely(__builtin_usubl_overflow(n_out, n_hrp, &n_out) || n_out < 1/*separator*/ + BECH32_CHECKSUM_SIZE))
		return BECH32_BUFFER_INADEQUATE;
	for (size_t i = 0; i < n_hrp; ++i)
		out[i] = hrp[i] | (hrp[i] >= 'A' && hrp[i] <= 'Z' ? 0x20 : 0);
	out += n_hrp;
	*out++ = '1', --n_out;
	state->out = out, state->n_out = n_out;
	state->nbits = 0;
	state->chk = polymod_hrp(1, hrp, n_hrp);
	return 0;
}

enum bech32_error bech32_encode_data(struct bech32_encoder_state *restrict state, const unsigned char *restrict in, size_t nbits_in) {
	size_t nbits;
	if (_unlikely(__builtin_uaddl_overflow(state->nbits, nbits_in, &nbits) || state->n_out < nbits / 5))
		return BECH32_BUFFER_INADEQUATE;
	for (ssize_t i = 0;;) {
		encode(state);
		if (nbits_in >= CHAR_BIT)
			state->bits = state->bits << CHAR_BIT | in[i++], state->nbits += CHAR_BIT, nbits_in -= CHAR_BIT;
		else if (nbits_in)
			state->bits = state->bits << nbits_in | in[i++], state->nbits += nbits_in, nbits_in = 0;
		else
			return 0;
	}
}

enum bech32_error bech32_encode_finish(struct bech32_encoder_state *restrict state, bech32_constant_t constant) {
	if (_unlikely(state->n_out < !!state->nbits + BECH32_CHECKSUM_SIZE))
		return BECH32_BUFFER_INADEQUATE;
	if (state->nbits) {
		state->bits <<= 5 - state->nbits, state->nbits = 5;
		encode(state);
	}
	state->bits = state->chk;
	for (size_t i = 0; i < BECH32_CHECKSUM_SIZE; ++i)
		state->bits = polymod(state->bits);
	state->bits ^= constant, state->nbits = BECH32_CHECKSUM_SIZE * 5;
	encode(state);
	if (_unlikely(state->chk != constant))
		return BECH32_CHECKSUM_FAILURE;
	return 0;
}


#ifndef LIBBECH32_C_SECOND_PASS
static const int8_t DECODE['z' - '0' + 1] = {
	15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
	 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
	-1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
	 1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2
};
#endif

static bool decode(struct bech32_decoder_state *restrict state, size_t nbits) {
	while (state->nbits < nbits) {
		int_fast32_t v = (int_fast32_t) *state->in++ - '0'; --state->n_in;
		if (_unlikely(v < 0 || v > 'z' - '0' || (v = DECODE[v]) < 0))
			return false;
		state->chk = polymod(state->chk) ^ v;
		state->bits = state->bits << 5 | v, state->nbits += 5;
	}
	return true;
}

ssize_t bech32_decode_begin(struct bech32_decoder_state *restrict state, const char *restrict in, size_t n_in) {
	if (_unlikely(n_in < BECH32_MIN_SIZE))
		return BECH32_TOO_SHORT;
	if (_unlikely(n_in > BECH32_MAX_SIZE))
		return BECH32_TOO_LONG;
	const char *sep = memrchr(in, '1', n_in);
	if (_unlikely(!sep))
		return BECH32_NO_SEPARATOR;
	size_t n_hrp = sep - in;
	if (_unlikely(n_hrp < BECH32_HRP_MIN_SIZE))
		return BECH32_HRP_TOO_SHORT;
	if (_unlikely(n_hrp > BECH32_HRP_MAX_SIZE))
		return BECH32_HRP_TOO_LONG;
	for (size_t i = 0; i < n_hrp; ++i)
		if (_unlikely(in[i] < 0x21 || in[i] >= 0x7F))
			return BECH32_HRP_ILLEGAL_CHAR;
	for (const char *p = in + n_hrp + 1/*separator*/, *end = in + n_in; p != end;) {
		int_fast32_t v = (int_fast32_t) *p++ - '0';
		if (_unlikely(v < 0 || v > 'z' - '0' || DECODE[v] < 0))
			return BECH32_ILLEGAL_CHAR;
	}
	if (_unlikely(is_mixed_case(in, n_in)))
		return BECH32_MIXED_CASE;
	if (_unlikely(__builtin_usubl_overflow(n_in, n_hrp + 1/*separator*/ + BECH32_CHECKSUM_SIZE, &n_in)))
		return BECH32_TOO_SHORT;
	state->in = in + n_hrp + 1/*separator*/, state->n_in = n_in;
	state->nbits = 0;
	state->chk = polymod_hrp(1, in, n_hrp);
	return n_hrp;
}

enum bech32_error bech32_decode_data(struct bech32_decoder_state *restrict state, unsigned char *restrict out, size_t nbits_out) {
	size_t nbits;
	if (_unlikely(!__builtin_usubl_overflow(nbits_out, state->nbits, &nbits) &&
			(__builtin_uaddl_overflow(nbits, 4, &nbits) || state->n_in < nbits / 5)))
		return BECH32_BUFFER_INADEQUATE;
	for (ssize_t i = 0;;)
		if (_unlikely(!decode(state, nbits_out > CHAR_BIT ? CHAR_BIT : nbits_out)))
			return BECH32_ILLEGAL_CHAR;
		else if (nbits_out >= CHAR_BIT)
			out[i++] = (unsigned char) (state->bits >> state->nbits - CHAR_BIT), state->nbits -= CHAR_BIT, nbits_out -= CHAR_BIT;
		else if (nbits_out)
			out[i++] = (unsigned char) (state->bits >> state->nbits - nbits_out & (1 << nbits_out) - 1), state->nbits -= nbits_out, nbits_out = 0;
		else
			return 0;
}

ssize_t bech32_decode_finish(struct bech32_decoder_state *restrict state, bech32_constant_t constant) {
	ssize_t nbits_pad = state->nbits;
	if (_unlikely(state->n_in || nbits_pad && (state->bits & (1 << nbits_pad) - 1)))
		return BECH32_PADDING_ERROR;
	state->n_in = BECH32_CHECKSUM_SIZE, state->nbits = 0;
	if (_unlikely(!decode(state, BECH32_CHECKSUM_SIZE * 5)))
		return BECH32_ILLEGAL_CHAR;
	state->nbits = 0;
	if (_unlikely(state->chk != constant || state->n_in))
		return BECH32_CHECKSUM_FAILURE;
	return nbits_pad;
}


ssize_t bech32_address_encode(char *restrict address, size_t n_address, const unsigned char *restrict program, size_t n_program, const char *restrict hrp, size_t n_hrp, unsigned version) {
	if (_unlikely(n_program < WITNESS_PROGRAM_MIN_SIZE))
		return SEGWIT_PROGRAM_TOO_SHORT;
	if (_unlikely(n_program > WITNESS_PROGRAM_MAX_SIZE))
		return SEGWIT_PROGRAM_TOO_LONG;
	if (_unlikely(version > WITNESS_MAX_VERSION))
		return SEGWIT_VERSION_ILLEGAL;
	if (version == 0 && _unlikely(!(n_program == WITNESS_PROGRAM_PKH_SIZE || n_program == WITNESS_PROGRAM_SH_SIZE)))
		return SEGWIT_PROGRAM_ILLEGAL_SIZE;
	size_t n_actual = n_hrp + 1/*separator*/ + 1/*version*/ + (n_program * CHAR_BIT + 4) / 5 + BECH32_CHECKSUM_SIZE;
	if (_unlikely(n_address < n_actual + 1/*null terminator*/))
		return BECH32_BUFFER_INADEQUATE;
	enum bech32_error error;
	struct bech32_encoder_state state;
	uint8_t ver = (uint8_t) version;
	if (_unlikely((error = bech32_encode_begin(&state, address, n_address, hrp, n_hrp)) < 0 ||
			(error = bech32_encode_data(&state, &ver, 5)) < 0 ||
			(error = bech32_encode_data(&state, program, n_program * CHAR_BIT)) < 0 ||
			(error = bech32_encode_finish(&state, version == 0 ? 1 : BECH32M_CONST)) < 0))
		return error;
	address[n_actual] = '\0';
	return (ssize_t) n_actual;
}

ssize_t bech32_address_decode(unsigned char *restrict program, size_t n_program, const char *restrict address, size_t n_address, size_t *restrict n_hrp, unsigned *restrict version) {
	if (_unlikely(n_address < SEGWIT_ADDRESS_MIN_SIZE))
		return BECH32_TOO_SHORT;
	ssize_t ret;
	struct bech32_decoder_state state;
	if (_unlikely((ret = bech32_decode_begin(&state, address, n_address)) < 0))
		return ret;
	size_t n_actual = (n_address - ret/*hrp*/ - 1/*separator*/ - 1/*version*/ - BECH32_CHECKSUM_SIZE) * 5 / CHAR_BIT;
	if (_unlikely(n_actual < WITNESS_PROGRAM_MIN_SIZE))
		return SEGWIT_PROGRAM_TOO_SHORT;
	if (_unlikely(n_actual > WITNESS_PROGRAM_MAX_SIZE))
		return SEGWIT_PROGRAM_TOO_LONG;
	if (_unlikely(n_program < n_actual))
		return BECH32_BUFFER_INADEQUATE;
	*n_hrp = (size_t) ret;
	uint8_t ver;
	if (_unlikely((ret = bech32_decode_data(&state, &ver, 5)) < 0))
		return ret;
	if (_unlikely(ver > WITNESS_MAX_VERSION))
		return SEGWIT_VERSION_ILLEGAL;
	else if (ver == 0 && _unlikely(!(n_actual == WITNESS_PROGRAM_PKH_SIZE || n_actual == WITNESS_PROGRAM_SH_SIZE)))
		return SEGWIT_PROGRAM_ILLEGAL_SIZE;
	*version = ver;
	if (_unlikely((ret = bech32_decode_data(&state, program, n_actual * CHAR_BIT)) < 0 ||
			(ret = bech32_decode_finish(&state, ver == 0 ? 1 : BECH32M_CONST)) < 0))
		return ret;
	return n_actual;
}


#ifndef LIBBECH32_C_SECOND_PASS
// define weak aliases for ABI backward compatibility
ssize_t segwit_address_encode(char *restrict, size_t, const unsigned char *restrict, size_t, const char *restrict, size_t, unsigned)
	__attribute__ ((__weak__, __alias__ ("bech32_address_encode")));
ssize_t segwit_address_decode(unsigned char *restrict, size_t, const char *restrict, size_t, size_t *restrict, unsigned *restrict)
	__attribute__ ((__weak__, __alias__ ("bech32_address_decode")));
#endif
