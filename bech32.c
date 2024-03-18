#define _GNU_SOURCE

#include "bech32.h"

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>


static void print_usage() {
	const char *implied = strcmp(program_invocation_short_name, "bech32m") == 0 ? "Bech32m" : NULL;
#ifndef DISABLE_BLECH32
	if (!implied)
		if (strcmp(program_invocation_short_name, "blech32") == 0)
			implied = "Blech32";
		else if (strcmp(program_invocation_short_name, "blech32m") == 0)
			implied = "Blech32m";
#endif
	fprintf(stderr, "usage: %1$s [-h]%2$s <hrp> { [<version>] | -d [-v|<version>] }\n\n"
		"Reads data from stdin and writes its %3$s encoding to stdout. If <version>\n"
		"is given, its least significant 5 bits are encoded as a SegWit version field.\n\n"
		"-d,--decode\n"
		"    Decode a %3$s encoding from stdin and write the data to stdout. If\n"
		"    <version> is given, assert that it matches the version field in the data.\n"
		"-h,--hex\n"
		"    Use hexadecimal for data input/output.\n"
		"%4$s"
#ifndef DISABLE_BLECH32
		"%5$s"
#endif
		"-v,--exit-version\n"
		"    Extract a 5-bit SegWit version field and return it as the exit status.\n",
		program_invocation_short_name,
		implied ? "" :
#ifndef DISABLE_BLECH32
			" [-l]"
#endif
			" [-m]",
		implied ?: "Bech32",
#ifndef DISABLE_BLECH32
		implied ? "" :
			"-l,--blech\n"
			"    Use Blech32/Blech32m instead of Bech32/Bech32m. Implied if invoked as\n"
			"    'blech32' or 'blech32m'.\n",
#endif
		implied ? "" :
			"-m,--modified\n"
#ifdef DISABLE_BLECH32
			"    Use Bech32m instead of Bech32. Implied if invoked as 'bech32m'.\n"
#else
			"    Use Bech32m/Blech32m instead of Bech32/Blech32. Implied if invoked as\n"
			"    'bech32m' or 'blech32m'.\n"
#endif
	);
}

static int gethex() {
	static const int8_t DECODE['f' + 1 - '0'] = {
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
		-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, 10, 11, 12, 13, 14, 15
	};
	int hi, lo;
	if ((hi = getchar()) < 0)
		return hi;
	if ((hi -= '0') >= 0 && hi <= 'f' - '0' && (hi = DECODE[hi]) >= 0) {
		if ((lo = getchar()) >= 0 && (lo -= '0') >= 0 && lo <= 'f' - '0' && (lo = DECODE[lo]) >= 0)
			return hi << 4 | lo;
	}
	else if (hi == '\n' - '0')
		return EOF;
	errx(EX_DATAERR, "invalid hex on stdin");
}

static ssize_t fwrite_hex(const unsigned char in[], size_t n_in, FILE *out) {
	static const char ENCODE[16] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	for (size_t i = 0; i < n_in; ++i) {
		char x[2] = { ENCODE[in[i] >> 4], ENCODE[in[i] & 0xF] };
		if (fwrite(x, 1, 2, out) < 2)
			return -1;
	}
	return putc('\n', out) < 0 ? -1 : (ssize_t) n_in;
}

static const char *errmsg(enum bech32_error error) {
	switch (error) {
		case BECH32_TOO_SHORT:
			return "input is too short";
		case BECH32_TOO_LONG:
			return "input is too long";
		case BECH32_NO_SEPARATOR:
			return "no separator found";
		case BECH32_MIXED_CASE:
			return "input uses mixed case";
		case BECH32_ILLEGAL_CHAR:
			return "illegal character";
		case BECH32_PADDING_ERROR:
			return "padding error";
		case BECH32_CHECKSUM_FAILURE:
			return "checksum verification failed";
		case BECH32_HRP_TOO_SHORT:
			return "human-readable prefix is empty";
		case BECH32_HRP_TOO_LONG:
			return "human-readable prefix is too long";
		case BECH32_HRP_ILLEGAL_CHAR:
			return "invalid human-readable prefix";
		case BECH32_BUFFER_INADEQUATE:
		case SEGWIT_VERSION_ILLEGAL:
		case SEGWIT_PROGRAM_TOO_SHORT:
		case SEGWIT_PROGRAM_TOO_LONG:
		case SEGWIT_PROGRAM_ILLEGAL_SIZE:
			break;
	}
	__builtin_unreachable();
}

int main(int argc, char *argv[]) {
	static const struct option longopts[] = {
		{ .name = "decode", .has_arg = no_argument, .val = 'd' },
		{ .name = "hex", .has_arg = no_argument, .val = 'h' },
#ifndef DISABLE_BLECH32
		{ .name = "blech", .has_arg = no_argument, .val = 'l' },
#endif
		{ .name = "modified", .has_arg = no_argument, .val = 'm' },
		{ .name = "bech32m", .has_arg = no_argument, .val = 3 }, // retained for backward compatibility
		{ .name = "exit-version", .has_arg = no_argument, .val = 'v' },
		{ .name = "help", .has_arg = no_argument, .val = 1 },
		{ .name = "version", .has_arg = no_argument, .val = 2 },
		{ }
	};
	bool modified = strcmp(program_invocation_short_name, "bech32m") == 0;
	bool implied = modified, decode = false, hex = false, exit_version = false;
#ifndef DISABLE_BLECH32
	int blech = 0;
	if (!implied)
		if (strcmp(program_invocation_short_name, "blech32") == 0)
			implied = true, blech = 1;
		else if (strcmp(program_invocation_short_name, "blech32m") == 0)
			implied = true, modified = true, blech = 1;
#endif
	for (int opt; (opt = getopt_long(argc, argv, "dh"
#ifndef DISABLE_BLECH32
			"l"
#endif
			"mv", longopts, NULL)) >= 0;)
		switch (opt) {
			case 1:
				print_usage();
				return EX_OK;
			case 2:
				printf("bech32 %s\n", VERSION);
				return EX_OK;
			case 'd':
				decode = true;
				break;
			case 'h':
				hex = true;
				break;
#ifndef DISABLE_BLECH32
			case 'l':
				if (implied || blech < 0)
					goto usage_error;
				blech = 1;
				break;
#endif
			case 3:
#ifndef DISABLE_BLECH32
				if (blech > 0)
					goto usage_error;
				blech = -1;
				// fall through
#endif
			case 'm':
				if (implied)
					goto usage_error;
				modified = true;
				break;
			case 'v':
				exit_version = true;
				break;
			default:
			usage_error:
				print_usage();
				return EX_USAGE;
		}
	if ((decode ? argc - optind > 1 + !exit_version : argc - optind > 2 || exit_version) || optind >= argc)
		return print_usage(), EX_USAGE;
	const char *const hrp = argv[optind++];
	size_t n_hrp = strlen(hrp), nmin_hrp, nmax_hrp;
#ifndef DISABLE_BLECH32
	if (blech > 0)
		nmin_hrp = BLECH32_HRP_MIN_SIZE, nmax_hrp = BLECH32_HRP_MAX_SIZE;
	else
#endif
		nmin_hrp = BECH32_HRP_MIN_SIZE, nmax_hrp = BECH32_HRP_MAX_SIZE;
	if (n_hrp < nmin_hrp)
		errx(EX_USAGE, errmsg(BECH32_HRP_TOO_SHORT));
	if (n_hrp > nmax_hrp)
		errx(EX_USAGE, errmsg(BECH32_HRP_TOO_LONG));
	int8_t version = optind < argc ? (int8_t) atoi(argv[optind++]) : -1;

	size_t n_in = 0, nmax_in;
#ifndef DISABLE_BLECH32
	if (blech > 0)
		nmax_in = decode ? BLECH32_MAX_SIZE :
				(BLECH32_MAX_SIZE - n_hrp - 1/*separator*/ - (version >= 0) - BLECH32_CHECKSUM_SIZE) * 5 / CHAR_BIT;
	else
#endif
		nmax_in = decode ? BECH32_MAX_SIZE :
				(BECH32_MAX_SIZE - n_hrp - 1/*separator*/ - (version >= 0) - BECH32_CHECKSUM_SIZE) * 5 / CHAR_BIT;
	unsigned char in[nmax_in];
	if (decode || hex) {
		for (int c;;) {
			if (decode ? (c = getchar()) < 0 || c == '\n' : (c = gethex()) < 0) {
				if (ferror(stdin))
					err(EX_IOERR, "error reading from stdin");
				break;
			}
			if (n_in == nmax_in)
				errx(EX_DATAERR, errmsg(BECH32_TOO_LONG));
			in[n_in++] = (unsigned char) c;
		}
	}
	else {
		n_in = fread(in, 1, nmax_in, stdin);
		if (ferror(stdin))
			err(EX_IOERR, "error reading from stdin");
		if (!feof(stdin) && getchar() >= 0)
			errx(EX_DATAERR, errmsg(BECH32_TOO_LONG));
	}

	size_t n_out = 0, nmax_out;
#ifndef DISABLE_BLECH32
	if (blech > 0)
		nmax_out = BLECH32_MAX_SIZE + 1/*'\n'*/;
	else
#endif
		nmax_out = BECH32_MAX_SIZE + 1/*'\n'*/;
	unsigned char out[nmax_out];
	if (decode) {
#ifndef DISABLE_BLECH32
		if (blech > 0) {
			if (n_in < BLECH32_MIN_SIZE)
				errx(EX_DATAERR, errmsg(BECH32_TOO_SHORT));
			ssize_t ret;
			struct blech32_decoder_state state;
			if ((ret = blech32_decode_begin(&state, (const char *) in, n_in)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
			if ((size_t) ret != n_hrp || strncasecmp((const char *) in, hrp, ret))
				errx(EX_DATAERR, "human-readable prefix was \"%.*s\", not \"%s\"", (int) ret, in, hrp);
			if (version >= 0 || exit_version) {
				if (blech32_decode_bits_remaining(&state) < 5)
					errx(EX_DATAERR, errmsg(BECH32_TOO_SHORT));
				int8_t expected_version = version;
				if ((ret = blech32_decode_data(&state, (unsigned char *) &version, 5)) < 0)
					errx(EX_DATAERR, errmsg((enum bech32_error) ret));
				if (expected_version >= 0 && version != expected_version)
					errx(EX_DATAERR, "version was %d, not %d", version, expected_version);
			}
			n_out = blech32_decode_bits_remaining(&state) / CHAR_BIT;
			assert(n_out <= nmax_out);
			if ((ret = blech32_decode_data(&state, out, n_out * CHAR_BIT)) < 0 ||
					(ret = blech32_decode_finish(&state, modified ? BLECH32M_CONST : 1)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
		}
		else
#endif
		{
			if (n_in < BECH32_MIN_SIZE)
				errx(EX_DATAERR, errmsg(BECH32_TOO_SHORT));
			ssize_t ret;
			struct bech32_decoder_state state;
			if ((ret = bech32_decode_begin(&state, (const char *) in, n_in)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
			if ((size_t) ret != n_hrp || strncasecmp((const char *) in, hrp, ret))
				errx(EX_DATAERR, "human-readable prefix was \"%.*s\", not \"%s\"", (int) ret, in, hrp);
			if (version >= 0 || exit_version) {
				if (bech32_decode_bits_remaining(&state) < 5)
					errx(EX_DATAERR, errmsg(BECH32_TOO_SHORT));
				int8_t expected_version = version;
				if ((ret = bech32_decode_data(&state, (unsigned char *) &version, 5)) < 0)
					errx(EX_DATAERR, errmsg((enum bech32_error) ret));
				if (expected_version >= 0 && version != expected_version)
					errx(EX_DATAERR, "version was %d, not %d", version, expected_version);
			}
			n_out = bech32_decode_bits_remaining(&state) / CHAR_BIT;
			assert(n_out <= nmax_out);
			if ((ret = bech32_decode_data(&state, out, n_out * CHAR_BIT)) < 0 ||
					(ret = bech32_decode_finish(&state, modified ? BECH32M_CONST : 1)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
		}
	}
	else {
#ifndef DISABLE_BLECH32
		if (blech > 0) {
			n_out = n_hrp + 1/*separator*/ + (version >= 0) + (n_in * CHAR_BIT + 4) / 5 + BLECH32_CHECKSUM_SIZE;
			assert(n_out <= nmax_out);
			ssize_t ret;
			struct blech32_encoder_state state;
			if ((ret = blech32_encode_begin(&state, (char *) out, n_out, hrp, n_hrp)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
			if (version >= 0 && (ret = blech32_encode_data(&state, (unsigned char *) &version, 5)) < 0 ||
					(ret = blech32_encode_data(&state, in, n_in * CHAR_BIT)) < 0 ||
					(ret = blech32_encode_finish(&state, modified ? BLECH32M_CONST : 1)) < 0)
				errx(EX_SOFTWARE, errmsg((enum bech32_error) ret));
			out[n_out++] = '\n';
		}
		else
#endif
		{
			n_out = n_hrp + 1/*separator*/ + (version >= 0) + (n_in * CHAR_BIT + 4) / 5 + BECH32_CHECKSUM_SIZE;
			assert(n_out <= nmax_out);
			ssize_t ret;
			struct bech32_encoder_state state;
			if ((ret = bech32_encode_begin(&state, (char *) out, n_out, hrp, n_hrp)) < 0)
				errx(EX_DATAERR, errmsg((enum bech32_error) ret));
			if (version >= 0 && (ret = bech32_encode_data(&state, (unsigned char *) &version, 5)) < 0 ||
					(ret = bech32_encode_data(&state, in, n_in * CHAR_BIT)) < 0 ||
					(ret = bech32_encode_finish(&state, modified ? BECH32M_CONST : 1)) < 0)
				errx(EX_SOFTWARE, errmsg((enum bech32_error) ret));
			out[n_out++] = '\n';
		}
	}

	if (hex && decode ?
			fwrite_hex(out, n_out, stdout) < (ssize_t) n_out :
			fwrite(out, 1, n_out, stdout) < n_out)
		err(EX_IOERR, "error writing to stdout");

	return exit_version ? version : EX_OK;
}
