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
	fprintf(stderr, "usage: %s [-h] [-m] <hrp> { [<version>] | -d [-v|<version>] }\n\n"
		"Reads data from stdin and writes its Bech32 encoding to stdout. If <version> is\n"
		"given, its least significant 5 bits are encoded as a SegWit version field.\n\n"
		"-d,--decode\n"
		"    Decode a Bech32 encoding from stdin and write the data to stdout. If\n"
		"    <version> is given, assert that it matches the version field in the data.\n"
		"-h,--hex\n"
		"    Use hexadecimal for data input/output.\n"
		"-m,--bech32m\n"
		"    Use Bech32m instead of Bech32. Implied if invoked as 'bech32m'.\n"
		"-v,--exit-version\n"
		"    Extract a 5-bit SegWit version field and return it as the exit status.\n",
		program_invocation_short_name);
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
		{ .name = "bech32m", .has_arg = no_argument, .val = 'm' },
		{ .name = "exit-version", .has_arg = no_argument, .val = 'v' },
		{ .name = "help", .has_arg = no_argument, .val = 1 },
		{ .name = "version", .has_arg = no_argument, .val = 2 },
		{ }
	};
	bool decode = false, hex = false, exit_version = false;
	uint32_t constant = strcmp(program_invocation_short_name, "bech32m") ? 1 : BECH32M_CONST;
	for (int opt; (opt = getopt_long(argc, argv, "dhmv", longopts, NULL)) >= 0;) {
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
			case 'm':
				constant = BECH32M_CONST;
				break;
			case 'v':
				exit_version = true;
				break;
			default:
				print_usage();
				return EX_USAGE;
		}
	}
	if ((decode ? argc - optind > 1 + !exit_version : argc - optind > 2 || exit_version) || optind >= argc)
		return print_usage(), EX_USAGE;
	const char *const hrp = argv[optind++];
	size_t n_hrp = strlen(hrp);
	if (n_hrp < BECH32_HRP_MIN_SIZE)
		errx(EX_USAGE, errmsg(BECH32_HRP_TOO_SHORT));
	if (n_hrp > BECH32_HRP_MAX_SIZE)
		errx(EX_USAGE, errmsg(BECH32_HRP_TOO_LONG));
	int8_t version = optind < argc ? (int8_t) atoi(argv[optind++]) : -1;

	unsigned char in[BECH32_MAX_SIZE];
	size_t n_in = 0, nmax_in = decode ? BECH32_MAX_SIZE :
			(BECH32_MAX_SIZE - n_hrp - 1/*separator*/ - (version >= 0) - 6/*checksum*/) * 5 / CHAR_BIT;
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

	unsigned char out[BECH32_MAX_SIZE + 1/*'\n'*/];
	size_t n_out = 0;
	if (decode) {
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
		assert(n_out <= sizeof out);
		if ((ret = bech32_decode_data(&state, out, n_out * CHAR_BIT)) < 0 ||
				(ret = bech32_decode_finish(&state, constant)) < 0)
			errx(EX_DATAERR, errmsg((enum bech32_error) ret));
	}
	else {
		n_out = n_hrp + 1/*separator*/ + (version >= 0) + (n_in * CHAR_BIT + 4) / 5 + 6/*checksum*/;
		assert(n_out <= sizeof out);
		ssize_t ret;
		struct bech32_encoder_state state;
		if ((ret = bech32_encode_begin(&state, (char *) out, n_out, hrp, n_hrp)) < 0)
			errx(EX_DATAERR, errmsg((enum bech32_error) ret));
		if (version >= 0 && (ret = bech32_encode_data(&state, (unsigned char *) &version, 5)) < 0 ||
				(ret = bech32_encode_data(&state, in, n_in * CHAR_BIT)) < 0 ||
				(ret = bech32_encode_finish(&state, constant)) < 0)
			errx(EX_SOFTWARE, errmsg((enum bech32_error) ret));
		out[n_out++] = '\n';
	}

	if (hex && decode ?
			fwrite_hex(out, n_out, stdout) < (ssize_t) n_out :
			fwrite(out, 1, n_out, stdout) < n_out)
		err(EX_IOERR, "error writing to stdout");

	return exit_version ? version : EX_OK;
}
