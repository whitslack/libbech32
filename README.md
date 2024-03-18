# libbech32
**Library for Bech32/Bech32m/Blech32/Blech32m encoding/decoding**

Libbech32 is a C library for encoding and decoding SegWit addresses and arbitrary bit strings in Bech32/Bech32m/Blech32/Blech32m format. It offers three interfaces: a **low-level API** for working with arbitrary bit strings, a **high-level API** for working with SegWit Bitcoin addresses specifically, and a **command-line utility** for Bech32/Bech32m/Blech32/Blech32m encoding/decoding from `stdin` to `stdout`. C++ wrappers are optionally provided for both APIs.

This document gives a general overview. Please refer to the auto-generated [Doxygen documentation](https://whitslack.github.io/libbech32/bech32_8h.html) for specific details.

## Low-level API

The low-level API allows encoding/decoding arbitrary bit strings to/from Bech32/Bech32m/Blech32/Blech32m format. Bits are supplied to the encoder, or extracted from the decoder, through function calls that pass a buffer and a bit length. In the case that the bit length is not evenly divisible by 8, the bits of the last byte in the buffer are aligned to the least significant bit. Successive calls pack/unpack bit strings in the encoding without introducing any padding between segments.

### Encoding

To encode a bit string in Bech32/Bech32m, allocate a `struct bech32_encoder_state` and initialize it by passing to `bech32_encode_begin()` a pointer to it along with a pointer to the output buffer that is to receive the encoding and a pointer to the human-readable prefix to use in the encoding:

```c
enum bech32_error error;
struct bech32_encoder_state state;
char output[BECH32_MAX_SIZE];
static const char hrp[] = "bc";

if ((error = bech32_encode_begin(&state, output, sizeof output, hrp, strlen(hrp))) < 0) {
	abort(); // TODO handle error
}
```

Next, supply any number of bit strings to the encoder by repeatedly calling `bech32_encode_data()`, passing a pointer to the bits to encode and the number of bits to encode:

```c
const uint8_t version = 16;
if ((error = bech32_encode_data(&state, &version, 5)) < 0) {
	abort(); // TODO handle error
}

static const unsigned char program[] = { 0x75, 0x1e };
if ((error = bech32_encode_data(&state, program, sizeof program * CHAR_BIT)) < 0) {
	abort(); // TODO handle error
}
```

Finally, call `bech32_encode_finish()` to flush the encoder and append the checksum to the encoding, passing the constant to use for the checksum calculation, either 1 for Bech32 or `BECH32M_CONST` for Bech32m:

```c
if ((error = bech32_encode_finish(&state, BECH32M_CONST)) < 0) {
	abort(); // TODO handle error
}
assert(strcmp(output, "bc1sw50qgdz25j") == 0);
```

### Decoding

To decode a bit string from Bech32/Bech32m, allocate a `struct bech32_decoder_state` and initialize it by passing to `bech32_decode_begin()` a pointer to it along with a pointer to the input buffer containing the encoding to be decoded:

```c
ssize_t n;
struct bech32_decoder_state state;
static const char input[] = "bc1sw50qgdz25j";

if ((n = bech32_decode_begin(&state, input, strlen(input))) < 0) {
	abort(); // TODO handle error
}
assert(n == 2); // returns size of human-readable prefix at input
```

Next, extract any number of bit strings from the decoder by repeatedly calling `bech32_decode_data()`, passing a pointer to an output buffer to receive the decoded bits and the number of bits to decode:

```c
enum bech32_error error;

uint8_t version;
if ((error = bech32_decode_data(&state, &version, 5)) < 0) {
	abort(); // TODO handle error
}
assert(version == 16);

unsigned char program[2];
if ((error = bech32_decode_data(&state, program, sizeof program * CHAR_BIT)) < 0) {
	abort(); // TODO handle error
}
static const unsigned char expected[] = { 0x75, 0x1e };
assert(memcmp(program, expected, sizeof program) == 0);
```

Finally, call `bech32_decode_finish()` to check any padding bits and verify the checksum, passing the constant to use for the checksum verification, either 1 for Bech32 or `BECH32M_CONST` for Bech32m:

```c
if ((n = bech32_decode_finish(&state, BECH32M_CONST)) < 0) {
	abort(); // TODO handle error
}
assert((5 - n) % 5 == (5 + sizeof program * CHAR_BIT) % 5); // returns number of padding bits
```

### C++ example

```cpp
#include <bech32.h>

#include <array>
#include <cassert>
#include <climits>
#include <string>

static void example_encode() {
	bech32::Encoder enc("bc");

	const uint8_t version = 16;
	enc.write(&version, 5);

	static constexpr std::array<unsigned char, 2> program { 0x75, 0x1e };
	enc.write(program.data(), program.size() * CHAR_BIT);

	std::string encoding = enc.finish(BECH32M_CONST);
	assert(encoding == "bc1sw50qgdz25j");
}

static void example_decode() {
	bech32::Decoder dec("bc1sw50qgdz25j");
	assert(dec.prefix() == "bc");

	uint8_t version;
	dec.read(&version, 5);
	assert(version == 16);

	std::array<unsigned char, 2> program;
	dec.read(program.data(), program.size() * CHAR_BIT);
	assert((program == std::array<unsigned char, 2> { 0x75, 0x1e }));

	size_t n = dec.finish(BECH32M_CONST);
	assert((5 - n) % 5 == (5 + program.size() * CHAR_BIT) % 5);
}

int main() {
	example_encode();
	example_decode();
	return 0;
}
```

### Blech32/Blech32m

Unless configured with `--disable-blech32`, the low-level API supports Blech32/Blech32m encoding/decoding via structures and functions whose names are prefixed by `blech32_` instead of `bech32_`. Aside from the names, the API is the same. Likewise, the C++ wrappers are in the `blech32` namespace instead of `bech32`.

## High-level API

The high-level API allows encoding/decoding a SegWit address with a single function call.

### Encoding

To encode a SegWit address, call `segwit_address_encode()`, passing a pointer to an output buffer to receive the null-terminated address, the size of the output buffer, a pointer to a buffer containing the witness program, the size of the witness program (in bytes), a pointer to the human-readable prefix, the size of the human-readable prefix, and the witness version:

```c
char address[BECH32_MAX_SIZE + 1];
static const unsigned char program[] = {
	0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
	0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
};
static const char hrp[] = "bc";
const unsigned version = 0;
ssize_t n;
if ((n = segwit_address_encode(
		address, sizeof address,
		program, sizeof program,
		hrp, strlen(hrp), version)) < 0)
{
	abort(); // TODO handle error
}
assert(strcmp(address, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4") == 0);
```

### Decoding

To decode a SegWit address, call `segwit_address_decode()`, passing a pointer to an output buffer to receive the decoded witness program, the size of the output buffer, a pointer to the address to decode, the size of the address, a pointer to a variable to receive the size of the human-readable prefix, and a pointer to a variable to receive the witness version:

```c
unsigned char program[WITNESS_PROGRAM_MAX_SIZE];
static const char address[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
size_t n_hrp;
unsigned version;
ssize_t n;
if ((n = segwit_address_decode(
		program, sizeof program,
		address, strlen(address),
		&n_hrp, &version)) < 0)
{
	abort(); // TODO handle error
}
assert(n_hrp == 2);
assert(version == 0);
static const unsigned char expected[] = {
	0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
	0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
};
assert(n == sizeof expected && memcmp(program, expected, n) == 0);
```

### C++ example

```cpp
#include <bech32.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <ranges>
#include <span>
#include <string>
#include <string_view>

static void example_encode() {
	static constexpr std::array<unsigned char, 20> program {
		0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
		0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
	};
	std::string address = bech32::encode_segwit_address(program.data(), program.size(), "bc", 0);
	assert(address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
}

static void example_decode() {
	static constexpr std::string_view address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
	static constexpr std::array<unsigned char, 20> expected {
		0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
		0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
	};
	auto [program, hrp, version] = bech32::decode_segwit_address(address);
	assert(std::ranges::equal(program, as_bytes(std::span(expected))));
	assert(hrp == "bc");
	assert(version == 0);
}

int main() {
	example_encode();
	example_decode();
	return 0;
}
```

### Blech32/Blech32m

Unless configured with `--disable-blech32`, the high-level API supports encoding/decoding of blinding SegWit addresses via functions whose names are prefixed by `blech32_` instead of `segwit_`. Aside from the names, the API is the same. Likewise, the C++ wrappers are in the `blech32` namespace instead of `bech32`.

## Command-line utility

The library comes with a command-line utility for encoding/decoding Bech32/Bech32m. It supports only data payloads a whole number of bytes in size, optionally prefixed by a 5-bit version field such as in SegWit addresses.

**Usage:**  
`bech32` \[`-h`] \[`-l`] \[`-m`] *hrp* { \[*version*] | `-d` \[`-v`|*version*] }  
`bech32m` \[`-h`] *hrp* { \[*version*] | `-d` \[`-v`|*version*] }  
`blech32` \[`-h`] *hrp* { \[*version*] | `-d` \[`-v`|*version*] }  
`blech32m` \[`-h`] *hrp* { \[*version*] | `-d` \[`-v`|*version*] }

Reads data from `stdin` and writes its Bech32 encoding to `stdout`.
If *version* is given, its least significant 5 bits are encoded as a SegWit version field.

<dl>
<dt><code>-d</code>,<code>--decode</code></dt>
<dd>Decode a Bech32 encoding from <code>stdin</code> and write the decoded data to <code>stdout</code>.
If <em>version</em> is given, assert that it matches the version field in the data.</dd>

<dt><code>-h</code>,<code>--hex</code></dt>
<dd>Use hexadecimal for data input/output.
If this option is not specified, the data are read/written in raw binary.</dd>

<dt><code>-l</code>,<code>--blech</code></dt>
<dd>Use Blech32/Blech32m instead of Bech32/Bech32m.
Implied if the command is invoked as <code>blech32</code> or <code>blech32m</code>.</dd>

<dt><code>-m</code>,<code>--modified</code></dt>
<dd>Use Bech32m/Blech32m instead of Bech32/Blech32.
Implied if the command is invoked as <code>bech32m</code> or <code>blech32m</code>.</dd>

<dt><code>-v</code>,<code>--exit-version</code></dt>
<dd>Extract a 5-bit SegWit version field and return it as the exit status.</dd>
</dl>

### Examples

Encode a 2-byte, version-16 witness program, given in hexadecimal:
```bash
$ echo 751e | bech32m -h bc 16
bc1sw50qgdz25j
```

Decode a Bech32m encoding to hexadecimal and return its witness version as the exit status:
```bash
$ echo bc1sw50qgdz25j | bech32m -dhv bc ; echo $?
751e
16
```

Encode a P2WPKH SegWit address, given its public key hash in hexadecimal:
```bash
$ echo 751e76e8199196d454941c45d1b3a323f1433bd6 | bech32 -h bc 0
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
```

Decode the public key hash from a P2WPKH SegWit address,
and assert that its human-readable prefix is `bc` and its witness version is 0:
```bash
$ echo bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 | bech32 -dh bc 0
751e76e8199196d454941c45d1b3a323f1433bd6
```

The *hrp* given on the command line is asserted when decoding:
```bash
$ echo tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx | bech32 -dhv bc
bech32: human-readable prefix was "tb", not "bc"
```

The *version* given on the command line is asserted when decoding:
```bash
$ echo bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh | bech32m -dh bc 1
bech32m: version was 0, not 1
```

Encode an empty string in Bech32 format with no version field:
```bash
$ bech32 bc </dev/null
bc1gmk9yu
```

Encode a 32-byte random string in Bech32m with version 1:
```bash
$ head -c32 /dev/urandom | bech32m bc 1
bc1pxgs5304wrx293jlreyefsgz4h8vlg36unnypxkre34zumqhy2e8st8k7y5
```

Encode a 20-byte random string in Bech32 with version 0,
and decode the encoding to hexadecimal, returning the version as the exit status:
```bash
$ head -c20 /dev/urandom | bech32 bc 0 | bech32 -dhv bc
270332edf25ec80516652bdc7fd4f762daecb5f7
```

Encoding with a version field and attempting to decode without one causes a padding error:
```bash
$ head -c20 /dev/urandom | bech32 bc 0 | bech32 -dh bc
bech32: padding error
```

Encoding without a version field and attempting to decode with one also causes a padding error:
```bash
$ head -c20 /dev/urandom | bech32 bc | bech32 -dhv bc
bech32: padding error
```

## Building

1. Install the prerequisites — most/all of which you probably already have:

	* [Autoconf](https://www.gnu.org/software/autoconf/)
	* [Autoconf Archive](https://www.gnu.org/software/autoconf-archive/)
	* [Automake](https://www.gnu.org/software/automake/)
	* [Libtool](https://www.gnu.org/software/libtool/)
	* [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)

1. Then it's just your standard Autotools madness:

	```
	$ autoreconf -i
	$ ./configure
	$ make
	$ sudo make install
	```
