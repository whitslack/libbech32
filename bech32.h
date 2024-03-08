/// @file

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
# define restrict __restrict
extern "C" {
#endif

static const uint_least32_t BECH32M_CONST = UINT32_C(0x2bc830a3);

static const size_t
	BECH32_HRP_MIN_SIZE = 1,
	BECH32_HRP_MAX_SIZE = 83,
	BECH32_MIN_SIZE = BECH32_HRP_MIN_SIZE + 1/*separator*/ + 6/*checksum*/,
	BECH32_MAX_SIZE = 90,
	WITNESS_PROGRAM_MIN_SIZE = 2,
	WITNESS_PROGRAM_MAX_SIZE = 40,
	WITNESS_PROGRAM_PKH_SIZE = 20,
	WITNESS_PROGRAM_SH_SIZE = 32,
	SEGWIT_ADDRESS_MIN_SIZE = BECH32_HRP_MIN_SIZE + 1/*separator*/ + 1/*version*/ +
			((WITNESS_PROGRAM_MIN_SIZE * CHAR_BIT + 4) / 5) + 6/*checksum*/;

static const unsigned WITNESS_MAX_VERSION = 16;


/**
 * @brief Possible error codes.
 */
enum bech32_error {
	BECH32_TOO_SHORT = -1,
	BECH32_TOO_LONG = -2,
	BECH32_NO_SEPARATOR = -3,
	BECH32_MIXED_CASE = -4,
	BECH32_ILLEGAL_CHAR = -5,
	BECH32_PADDING_ERROR = -6,
	BECH32_CHECKSUM_FAILURE = -7,
	BECH32_BUFFER_INADEQUATE = -8,
	BECH32_HRP_TOO_SHORT = -9,
	BECH32_HRP_TOO_LONG = -10,
	BECH32_HRP_ILLEGAL_CHAR = -11,
	SEGWIT_VERSION_ILLEGAL = -12,
	SEGWIT_PROGRAM_TOO_SHORT = -13,
	SEGWIT_PROGRAM_TOO_LONG = -14,
	SEGWIT_PROGRAM_ILLEGAL_SIZE = -15,
};


/**
 * @brief The state of a Bech32 encoder.
 */
struct bech32_encoder_state {

	/**
	 * @brief A pointer to the next character that the encoder will produce.
	 */
	char *restrict out;

	/**
	 * @brief The number of characters of output buffer space remaining at #out.
	 */
	size_t n_out;

	/**
	 * @brief The number of bits that have been consumed by the encoder but that do not yet appear in the output.
	 */
	size_t nbits;

	/**
	 * @brief The bits that have been consumed by the encoder but that do not yet appear in the output.
	 *
	 * Only the #nbits least significant bits of this field are valid.
	 */
	uint_fast32_t bits;

	/**
	 * @brief The intermediate checksum state.
	 */
	uint_fast32_t chk;

};

/**
 * @brief Returns the size of the Bech32 encoding of the specified number of data bits.
 * @param n_hrp The size of the human-readable prefix in characters.
 * @param nbits_in The number of data bits to be encoded.
 * @param n_pad The number of excess bytes to include in the returned size.
 * @return The size of the specified Bech32 encoding, or @c SIZE_MAX upon overflow.
 */
size_t bech32_encoded_size(
		size_t n_hrp,
		size_t nbits_in,
		size_t n_pad)
	__attribute__ ((__nothrow__, __const__));

/**
 * @brief Begins a Bech32 encoding.
 * @param[out] state A pointer to the encoder state to initialize.
 * @param[out] out A pointer to a buffer into which the encoder is to write the encoding.
 * Call bech32_encoded_size() to calculate the required size of this buffer.
 * @param n_out The size of the buffer at @p out.
 * @param[in] hrp A pointer to a character sequence specifying the human-readable prefix of the encoding.
 * @param n_hrp The size of the human-readable prefix in characters.
 * @return 0 if the parameters were accepted and the state structure was initialized, or a negative number if an error occurred,
 * which may be
 * @c BECH32_HRP_TOO_SHORT because the human-readable prefix is empty,
 * @c BECH32_HRP_TOO_LONG because the human-readable prefix is too long,
 * @c BECH32_HRP_ILLEGAL_CHAR because the human-readable prefix contains an illegal character, or
 * @c BECH32_BUFFER_INADEQUATE because @p n_out is too small.
 */
enum bech32_error bech32_encode_begin(
		struct bech32_encoder_state *restrict state,
		char *restrict out,
		size_t n_out,
		const char *restrict hrp,
		size_t n_hrp)
	__attribute__ ((__access__ (write_only, 1), __access__ (write_only, 2), __access__ (read_only, 4), __nonnull__, __nothrow__, __warn_unused_result__));

/**
 * @brief Feeds data to the Bech32 encoder.
 * @param[in,out] state A pointer to the encoder state, which must previously have been initialized by a call to
 * bech32_encode_begin().
 * @param[in] in A pointer to the data to encode.
 * @param nbits_in The number of valid bits in the data at @p in.
 * If this is not an integer multiple of @c CHAR_BIT, then the valid bits in the last input byte must be aligned to the least
 * significant bit.
 * @return 0 if the given data bits were consumed, or a negative number if an error occurred, which may be
 * @c BECH32_BUFFER_INADEQUATE because insufficient space remains in the output buffer.
 */
enum bech32_error bech32_encode_data(
		struct bech32_encoder_state *restrict state,
		const unsigned char *restrict in,
		size_t nbits_in)
	__attribute__ ((__access__ (read_write, 1), __access__ (read_only, 2), __nonnull__, __nothrow__, __warn_unused_result__));

/**
 * @brief Finishes a Bech32 encoding.
 * @param[in,out] state A pointer to the encoder state, which must previously have been initialized by a call to
 * bech32_encode_begin().
 * @param constant The constant to add to the checksum.
 * It should be 1 for the original Bech32 specification or @c BECH32M_CONST for Bech32m.
 * @return 0 if the encoder successfully finished the encoding, or a negative number if an error occurred, which may be
 * @c BECH32_BUFFER_INADEQUATE because insufficient space remains in the output buffer or
 * @c BECH32_CHECKSUM_FAILURE because the encoding failed its internal checksum check (due to a software bug or hardware failure).
 */
enum bech32_error bech32_encode_finish(
		struct bech32_encoder_state *restrict state,
		uint_least32_t constant)
	__attribute__ ((__access__ (read_write, 1), __nonnull__, __nothrow__, __warn_unused_result__));



/**
 * @brief The state of a Bech32 decoder.
 */
struct bech32_decoder_state {

	/**
	 * @brief A pointer to the next character that the decoder will consume.
	 */
	const char *restrict in;

	/**
	 * @brief The number of characters of input remaining at #in.
	 */
	size_t n_in;

	/**
	 * @brief The number of bits that have been consumed by the decoder but that do not yet appear in the output.
	 */
	size_t nbits;

	/**
	 * @brief The bits that have been consumed by the decoder but that do not yet appear in the output.
	 *
	 * Only the #nbits least significant bits of this field are valid.
	 */
	uint_fast32_t bits;

	/**
	 * @brief The intermediate checksum state.
	 */
	uint_fast32_t chk;

};

/**
 * @brief Begins a Bech32 decoding.
 * @param[out] state A pointer to the decoder state to initialize.
 * @param[in] in A pointer to the encoding to be decoded.
 * @param n_in The size of the encoding at @p in.
 * @return The size of the human-readable prefix of the encoding at @p in if the parameters were accepted and the state structure
 * was initialized, or a negative number if an error occurred, which may be
 * @c BECH32_TOO_SHORT because the encoding is too short,
 * @c BECH32_TOO_LONG because the encoding is too long,
 * @c BECH32_NO_SEPARATOR because the encoding contains no separator,
 * @c BECH32_HRP_TOO_SHORT because the human-readable prefix is empty,
 * @c BECH32_HRP_TOO_LONG because the human-readable prefix is too long,
 * @c BECH32_HRP_ILLEGAL_CHAR because the human-readable prefix contains an illegal character,
 * @c BECH32_ILLEGAL_CHAR because the encoding contains an illegal character, or
 * @c BECH32_MIXED_CASE because the encoding uses mixed case.
 */
ssize_t bech32_decode_begin(
		struct bech32_decoder_state *restrict state,
		const char *restrict in,
		size_t n_in)
	__attribute__ ((__access__ (write_only, 1), __access__ (read_only, 2), __nonnull__, __nothrow__, __warn_unused_result__));

/**
 * @brief Returns the number of data bits remaining in the Bech32 encoding, including any padding bits but excluding the checksum.
 * @param[in] state A pointer to the decoder state, which must previously have been initialized by a call to bech32_decode_begin().
 */
static inline size_t
__attribute__ ((__access__ (read_only, 1), __nonnull__, __nothrow__, __pure__))
bech32_decode_bits_remaining(const struct bech32_decoder_state *restrict state) {
	return state->nbits + state->n_in * 5;
}

/**
 * @brief Pulls data from the Bech32 decoder.
 * @param[in,out] state A pointer to the decoder state, which must previously have been initialized by a call to
 * bech32_decode_begin().
 * @param[out] out A pointer to a buffer into which the decoder is to place the decoded data.
 * @param nbits_out The number of data bits to place in the buffer at @p out.
 * If this is not an integer multiple of @c CHAR_BIT, then the valid bits in the last output byte will be aligned to the least
 * significant bit.
 * @return 0 if the requested data bits were produced, or a negative number if an error occurred, which may be
 * @c BECH32_BUFFER_INADEQUATE because insufficient characters remain in the input buffer or
 * @c BECH32_ILLEGAL_CHAR because the decoder encountered an illegal character in the encoding.
 */
enum bech32_error bech32_decode_data(
		struct bech32_decoder_state *restrict state,
		unsigned char *restrict out,
		size_t nbits_out)
	__attribute__ ((__access__ (read_write, 1), __access__ (write_only, 2), __nonnull__, __nothrow__, __warn_unused_result__));

/**
 * @brief Finishes a Bech32 decoding.
 * @param[in,out] state A pointer to the decoder state, which must previously have been initialized by a call to
 * bech32_decode_begin().
 * @param constant The constant to add to the checksum.
 * It should be 1 for the original Bech32 specification or @c BECH32M_CONST for Bech32m.
 * @return The number of unconsumed padding bits remaining at the end of the encoding if the decoder successfully finished the
 * decoding and verified the checksum, or a negative number if an error occurred, which may be
 * @c BECH32_PADDING_ERROR because of a padding error (more than 5 data bits remain unconsumed or an unconsumed data bit is set),
 * @c BECH32_ILLEGAL_CHAR because the decoder encountered an illegal character in the encoding, or
 * @c BECH32_CHECKSUM_FAILURE because checksum verification failed.
 */
ssize_t bech32_decode_finish(
		struct bech32_decoder_state *restrict state,
		uint_least32_t constant)
	__attribute__ ((__access__ (read_write, 1), __nonnull__, __nothrow__, __warn_unused_result__));


/**
 * @brief Encodes a Segregated Witness program into a Bech32 address.
 * @param[out] address A pointer to a buffer into which the address is to be written.
 * This function will never write more than 91 characters to this buffer, including the null terminator.
 * @param n_address The size of the output buffer at @p address.
 * @param[in] program A pointer to the witness program to encode.
 * @param n_program The size of the witness program at @p program.
 * @param[in] hrp A pointer to a character sequence specifying the human-readable prefix to use.
 * Should be "bc" for Bitcoin mainnet or "tb" for Bitcoin testnet.
 * @param n_hrp The size of the human-readable prefix, not including any null terminator that may be present but is not required.
 * @param version The witness version to use. Must be between 0 and 16.
 * Addresses using witness version 0 are encoded using Bech32; all others are encoded using Bech32m.
 * @return The size of the address (not including the null terminator) if the encoding was successful, or a negative number if an
 * error occurred, which may be
 * @c SEGWIT_PROGRAM_TOO_SHORT because the witness program is too short,
 * @c SEGWIT_PROGRAM_TOO_LONG because the witness program is too long,
 * @c SEGWIT_VERSION_ILLEGAL because the witness version is illegal,
 * @c SEGWIT_PROGRAM_ILLEGAL_SIZE because the witness program is of an illegal size for the specified witness version,
 * @c BECH32_BUFFER_INADEQUATE because @p n_address is too small,
 * @c BECH32_HRP_TOO_SHORT because the human-readable prefix is empty,
 * @c BECH32_HRP_TOO_LONG because the human-readable prefix is too long,
 * @c BECH32_HRP_ILLEGAL_CHAR because the human-readable prefix contains an illegal character, or
 * @c BECH32_CHECKSUM_FAILURE because the encoding failed its internal checksum check (due to a software bug or hardware failure).
 */
ssize_t segwit_address_encode(
		char *restrict address,
		size_t n_address,
		const unsigned char *restrict program,
		size_t n_program,
		const char *restrict hrp,
		size_t n_hrp,
		unsigned version)
	__attribute__ ((__access__ (write_only, 1), __access__ (read_only, 3), __access__ (read_only, 5), __nonnull__, __nothrow__, __warn_unused_result__));

/**
 * @brief Decodes a Bech32 address into a Segregated Witness program.
 * @param[out] program A pointer to a buffer into which the witness program is to be written.
 * This function will never write more than 40 bytes to this buffer.
 * @param n_program The size of the output buffer at @p program.
 * @param[in] address A pointer to the Bech32 address to decode.
 * It may be in either the uppercase or lowercase form.
 * @param n_address The size of the address at @p address, not including any null terminator that may be present but is not
 * required.
 * @param[out] n_hrp A pointer to a variable that is to receive the size of the human-readable prefix in characters.
 * @param[out] version A pointer to a variable that is to receive the witness version, which will be between 0 and 16.
 * Addresses using witness version 0 are decoded using Bech32; all others are decoded using Bech32m.
 * @return The size of the witness program if the decoding was successful, or a negative number if an error occurred, which may be
 * @c BECH32_TOO_SHORT because the address is too short,
 * @c BECH32_TOO_LONG because the address is too long,
 * @c BECH32_NO_SEPARATOR because the address contains no separator,
 * @c BECH32_HRP_TOO_SHORT because the human-readable prefix is empty,
 * @c BECH32_HRP_TOO_LONG because no separator was found,
 * @c BECH32_HRP_ILLEGAL_CHAR because the human-readable prefix contains an illegal character,
 * @c BECH32_ILLEGAL_CHAR because the address contains an illegal character,
 * @c BECH32_MIXED_CASE because the address uses mixed case,
 * @c SEGWIT_PROGRAM_TOO_SHORT because the witness program is too short,
 * @c SEGWIT_PROGRAM_TOO_LONG because the witness program is too long,
 * @c BECH32_BUFFER_INADEQUATE because @p n_program is too small,
 * @c SEGWIT_VERSION_ILLEGAL because the witness version is illegal,
 * @c SEGWIT_PROGRAM_ILLEGAL_SIZE because the witness program is of an illegal size for the encoded witness version,
 * @c BECH32_PADDING_ERROR because of a padding error, or
 * @c BECH32_CHECKSUM_FAILURE because checksum verification failed.
 */
ssize_t segwit_address_decode(
		unsigned char *restrict program,
		size_t n_program,
		const char *restrict address,
		size_t n_address,
		size_t *restrict n_hrp,
		unsigned *restrict version)
	__attribute__ ((__access__ (write_only, 1), __access__ (read_only, 3), __access__ (write_only, 5), __access__ (write_only, 6), __nonnull__, __nothrow__, __warn_unused_result__));


#ifdef __cplusplus
} // extern "C"
# undef restrict


#include <climits>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace bech32 {


class Error : public std::runtime_error {

public:
	enum ::bech32_error error;

public:
	explicit Error(enum ::bech32_error error);

};


class Encoder {

private:
	struct ::bech32_encoder_state state;
	std::string out;

public:
#if __cpp_lib_constexpr_string >= 201907L
	constexpr
#endif
	Encoder() noexcept : state() { }

	explicit Encoder(std::string_view hrp, size_t nbits_reserve = 0) {
		this->reset(hrp, nbits_reserve);
	}

public:
	void reset(std::string_view hrp, size_t nbits_reserve = 0);

	void write(const void *in, size_t nbits_in);

	std::string finish(uint_least32_t constant = BECH32M_CONST);

};


class Decoder {

private:
	struct ::bech32_decoder_state state;
	std::string_view hrp;

public:
	constexpr Decoder() noexcept : state() { }

	explicit Decoder(std::string_view in) {
		this->reset(in);
	}

public:
	std::string_view __attribute__ ((__pure__)) prefix() const noexcept {
		return hrp;
	}

	size_t __attribute__ ((__pure__)) bits_remaining() const noexcept {
		return ::bech32_decode_bits_remaining(&state);
	}

	void reset(std::string_view in);

	void read(void *out, size_t nbits_out);

	std::vector<std::byte> read(size_t nbits);

	auto read() {
		return this->read(this->bits_remaining() & ~static_cast<size_t>(CHAR_BIT - 1));
	}

	size_t finish(uint_least32_t constant = BECH32M_CONST);

};


std::string encode_segwit_address(
		const void *program,
		size_t n_program,
		std::string_view hrp,
		unsigned version)
	__attribute__ ((__access__ (read_only, 1), __nonnull__, __pure__));

std::tuple<std::vector<std::byte>, std::string_view, unsigned> decode_segwit_address(
		std::string_view address)
	__attribute__ ((__pure__));


} // namespace bech32

#endif // defined(__cplusplus)
