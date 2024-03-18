#include "bech32.h"


static inline const char * __attribute__ ((__const__)) error_to_message(enum ::bech32_error error) {
	switch (error) {
		case BECH32_TOO_SHORT:
			return "encoding is too short";
		case BECH32_TOO_LONG:
			return "encoding is too long";
		case BECH32_NO_SEPARATOR:
			return "encoding contains no separator";
		case BECH32_MIXED_CASE:
			return "encoding uses mixed case";
		case BECH32_ILLEGAL_CHAR:
			return "encoding contains an illegal character";
		case BECH32_PADDING_ERROR:
			return "padding error";
		case BECH32_CHECKSUM_FAILURE:
			return "checksum verification failed";
		case BECH32_BUFFER_INADEQUATE: // should not be reachable
			return "buffer size is inadequate";
		case BECH32_HRP_TOO_SHORT:
			return "human-readable prefix is empty";
		case BECH32_HRP_TOO_LONG:
			return "human-readable prefix is too long";
		case BECH32_HRP_ILLEGAL_CHAR:
			return "human-readable prefix contains an illegal character";
		case SEGWIT_VERSION_ILLEGAL:
			return "witness version is illegal";
		case SEGWIT_PROGRAM_TOO_SHORT:
			return "witness program is too short";
		case SEGWIT_PROGRAM_TOO_LONG:
			return "witness program is too long";
		case SEGWIT_PROGRAM_ILLEGAL_SIZE:
			return "witness program is of illegal size";
	}
	std::abort(); // should not be reachable
}


namespace bech32 {


Error::Error(enum ::bech32_error error) : std::runtime_error(::error_to_message(error)), error(error) {
}


void Encoder::reset(std::string_view hrp, size_t nbits_reserve) {
	out.clear();
	out.resize(::bech32_encoded_size(hrp.size(), nbits_reserve, 0));
	if (auto error = ::bech32_encode_begin(&state, out.data(), out.size(), hrp.data(), hrp.size()))
		throw Error(error);
	out.resize(state.out - out.data());
}

void Encoder::write(const void *in, size_t nbits_in) {
	size_t written = out.size();
	out.resize(written + (state.n_out = ::bech32_encoded_size(0, state.nbits + nbits_in, 0) - 1));
	state.out = out.data() + written;
	if (auto error = ::bech32_encode_data(&state, static_cast<const unsigned char *>(in), nbits_in))
		throw Error(error);
	out.resize(state.out - out.data());
}

std::string Encoder::finish(bech32_constant_t constant) {
	size_t written = out.size();
	out.resize(written + (state.n_out = ::bech32_encoded_size(0, state.nbits, 0) - 1));
	state.out = out.data() + written;
	if (auto error = ::bech32_encode_finish(&state, constant))
		throw Error(error);
	out.resize(state.out - out.data());
	state = { };
	return std::move(out);
}


void Decoder::reset(std::string_view in) {
	if (auto ret = ::bech32_decode_begin(&state, in.data(), in.size()); ret < 0)
		throw Error(static_cast<enum ::bech32_error>(ret));
	else
		hrp = in.substr(0, static_cast<size_t>(ret));
}

void Decoder::read(void *out, size_t nbits_out) {
	if (auto error = ::bech32_decode_data(&state, static_cast<unsigned char *>(out), nbits_out))
		throw Error(error);
}

std::vector<std::byte> Decoder::read(size_t nbits) {
	if (nbits > this->bits_remaining())
		throw Error(BECH32_TOO_SHORT);
	std::vector<std::byte> out((nbits + CHAR_BIT - 1) / CHAR_BIT);
	this->read(out.data(), nbits);
	return out;
}

size_t Decoder::finish(bech32_constant_t constant) {
	if (auto ret = ::bech32_decode_finish(&state, constant); ret < 0)
		throw Error(static_cast<enum ::bech32_error>(ret));
	else
		return static_cast<size_t>(ret);
}


std::string encode_segwit_address(const void *program, size_t n_program, std::string_view hrp, unsigned version) {
	std::string address;
	address.resize(::bech32_encoded_size(hrp.size(), 5/*version*/ + n_program * CHAR_BIT, 0));
	if (auto ret = ::segwit_address_encode(address.data(), address.size() + 1/*null*/, static_cast<const unsigned char *>(program), n_program, hrp.data(), hrp.size(), version); ret < 0)
		throw Error(static_cast<enum ::bech32_error>(ret));
	else
		address.resize(static_cast<size_t>(ret));
	return address;
}

std::tuple<std::vector<std::byte>, std::string_view, unsigned> decode_segwit_address(std::string_view address) {
	std::tuple<std::vector<std::byte>, std::string_view, unsigned> ret;
	auto &[program, hrp, version] = ret;
	program.resize((address.size() - 1/*hrp*/ - 1/*separator*/ - BECH32_CHECKSUM_SIZE) * 5 / CHAR_BIT);
	size_t n_hrp;
	if (auto ret = ::segwit_address_decode(reinterpret_cast<unsigned char *>(program.data()), program.size(), address.data(), address.size(), &n_hrp, &version); ret < 0)
		throw Error(static_cast<enum ::bech32_error>(ret));
	else
		program.resize(static_cast<size_t>(ret));
	hrp = address.substr(0, n_hrp);
	return ret;
}


} // namespace bech32
