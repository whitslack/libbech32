#include "bech32.h"

#include <algorithm>
#include <cassert>
#include <initializer_list>
#include <ranges>
#include <span>


template <std::ranges::viewable_range R> requires std::same_as<std::ranges::range_value_t<R>, char>
static inline auto lowercase_view(R &&range) {
	return std::views::transform(std::forward<R>(range), static_cast<int (*)(int)>(std::tolower));
}

static void test_round_trip(std::string_view encoding, bool bech32m) {
	bech32::Decoder decoder(encoding);
	auto bytes = decoder.read();
	uint8_t extra_bits = 0;
	size_t nbits_extra = decoder.bits_remaining();
	if (nbits_extra)
		decoder.read(&extra_bits, nbits_extra);
	decoder.finish(bech32m ? BECH32M_CONST : 1);
	bech32::Encoder encoder(std::string(decoder.prefix()).c_str(), bytes.size() * CHAR_BIT);
	encoder.write(bytes.data(), bytes.size() * CHAR_BIT);
	if (nbits_extra)
		encoder.write(&extra_bits, nbits_extra);
	auto actual = encoder.finish(bech32m ? BECH32M_CONST : 1);
	assert(std::ranges::equal(actual, lowercase_view(encoding)));
}

static void test_invalid(std::string_view encoding, bool bech32m, enum ::bech32_error reason) {
	try {
		bech32::Decoder decoder(encoding);
		decoder.read();
		if (size_t nbits_extra = decoder.bits_remaining()) {
			assert(nbits_extra < CHAR_BIT);
			uint8_t extra_bits;
			decoder.read(&extra_bits, nbits_extra);
		}
		decoder.finish(bech32m ? BECH32M_CONST : 1);
	}
	catch (const bech32::Error &e) {
		assert(e.error == reason);
		return;
	}
	throw std::logic_error("should have thrown");
}

static void test_segwit_round_trip(std::string_view address, unsigned expect_version, std::span<const std::byte> expect_program) {
	auto [program, hrp, version] = bech32::decode_segwit_address(address);
	assert(version == expect_version);
	assert(std::ranges::equal(program, expect_program));
	auto actual = bech32::encode_segwit_address(program.data(), program.size(), hrp, version);
	assert(std::ranges::equal(actual, lowercase_view(address)));
}

static void test_segwit_invalid(std::string_view address, enum ::bech32_error reason) {
	try {
		bech32::decode_segwit_address(address);
	}
	catch (const bech32::Error &e) {
		assert(e.error == reason);
		return;
	}
	throw std::logic_error("should have thrown");
}

template <typename T> requires std::is_trivially_copyable_v<typename decltype(std::span(std::declval<T>()))::element_type>
static inline void test_segwit_round_trip(std::string_view address, unsigned version, T &&expect) {
	auto bytes = as_bytes(std::span(std::forward<T>(expect)));
	return test_segwit_round_trip(address, version, std::span<const std::byte, std::dynamic_extent>(bytes));
}

static inline void test_segwit_round_trip(std::string_view address, unsigned version, std::initializer_list<uint8_t> expect) {
	auto bytes = as_bytes(std::span(expect));
	return test_segwit_round_trip(address, version, std::span<const std::byte, std::dynamic_extent>(bytes));
}

int main() {
	// HASH160(0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
	static constexpr uint8_t pkh[20] = {
		0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
	};
	test_segwit_round_trip("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", 0, pkh);
	test_segwit_round_trip("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", 0, pkh);

	// SHA256(21 0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 AC)
	static constexpr uint8_t sh[32] = {
		0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
		0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62
	};
	test_segwit_round_trip("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", 0, sh);
	test_segwit_round_trip("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 0, sh);

	test_round_trip("A12UEL5L", false);
	test_round_trip("A1LQFN3A", true);
	test_round_trip("a12uel5l", false);
	test_round_trip("a1lqfn3a", true);
	test_round_trip("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", false);
	test_round_trip("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6", true);
	test_round_trip("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", false);
	test_round_trip("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", true);
	test_round_trip("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", false);
	test_round_trip("11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8", true);
	test_round_trip("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", false);
	test_round_trip("split1checkupstagehandshakeupstreamerranterredcaperredlc445v", true);
	test_round_trip("?1ezyfcl", false);
	test_round_trip("?1v759aa", true);

	test_invalid("A1LQFN3A", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("a1lqfn3a", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("split1checkupstagehandshakeupstreamerranterredcaperredlc445v", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("?1v759aa", false, BECH32_CHECKSUM_FAILURE);

	test_invalid("\x20""1nwldj5", false, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("\x20""1xj0phk", true, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("\x7F""1axkwrx", false, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("\x7F""1g6xzxy", true, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("\x80""1eym55h", false, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("\x80""1vctc34", true, BECH32_HRP_ILLEGAL_CHAR);
	test_invalid("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", false, BECH32_TOO_LONG);
	test_invalid("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", true, BECH32_TOO_LONG);
	test_invalid("pzry9x0s0muk", false, BECH32_NO_SEPARATOR);
	test_invalid("qyrz8wqd2c9m", true, BECH32_NO_SEPARATOR);
	test_invalid("1pzry9x0s0muk", false, BECH32_HRP_TOO_SHORT);
	test_invalid("1qyrz8wqd2c9m", true, BECH32_HRP_TOO_SHORT);
	test_invalid("x1b4n0q5v", false, BECH32_ILLEGAL_CHAR);
	test_invalid("y1b0jsk6g", true, BECH32_ILLEGAL_CHAR);
	test_invalid("lt1igcx5c0", true, BECH32_ILLEGAL_CHAR);
	test_invalid("li1dgmt3", false, BECH32_TOO_SHORT);
	test_invalid("in1muywd", true, BECH32_TOO_SHORT);
	test_invalid("de1lg7wt\xFF", false, BECH32_ILLEGAL_CHAR);
	test_invalid("mm1crxm3i", true, BECH32_ILLEGAL_CHAR);
	test_invalid("au1s5cgom", true, BECH32_ILLEGAL_CHAR);
	test_invalid("A1G7SGD8", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("M1VUXWEZ", true, BECH32_CHECKSUM_FAILURE);
	test_invalid("10a06t8", false, BECH32_TOO_SHORT);
	test_invalid("16plkw9", true, BECH32_TOO_SHORT);
	test_invalid("1qzzfhee", false, BECH32_HRP_TOO_SHORT);
	test_invalid("1p2gdwpf", true, BECH32_HRP_TOO_SHORT);

	test_invalid("a12uelsl", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("a1lqfn39", true, BECH32_CHECKSUM_FAILURE);
	test_invalid("hj1fpjkcmr0ypmk7unvvssszef0zk", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("hj1fpjkcmr0ypmk7unvvsssh9er85", true, BECH32_CHECKSUM_FAILURE);
	test_invalid("hi1fpjkcmr0ypmx7unvvssszef0zk", false, BECH32_CHECKSUM_FAILURE);
	test_invalid("hi1fpjkcmr0ypmx7unvvsssh9er85", true, BECH32_CHECKSUM_FAILURE);

	test_segwit_round_trip("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", 0, pkh);
	test_segwit_round_trip("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", 0, sh);
	test_segwit_round_trip("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", 1, {
		0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
		0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
	});
	test_segwit_round_trip("BC1SW50QGDZ25J", 16, { 0x75, 0x1e });
	test_segwit_round_trip("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", 2, std::span(pkh).first(16));
	test_segwit_round_trip("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", 0, {
		0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
		0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33
	});
	test_segwit_round_trip("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", 1, {
		0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
		0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33
	});
	test_segwit_round_trip("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", 1, {
		0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
		0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
	});

	test_segwit_invalid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", SEGWIT_VERSION_ILLEGAL);
	test_segwit_invalid("bc1rw5uspcuh", BECH32_TOO_SHORT);
	test_segwit_invalid("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", SEGWIT_PROGRAM_TOO_LONG);
	test_segwit_invalid("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", SEGWIT_PROGRAM_ILLEGAL_SIZE);
	test_segwit_invalid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", BECH32_MIXED_CASE);
	test_segwit_invalid("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", BECH32_PADDING_ERROR);
	test_segwit_invalid("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", BECH32_PADDING_ERROR);
	test_segwit_invalid("bc1gmk9yu", BECH32_TOO_SHORT);

	test_segwit_invalid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", BECH32_ILLEGAL_CHAR);
	test_segwit_invalid("BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", SEGWIT_VERSION_ILLEGAL);
	test_segwit_invalid("bc1pw5dgrnzv", BECH32_TOO_SHORT);
	test_segwit_invalid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", SEGWIT_PROGRAM_TOO_LONG);
	test_segwit_invalid("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", SEGWIT_PROGRAM_ILLEGAL_SIZE);
	test_segwit_invalid("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", BECH32_MIXED_CASE);
	test_segwit_invalid("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", BECH32_PADDING_ERROR);
	test_segwit_invalid("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j", BECH32_PADDING_ERROR);
	test_segwit_invalid("bc1gmk9yu", BECH32_TOO_SHORT);

	// The below test vectors, which were originally valid under BIP173 (Bech32), are now invalid under BIP350 (Bech32m) because
	// they use witness versions greater than 0 but carry Bech32 checksums.
	test_segwit_invalid("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("BC1SW50QA3JX3S", BECH32_CHECKSUM_FAILURE);
	test_segwit_invalid("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", BECH32_CHECKSUM_FAILURE);

	return 0;
}
