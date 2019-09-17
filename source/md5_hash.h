#pragma once

#include <string>
#include <array>

class md5_hash
{
public:
	[[nodiscard]] static std::array<uint8_t, 16> compute(const std::string & message)
	{
		// These vars will contain the hash
		uint32_t h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
		size_t new_len = message.size() + 1;

		//Pre-processing:
		//append "1" bit to message
		//append "0" bits until message length in bits ≡ 448 (mod 512)
		//append length mod (2^64) to message
		while (new_len % (512 / 8) != 448 / 8)
			new_len++;

		std::string msg_copy = message; msg_copy.resize(new_len + 8);
		msg_copy[message.size()] = 0x80; // append the "1" bit; most significant bit is "first"

		std::array<uint8_t, 4> bytes = md5_hash::uint32_to_4_bytes(message.size() * 8);
		for (size_t i = new_len; i < new_len + 4; i++)
			msg_copy[i] = bytes[i - new_len];

		bytes = md5_hash::uint32_to_4_bytes(message.size() >> 29);
		for (size_t i = new_len + 4; i < new_len + 8; i++)
			msg_copy[i] = bytes[i - new_len - 4];

		for (size_t i = 0; i < new_len; i += (512 / 8))
		{
			uint32_t w[16];
			for (size_t j = 0; j < 16; j++)
			{
				const std::array<uint8_t, 4> array
				{
					static_cast<unsigned char>(msg_copy[i + j * 4]),
					static_cast<unsigned char>(msg_copy[i + j * 4 + 1]),
					static_cast<unsigned char>(msg_copy[i + j * 4 + 2]),
					static_cast<unsigned char>(msg_copy[i + j * 4 + 3]),
				};

				w[j] = md5_hash::uint32_from_4_bytes(array);
			}

			uint32_t a = h0, b = h1, c = h2, d = h3;

			for (size_t j = 0; j < 64; j++)
			{
				uint32_t f, g;

				if (j < 16)
				{
					f = (b & c) | ((~b) & d);
					g = j;
				}
				else if (j < 32)
				{
					f = (d & b) | ((~d) & c);
					g = (5 * j + 1) % 16;
				}
				else if (j < 48)
				{
					f = b ^ c ^ d;
					g = (3 * j + 5) % 16;
				}
				else
				{
					f = c ^ (b | (~d));
					g = (7 * j) % 16;
				}

				const uint32_t temp = d;
				d = c;
				c = b;
				b = b + md5_hash::rotate_left((a + f + md5_hash::k[j] + w[g]), md5_hash::r[j]);
				a = temp;
			}

			h0 += a;
			h1 += b;
			h2 += c;
			h3 += d;
		}

		std::array<uint8_t, 4> h0_arr = md5_hash::uint32_to_4_bytes(h0);
		std::array<uint8_t, 4> h1_arr = md5_hash::uint32_to_4_bytes(h1);
		std::array<uint8_t, 4> h2_arr = md5_hash::uint32_to_4_bytes(h2);
		std::array<uint8_t, 4> h3_arr = md5_hash::uint32_to_4_bytes(h3);

		const std::array<uint8_t, 16> result = {
			h0_arr[0],
			h0_arr[1],
			h0_arr[2],
			h0_arr[3],

			h1_arr[0],
			h1_arr[1],
			h1_arr[2],
			h1_arr[3],

			h2_arr[0],
			h2_arr[1],
			h2_arr[2],
			h2_arr[3],

			static_cast<uint8_t>(h3_arr[0]),
			static_cast<uint8_t>(h3_arr[1]),
			static_cast<uint8_t>(h3_arr[2]),
			static_cast<uint8_t>(h3_arr[3]),
		};

		return result;
	}
private:
	md5_hash() = default;

	static uint32_t rotate_left(uint32_t x, int n)
	{
		return (x << n) | (x >> (32 - n));
	}

	static std::array<uint8_t, 4> uint32_to_4_bytes(uint32_t value)
	{
		std::array<uint8_t, 4> bytes{};

		bytes[0] = static_cast<uint8_t>(value);
		bytes[1] = static_cast<uint8_t>(value >> 8);
		bytes[2] = static_cast<uint8_t>(value >> 16);
		bytes[3] = static_cast<uint8_t>(value >> 24);

		return bytes;
	}

	static uint32_t uint32_from_4_bytes(std::array<uint8_t, 4> bytes)
	{
		uint32_t value = 0;

		value = (value << 8) + bytes[3];
		value = (value << 8) + bytes[2];
		value = (value << 8) + bytes[1];
		value = (value << 8) + bytes[0];

		return value;
	}

	constexpr static uint32_t k[64] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
	};

	constexpr static uint32_t r[64] = {
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};
};