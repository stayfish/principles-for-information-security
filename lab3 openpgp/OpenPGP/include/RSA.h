#pragma once
#include <NTL/ZZ.h>
#include <vector>
#include <ostream>
#include <istream>
#include <string>
using namespace NTL;
typedef ZZ BIGINT;

const int PRIME_LEN1 = 512;
const int PRIME_LEN2 = 1024;

// typedef unsigned char u8;
#include <string>
const int DIGEST_LEN = 40; // 40 bytes

typedef BIGINT Signature;

namespace RSA
{
	struct Public_key
	{
		BIGINT n;
		BIGINT b;
	};
	struct Private_key
	{
		BIGINT p;
		BIGINT q;
		BIGINT a;
	};
	struct Key
	{
		Public_key pub;
		Private_key priv;
	};

	// struct SignedMessage
	// {
	// 	std::string digest;
	// 	BIGINT signature;
	// };
	std::ostream &operator<<(std::ostream &, const Public_key &);
	std::ostream &operator<<(std::ostream &, const Private_key &);
	std::istream &operator>>(std::istream &, Public_key &);
	std::istream &operator>>(std::istream &, Private_key &);
	Key KeyGenerator(int);
	BIGINT Encode(Public_key, const BIGINT &);
	BIGINT Decode(Private_key, Public_key, const BIGINT &);

	Signature Sign(Private_key, Public_key, const std::string &);
	bool Verify(Public_key, Signature, const std::string &);
}

const int BASE = 128;
BIGINT String2BIGINT(const std::string &);
std::string BIGINT2String(const BIGINT &);
BIGINT stringstream2BIGINT(std::string);