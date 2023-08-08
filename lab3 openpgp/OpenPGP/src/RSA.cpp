#include <string>
#include <iostream>
#include <fstream>
#include <NTL/ZZ.h>

using namespace NTL;

#define IS_PRIME true
#define NOT_PRIME false

#define PRIME_TEST_ROUND 5

typedef ZZ BIGINT;

#include "RSA.h"

// Prime test
bool Miller_Rabin(const BIGINT &n, const BIGINT &a)
{
	BIGINT m;
	m = n - 1;
	long k = MakeOdd(m);
	// std::cout << "m:" << m << ",k:" << k << std::endl;

	BIGINT b;
	PowerMod(b, a, m, n);
	if (b % n == 1)
		return IS_PRIME;
	for (long i = 0; i < k; i++)
	{
		if (b % n == -1)
			return IS_PRIME;
		else
			b = (b * b) % n;
	}
	return NOT_PRIME;
}

bool easy_prime_test(const BIGINT &n)
{
	PrimeSeq seq;
	long p = seq.next();
	while (p < 2000)
	{
		if (n % p == 0)
		{
			if (n == p)
				return IS_PRIME;
			else
				return NOT_PRIME;
		}
		p = seq.next();
	}
	return IS_PRIME;
}

// Prime generator
BIGINT myGenPrime(int l, BIGINT p = BIGINT(0))
{
	BIGINT n;
	BIGINT a;
	bool Miller_Rabin_test;
	RandomLen(n, l - 1);
	n = 2 * n - 1;
	while (1)
	{
		n = n + 2;
		if (easy_prime_test(n) == NOT_PRIME)
			continue; // 没通过素数检测，重新生成
		Miller_Rabin_test = IS_PRIME;
		for (int i = 1; i <= PRIME_TEST_ROUND; i++)
		{
			RandomBnd(a, n);
			if (Miller_Rabin(n, a) == NOT_PRIME)
			{
				Miller_Rabin_test = NOT_PRIME;
				break; // 没通过素数检测，重新生成
			}
		}
		if (Miller_Rabin_test == IS_PRIME)
		{
			if (n != p) // 通过了素数检测，判断是否是已经生成的素数
				break;
		}
	}
	return n;
}

RSA::Key RSA::KeyGenerator(int key_len)
{
	BIGINT p, q;
	int l;
	try
	{
		if (key_len != PRIME_LEN1 && key_len != PRIME_LEN2)
			throw std::string("key length is not support");
		else
			l = key_len;
	}
	catch (std::string e)
	{
		std::cout << e << std::endl;
	}

	GenPrime(p, l);
	GenPrime(q, l);
	bool flag = Miller_Rabin(p, RandomBnd(p));
	// p = myGenPrime(l);
	// q = myGenPrime(l, p);

	BIGINT phi;
	mul(phi, p - 1, q - 1);

	BIGINT a, b, d;
	do
	{
		RandomBnd(b, phi);
		GCD(d, b, phi);
	} while (b <= 1 || d != 1);

	InvMod(a, b, phi);
	BIGINT n;
	mul(n, p, q);
	RSA::Public_key pub = {n, b};
	RSA::Private_key priv = {p, q, a};
	RSA::Key res;
	res.pub = pub;
	res.priv = priv;
	return res;
}

BIGINT RSA::Encode(Public_key pub, const BIGINT &x)
{
	return PowerMod(x, pub.b, pub.n);
}

BIGINT RSA::Decode(Private_key priv, Public_key pub, const BIGINT &y)
{
	return PowerMod(y, priv.a, pub.n);
}

Signature RSA::Sign(RSA::Private_key priv, RSA::Public_key pub, const std::string &digest)
{
	Signature res;
	BIGINT x = String2BIGINT(digest);
	res = PowerMod(x, priv.a, pub.n);
	return res;
}

bool RSA::Verify(RSA::Public_key pub, Signature s, const std::string &d)
{
	BIGINT digest = String2BIGINT(d);
	BIGINT decoded_digest = PowerMod(s, pub.b, pub.n);
	return (digest == decoded_digest);
}

BIGINT String2BIGINT(const std::string &str)
{
	ZZ number = conv<ZZ>(str[0]);
	long len = str.length();
	for (long i = 1; i < len; i++)
	{
		number *= BASE;
		number += conv<ZZ>(str[i]);
	}

	return number;
}

std::string BIGINT2String(const BIGINT &n)
{
	BIGINT num = n;
	long len = ceil(log(num) / log(BASE));
	std::string str(len, 0);
	for (long i = len - 1; i >= 0; i--)
	{
		str[i] = conv<int>(num % BASE);
		num /= BASE;
	}

	return str;
}

std::ostream &RSA::operator<<(std::ostream &stream, const RSA::Public_key &pub)
{
	stream << pub.n << "\n"
		   << pub.b << "\n";
	return stream;
}

std::ostream &RSA::operator<<(std::ostream &stream, const RSA::Private_key &priv)
{
	stream << priv.p << "\n"
		   << priv.q << "\n"
		   << priv.a << "\n";
	return stream;
}

BIGINT stringstream2BIGINT(std::string str)
{
	BIGINT res(0);
	int len = str.length();
	for (int i = 0; i < len; i++)
	{
		res *= 10;
		res += str[i] - '0';
	}
	return res;
}

std::istream &RSA::operator>>(std::istream &stream, Public_key &pub)
{
	std::string n, b;
	stream >> n >> b;
	// pub.n = String2BIGINT(n);
	// pub.b = String2BIGINT(b);
	pub.n = stringstream2BIGINT(n);
	pub.b = stringstream2BIGINT(b);
	return stream;
}

std::istream &RSA::operator>>(std::istream &stream, RSA::Private_key &priv)
{
	std::string p, q, a;
	stream >> p >> q >> a;
	// priv.p = String2BIGINT(p);
	// priv.q = String2BIGINT(q);
	// priv.a = String2BIGINT(a);
	priv.p = stringstream2BIGINT(p);
	priv.q = stringstream2BIGINT(q);
	priv.a = stringstream2BIGINT(a);
	return stream;
}
