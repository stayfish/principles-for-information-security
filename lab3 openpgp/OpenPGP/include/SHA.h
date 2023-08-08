#pragma once
#include <fstream>
#include <iostream>
#include <vector>
#include <bitset>
#include <istream>
#include <sstream>
using namespace std;
const int MODE_FILE = 1;
const int MODE_STRING = 2;
bitset<160> SHA1(const string &, int mode = MODE_FILE);
// bitset<160> SHA1str(const string &);
// string bitset2String(bitset<160>);
string WriteHex(const bitset<160> &);

const int WORD_LEN = 32;
typedef bitset<32> WORD;
// #ifdef TEST
// string readfile(ifstream& f);
// #endif // test
