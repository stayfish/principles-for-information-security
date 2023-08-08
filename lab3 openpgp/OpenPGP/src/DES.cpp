#include "DES.h"

BitStream::BitStream()
{
    arr = NULL;
    len = 0;
}

void BitStream::Init(int l)
{
    len = l;
    arr = new BIT[len]();
}

BitStream::BitStream(int l)
{
    len = l;
    arr = new BIT[len]();
}

BitStream::BitStream(const string &str)
{
    len = str.length() * 8;
    arr = new BIT[len];
    for (int i = 0; i < str.length(); i++)
    {
        char cur = str[i];
        for (int j = 0; j < 8; j++)
        {
            arr[i * 8 + j] = (cur >> (7 - j)) & 1;
        }
    }
}

BitStream::~BitStream()
{
    delete[] arr;
}

BIT &BitStream::operator[](int idx)
{
    return arr[idx];
}

void BitStream::operator=(BitStream &bs)
{
    if (this->len != bs.len)
        cout << "length not matched in =\n";
    for (int i = 0; i < this->len; i++)
        this->arr[i] = bs[i];
}

int BitStream::length() { return len; }

void BitStream::XOR(BitStream &K)
{
    if (len != K.length())
        cout << "length not matched in XOR\n";
    for (int i = 0; i < len; i++)
        arr[i] = arr[i] ^ K[i];
}

void BitStream::SLR(int num)
{
    while (num < 0)
        num += len;
    int n = num % len;
    if (num == 0)
        return;
    BitStream tmp(n);
    for (int i = 0; i < n; i++)
        tmp[i] = arr[i];
    for (int i = 0; i < len - n; i++)
        arr[i] = arr[i + 1];
    for (int i = 0; i < n; i++)
        arr[len - n + i] = tmp[i];
}

string BitStream::toStr()
{
    if (len % 8 != 0)
        cout << "illegal length in toStr\n";
    int l = len / 8;
    string res(l, 0);
    for (int i = 0; i < l; i++)
    {
        unsigned char cur = 0;
        for (int j = 0; j < 8; j++)
        {
            cur = (cur << 1) + arr[i * 8 + j];
        }
        res[i] = cur;
    }
    return res;
}

void Permutation(BitStream &out, BitStream &in, const int table[], int len)
{
    int l = in.length();
    if (out.length() != len)
    {
        cout << "length not matched in Permutation\n";
    }
    for (int i = 0; i < len; i++)
    {
        int idx = table[i] - 1;
        out[i] = in[idx];
    }
}

void Sbox(BitStream &out, BitStream &in)
{
    if (out.length() != 32 || in.length() != 48)
        cout << "illegal length in SBOX\n";
    for (int i = 0; i < 8; i++)
    {
        int row, col;
        row = (in[i * 6] << 1) | (in[i * 6 + 5]);
        col = (in[i * 6 + 1] << 3) | (in[i * 6 + 2] << 2) | (in[i * 6 + 3] << 1) | (in[i * 6 + 4]);
        int svalue = DES::S[i][row][col];
        for (int j = 0; j < 4; j++)
            out[i * 4 + j] = (svalue >> (3 - j)) & 1;
    }
}

void f(BitStream &R, BitStream &K)
{
    if (R.length() != 32 || K.length() != 48)
        cout << "illegal length in f\n";
    // 扩展为 48 位
    BitStream ER(48);
    Permutation(ER, R, DES::Expand, 48);
    // 和密钥异或
    ER.XOR(K);
    // S 盒，放在 R 中
    BitStream after_S(32);
    Sbox(after_S, ER);
    Permutation(R, after_S, DES::P, 32);
}

string DesEncode(const string &in_str, const string &k_str)
{
    if (in_str.length() != 8 || k_str.length() != 8)
        cout << "illegal length in Decode\n";
    BitStream k(k_str);
    BitStream in(in_str);
    BitStream in_after_ip(64);
    BitStream L(32), R(32);
    BitStream tmp(32);
    // subkey
    BitStream key[DES::ROUND];
    BitStream C(28), D(28), CD(56);
    Permutation(CD, k, DES::PC1, 56);
    for (int i = 0; i < 56; i++)
    {
        if (i < 28)
            C[i] = CD[i];
        else
            C[i - 28] = CD[i];
    }
    for (int i = 0; i < DES::ROUND; i++)
    {
        key[i].Init(48);
        C.SLR(DES::left[i]);
        D.SLR(DES::left[i]);
        for (int i = 0; i < 56; i++)
        {
            if (i < 28)
                CD[i] = C[i];
            else
                CD[i] = D[i - 28];
        }
        Permutation(key[i], CD, DES::PC2, 48);
    }
    // IP
    Permutation(in_after_ip, in, DES::IP, 64);
    // L R
    for (int i = 0; i < 64; i++)
    {
        if (i < 32)
            L[i] = in_after_ip[i];
        else
            R[i - 32] = in_after_ip[i];
    }

    for (int i = 0; i < DES::ROUND; i++)
    {
        // input of the loop: Ri, Ki
        tmp = R;
        f(R, key[i]);
        L.XOR(R);
        R = L;
        L = tmp;
        // output of the loop: R(i+1), L(i+1)
    }
    BitStream round_out(64);
    for (int i = 0; i < 64; i++)
    {
        if (i < 32)
            round_out[i] = R[i];
        else
            round_out[i] = L[i - 32];
    }
    BitStream out(64);
    Permutation(out, round_out, DES::IPinv, 64);
    return out.toStr();
}

string DesDecode(const string &in_str, const string &k_str)
{
    if (in_str.length() != 8 || k_str.length() != 8)
        cout << "illegal length in Decode\n";
    BitStream k(k_str);
    BitStream in(in_str);
    BitStream in_after_ip(64);
    BitStream L(32), R(32);
    BitStream tmp(32);
    // subkey
    BitStream key[DES::ROUND];
    BitStream C(28), D(28), CD(56);
    Permutation(CD, k, DES::PC1, 56);
    for (int i = 0; i < 56; i++)
    {
        if (i < 28)
            C[i] = CD[i];
        else
            C[i - 28] = CD[i];
    }
    for (int i = 0; i < DES::ROUND; i++)
    {
        key[i].Init(48);
        C.SLR(DES::left[i]);
        D.SLR(DES::left[i]);
        for (int i = 0; i < 56; i++)
        {
            if (i < 28)
                CD[i] = C[i];
            else
                CD[i] = D[i - 28];
        }
        Permutation(key[i], CD, DES::PC2, 48);
    }
    // IP
    Permutation(in_after_ip, in, DES::IP, 64);
    // L R
    for (int i = 0; i < 64; i++)
    {
        if (i < 32)
            L[i] = in_after_ip[i];
        else
            R[i - 32] = in_after_ip[i];
    }

    for (int i = 0; i < DES::ROUND; i++)
    {
        // input of the loop: Ri, Ki
        tmp = R;
        f(R, key[DES::ROUND - i - 1]);
        L.XOR(R);
        R = L;
        L = tmp;
        // output of the loop: R(i+1), L(i+1)
    }
    BitStream round_out(64);
    for (int i = 0; i < 64; i++)
    {
        if (i < 32)
            round_out[i] = R[i];
        else
            round_out[i] = L[i - 32];
    }
    BitStream out(64);
    Permutation(out, round_out, DES::IPinv, 64);
    return out.toStr();
}

string ReadStream(istream &stream)
{
    // 读 64 bit，即 8 字节
    string res;
    char cur;
    int count = 0;
    while (1)
    {
        cur = stream.get();
        if (stream.eof())
            break;
        res.push_back(cur);
        count++;
        if (count >= 8)
            break;
    }
    return res;
}

void DES::Encode(const string &path, const string &key)
{
    fstream file;
    streampos pr = ios::beg;
    streampos pw = ios::beg;
    bool isLast = false;
    int padding = 0;
    while (1)
    {
        file.open(path, ios::in | ios::out | ios::binary);
        file.seekg(pr);
        string str = ReadStream(file);
        pr = file.tellg();
        int l = str.length();
        if (l == 0)
            return;
        if (l != 8)
        {
            char ch = 0;
            while (l != 8)
            {
                str.push_back(ch);
                l++;
                padding++;
            }
            isLast = true;
        }
        string code = DesEncode(str, key);
        if (isLast)
        {
            file.close();
            file.open(path, ios::in | ios::out);
            file.seekg(0, ios::end);
            streampos size = file.tellg();
            file.seekp(size - streampos(8 - padding));
            file << code;
            return;
        }
        else
        {
            file.seekp(pw);
            file << code;
            pw = file.tellp();
            file.close();
        }
    }
}

#include <conio.h>

void DES::Decode(const string &path, const string &key)
{
    fstream file;
    fstream newfile;

    streampos pr = ios::beg;
    streampos pw = ios::beg;
    bool isLast = false;
    int padding = 0;
    newfile.open(path + "-DES.txt", ios::out | ios::in);
    while (1)
    {
        file.open(path, ios::in | ios::out | ios::binary);
        file.seekg(pr);
        string str = ReadStream(file);
        pr = file.tellg();
        int l = str.length();
        if (l == 0)
            return;
        string code = DesDecode(str, key);
        for (int i = 7; i >= 0; i--)
        {
            if (code[i] == 0)
            {
                isLast = true;
                padding++;
            }
            else
                break;
        }

        if (isLast)
        {
            // file.seekp(pw);
            // for (int i = 0; i < 8 - padding; i++)
            // file.put(code[i]);
            // newfile.seekp(pw);
            // newfile << code;
            // newfile.close();
            for (int i = 0; i < 8 - padding; i++)
            {
                if (code[i] != '\r')
                    newfile << code[i];
            }
            file.close();
            // file.write("", padding);
            return;
        }
        else
        {
            for (int i = 0; i < 8; i++)
            {
                if (code[i] != '\r')
                    newfile << code[i];
            }
            // file.seekp(pw);
            // file << code;
            // newfile.seekp(pw);
            // newfile << code;
            // cout << "START"
            //      << "\n"
            //      << code << "\n";
            // for (int i = 0; i < code.length(); i++)
            // {
            //     cout << (int)code[i] << ' ';
            // }
            // cout << "\n";
            // pw = newfile.tellp();
            // cout << "pw: " << pw << '\n';
            // newfile.close();
            // getch();
            // pw = file.tellp();
            file.close();
        }
    }
}