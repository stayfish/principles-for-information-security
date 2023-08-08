#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include <iomanip>
using namespace std;
#include "crypto.h"
#include "User.h"
#include "CA.h"
#include "Menu.h"

string root = "D:\\workspace\\course\\信息安全原理\\assignment\\openpgp\\OpenPGP\\data\\";

void RSA_test()
{
    RSA::Key key = RSA::KeyGenerator(1024);
    // BIGINT encode = RSA::Encode(key.pub, ZZ(1953246));
    // std::cout << Decode(key.priv, key.pub, encode) << std::endl;
}

void Sign_test()
{
    RSA::Key key = RSA::KeyGenerator(1024);
    // BIGINT test(1953246);
    // std::string test_str = BIGINT2String(test);
    // std::cout << test_str << std::endl;
    // std::cout << String2BIGINT(test_str) << std::endl;
    // std::string str = "abc";
    // Signature s = RSA::Sign(key.priv, key.pub, str);
    // std::cout << RSA::Verify(key.pub, s, str) << std::endl;
    // str[0] = 'm';
    // std::cout << RSA::Verify(key.pub, s, str) << std::endl;
}

void SHA_test()
{
    RSA::Key key = RSA::KeyGenerator(1024);
    string path = "../../data/test.txt";
    bitset<160> sha1 = SHA1(path);
    cout << WriteHex(sha1) << endl;
}

void SHA_test2()
{
    RSA::Key key = RSA::KeyGenerator(1024);
    string str = "123456";
    cout << WriteHex(SHA1(str, MODE_STRING)) << endl;
}

void User_Sign_test()
{
    string path = "../../data/test.txt";
    User user("1953246");
    user.Sign(path);
}

void CA_test()
{
    string rca = root + "CA/";
    string rdb = root + "USER/";
    string id = "1953246";
    CA ca(rca);

    User user(rdb);
    user.Register(id, ca);
    // cout << user.Login(id, "123456") << endl;
    // cout << user.Login(id, "012345") << endl;
    // cout << user.VerifyCert(id, ca) << endl;
    string path = root + "test.txt";
    string spub = rdb + "KEY\\" + id + ".pub";
    string spriv = rdb + "KEY\\" + id + ".priv";
    // user.LoadKey(spriv, spub);
    // cout << user.Login(id, "123456") << endl;
    // user.Sign(path);
    cout << user.Verify(path, id, ca);
    cout << "test end" << endl;
}

void DES_test()
{
    string key = "12345678";
    // string message = "1953246 ";
    string path = root + "test.txt";
    string path1 = root + "test2.txt";
    ofstream file(path1, ios::out | ios::binary);
    unsigned char ch = 0xee;
    file.put(ch);

    int choice;
    cin >> choice;
    if (choice == 1)
        DES::Encode(path, key);
    else
        DES::Decode(path, key);
}

void crypt_test()
{
    string r = "D:\\workspace\\course\\test\\";
    CA ca(r + "CA");
    User user(r + "USER");
    cout << user.VerifyCert("1953245", ca) << endl;
    user.LoadKey("D:\\workspace\\1953246.priv", "D:\\workspace\\1953246.pub");
    user.Sign("D:\\workspace\\test.txt");
    user.Encrypt("D:\\workspace\\test.txt", "key88888", "1953245", ca);
    user.LoadKey("D:\\workspace\\1953245.priv", "D:\\workspace\\1953245.pub");
    user.Decrypt("D:\\workspace\\test.txt");
    user.Verify("D:\\workspace\\test.txt.DES", "1953246", ca);
}

int main()
{
    // SHA_test();
    // SHA_test2();
    // User_Sign_test();
    // CA_test();
    // DES_test();
    Menu menu;
    menu.Start();
    // crypt_test();
}
