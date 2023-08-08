#include "User.h"

User::User(const string &path)
{
    root = path;
    cout << "User root is:" << root << endl;
    // RSA::Key key = RSA::KeyGenerator(PRIME_LEN2);
    // pub = key.pub;
    // priv = key.priv;
}

void User::Register(const string &id, CA &ca)
{
    // 保存用户密码
    string account_path = root + "/" + id + ".pwd";
    fstream account(account_path);
    if (account.good())
    {
        cout << "USER EXISTS\n";
        return;
    }
    string pwd;
    account.open(account_path, ios::out);
    cout << "Input the password\n";
    cin >> pwd;
    account << WriteHex(SHA1(pwd, MODE_STRING));
    account.close();
    RSA::Key key = ca.CreateCert(id);
    pub = key.pub;
    priv = key.priv;
    // 生成私钥文件和公钥文件
    string spriv = root + "/" + id + ".priv";
    fstream fpriv(spriv, ios::out | ios::trunc);
    fpriv << priv;
    fpriv.close();
    string spub = root + "/" + id + ".pub";
    fstream fpub(spub, ios::out | ios::trunc);
    fpub << pub;
    fpub.close();
}

bool User::Login(const string &id, const string &pwd)
{
    string account_path = root + "/" + id + ".pwd";
    fstream account;
    string pwd_hash;
    account.open(account_path, ios::in);
    account >> pwd_hash;
    string pwd_hash2 = WriteHex(SHA1(pwd, MODE_STRING));
    if (pwd_hash == pwd_hash2)
    {
        this->id = id;
        return true;
    }
    else
        return false;
}

void User::LoadKey(const string &spriv, const string &spub)
{
    string id;
    string pwd;
    while (1)
    {
        cout << "Input your ID: \n";
        cin >> id;
        cout << "Input your password: \n";
        cin >> pwd;
        if (!Login(id, pwd))
            cout << "ID and Password not matched\n";
        else
            break;
    }
    cout << "Log in: Success\n";
    // string spriv = root + "KEY/" + id + ".priv";
    fstream file;
    file.open(spriv, ios::in);

    file >> priv;
    file.close();
    file.open(spub, ios::in);
    file >> pub;
    file.close();
}

void User::Sign(const string &path)
{
    fstream file;
    string hash = WriteHex(SHA1(path));
    // cout << hash;
    file.open(path, ios::out | ios::app);
    if (!file)
    {
        cout << "No such File" << endl;
        return;
    }
    // cout << pub << endl;
    // cout << priv << endl;
    Signature s = RSA::Sign(priv, pub, hash);
    file << "\nSignature\n"
         << s << "\n"
         << "END";
}

bool User::Verify(const string &path, const string &id, const CA &ca)
{
    if (!VerifyCert(id, ca))
        return false;
    fstream file;
    fstream new_file;
    file.open(path, ios::in);
    new_file.open(path + ".origin", ios::out);
    deque<string> window;
    string line;
    int lines = 0;
    while (getline(file, line))
    {
        lines++;
        window.push_back(line);
        if (window.size() > 3)
        {
            if (lines != 4)
                new_file << endl;
            new_file << window.front();
            // cout << window.front() << std::endl;
            window.pop_front();
        }
    }
    new_file.close();
    window.pop_front();
    string signstr = window.front();
    // cout << signstr << std::endl;
    Signature sign = stringstream2BIGINT(signstr);
    // new_file.close();
    string hash = WriteHex(SHA1(path + ".origin"));
    if (!RSA::Verify(otherpub, sign, hash))
    {
        cout << "Verify the signature: Fail" << endl;
        return false;
    }
    else
        return true;
}

bool User::VerifyCert(const string &id, const CA &ca)
{
    const string cert_path = ca.root + "/" + id + ".cert";
    fstream cert;
    cert.open(cert_path, ios::in);
    stringstream ss;
    string tmp;
    int size = 2056;
    string idInCert;
    cert >> tmp >> idInCert;
    if (idInCert != id)
        return false;

    RSA::Public_key pub;
    cert >> tmp >> pub;
    Signature sign;
    cert >> tmp >> sign;
    ss << "ID\n"
       << idInCert << "\n"
       << "PUBLIC-KEY\n"
       << pub << "\n";
    string hash = WriteHex(SHA1(ss.str(), MODE_STRING));
    if (RSA::Verify(ca.pub, sign, hash))
    {
        otherpub = pub;
        return true;
    }
    else
        return false;
}

void User::Encrypt(const string &path, const string &key, const string &otherid, const CA &ca)
{
    DES::Encode(path, key);
    if (!VerifyCert(otherid, ca))
    {
        cout << "No safe certification" << endl;
        return;
    }
    // todo
    string filepath = root + "/" + otherid + ".PGP";
    fstream file(filepath, ios::out);
    file << RSA::Encode(otherpub, String2BIGINT(key));
    file.close();
}
void User::Decrypt(const string &path)
{
    string filepath = root + "/" + id + ".PGP";
    fstream file(filepath, ios::in);
    BIGINT cipher;
    file >> cipher;
    string key = BIGINT2String(RSA::Decode(priv, pub, cipher));
    DES::Decode(path, key);
    cout << "key is " << key << endl;
}