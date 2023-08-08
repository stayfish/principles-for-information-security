#include "CA.h"

CA::CA(const string &dir)
{
    root = dir;
    cout << "CA root is: " << root << endl;
    string ppriv = root + "/KEY.priv";
    string ppub = root + "/KEY.pub";
    fstream fpriv, fpub;
    fpriv.open(ppriv, ios::in);
    fpub.open(ppub, ios::in);
    if (!fpriv || !fpub)
    {
        RSA::Key key = RSA::KeyGenerator(PRIME_LEN2);
        pub = key.pub;
        priv = key.priv;
        fpriv.open(ppriv, ios::out);
        fpub.open(ppub, ios::out);
        fpriv << priv;
        fpub << pub;
    }
    else
    {
        std::cout << "CA FILE EXISTS" << std::endl;
        fpriv >> priv;
        fpub >> pub;
    }

    // cout << "CA pub is:" << pub << endl;

    // std::cout << priv << std::endl
    //           << pub << std::endl;

    fpriv.close();
    fpub.close();
}

// 创建证书的时候，需要输入用户名和密码，输入后用哈希加密后保存好密码文件
// 证书格式
// ID
// ID 内容
// PUBLIC-KEY
// 公钥内容
// SIGNATURE
// 签名内容
// END
RSA::Key CA::CreateCert(const string &id)
{
    RSA::Key key = RSA::KeyGenerator(PRIME_LEN2);
    // 保存证书
    const string cert_path = root + "/" + id + ".cert";
    fstream cert;
    cert.open(cert_path, ios::out);
    cert << "ID\n"
         << id << "\n"
         << "PUBLIC-KEY\n"
         << key.pub << "\n";
    cert.close();
    string hash = WriteHex(SHA1(cert_path));
    cert.open(cert_path, ios::out | ios::app);
    cert << "SIGNATURE\n"
         << RSA::Sign(priv, pub, hash) << "\n"
         << "END";
    // 保存公钥和私钥
    return key;
}

// bool CA::VerifyCert(const string &id)
// {
//     const string cert_path = root + "CERT/" + id + ".cert";
//     fstream cert;
//     cert.open(cert_path, ios::in);
//     stringstream ss;
//     string tmp;
//     int size = 2056;
//     string idInCert;
//     // getline(cert, tmp, '\n');
//     // getline(cert, idInCert, '\n');
//     cert >> tmp >> idInCert;
//     if (idInCert != id)
//         return false;

//     RSA::Public_key pub;
//     // getline(cert, tmp, '\n');
//     // getline(cert, pub, '\n');
//     cert >> tmp >> pub;
//     Signature sign;
//     // getline(cert, tmp, '\n');
//     // getline(cert, sign, '\n');
//     cert >> tmp >> sign;
//     ss << "ID\n"
//        << idInCert << "\n"
//        << "PUBLIC-KEY\n"
//        << pub << "\n";
//     string hash = WriteHex(SHA1(ss.str(), MODE_STRING));
//     return RSA::Verify(this->pub, sign, hash);
// }
