#pragma once

#include "crypto.h"
#include "CA.h"

#include <deque>
using std::deque;

class User
{
public:
    RSA::Public_key pub;
    string id;

    RSA::Public_key otherpub;

    string root;

private:
    RSA::Private_key priv;

public:
    User() = delete;
    User(const string &);
    // ~User();
    // account
    void Register(const string &, CA &);
    bool Login(const string &, const string &);
    void LoadKey(const string &, const string &);
    // Options
    bool VerifyCert(const string &, const CA &);
    void Sign(const string &);
    bool Verify(const string &, const string &, const CA &);
    void Encrypt(const string &, const string &, const string &, const CA &);
    void Decrypt(const string &);
};