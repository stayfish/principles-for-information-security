#pragma once
#include "crypto.h"

#include <iostream>
#include <sstream>
#include <string>

class CA
{
public:
    RSA::Public_key pub;
    string root;

private:
    RSA::Private_key priv;

public:
    CA() = delete;
    CA(const string &);

    RSA::Key CreateCert(const string &);
    // bool VerifyCert(const string &);
};