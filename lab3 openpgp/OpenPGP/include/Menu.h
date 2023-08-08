#pragma once

#include <iostream>
#include <string>
#include "CA.h"
#include "User.h"
using std::cin;
using std::cout;
using std::endl;
using std::string;

const enum STATUS {
    START,
    MENU,
    REG,
    LOGIN,
    VC,
    SIGN,
    VS,
    EN,
    DE,
    QUIT,
    ILLEGAL
};

class Menu
{
public:
    Menu();
    ~Menu();
    bool FA(STATUS);
    void Start();

private:
    CA *ca;
    User *user;
    STATUS status;
    bool isLogin;
    string rca;
    string ruser;
};