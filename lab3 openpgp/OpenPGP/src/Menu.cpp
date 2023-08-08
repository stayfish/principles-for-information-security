#include "Menu.h"
#include <conio.h>

Menu::Menu()
{
    ca = nullptr;
    user = nullptr;
    isLogin = false;
}
Menu::~Menu()
{
    delete ca;
    delete user;
}

void wait()
{
    cout << "Press any key to continue" << endl;
    // cin.ignore();
    getch();
}

bool Menu::FA(STATUS s)
{
    string line(20, '-');
    string inputid("Input your id");
    string id;
    string path;
    string spriv, spub;
    string key;
    switch (s)
    {
    case START:
        cout << "Input the root directory for CA (ascii support only)\nMake Sure root dir exists" << endl;
        cin >> rca;
        cout << "Input the root directory for USER (ascii support only)\nMake Sure root dir exists" << endl;
        cin >> ruser;
        ca = new CA(rca);
        user = new User(ruser);
        status = MENU;
        break;
    case MENU:
        cout << line << endl;
        cout << "1. Sign up" << endl;
        cout << "2. Sign in" << endl;
        cout << "3. Verify the Certificate" << endl;
        cout << "4. Sign the file" << endl;
        cout << "5. Verify the signature" << endl;
        cout << "6. Encrypt" << endl;
        cout << "7. Decrypt" << endl;
        cout << "8. Quit" << endl;
        cout << line << endl;
        cout << "Input your option(1-8):";
        int state;
        cin >> state;
        cout << endl;
        if (state >= 1 && state <= 8)
        {
            if (isLogin || (state == 1) || (state == 2) || (state == 8))
                status = static_cast<STATUS>(state + 1);
            else
            {
                cout << "Sign in First!" << endl;
                status = MENU;
            }
        }
        else
            status = ILLEGAL;
        break;
    case REG:
        cout << inputid << endl;
        cin >> id;
        user->Register(id, *ca);
        cout << "REG: Success" << endl;
        wait();
        status = MENU;
        break;
    case LOGIN:
        cout << "Input the path for Private Key (ASCII only)" << endl;
        cin >> spriv;
        cout << "Input the path for Public Key (ASCII only)" << endl;
        cin >> spub;
        cout << "Loading...." << endl;
        user->LoadKey(spriv, spub);
        cout << "Done" << endl;
        isLogin = true;
        wait();
        status = MENU;
        break;
    case VC:
        cout << "Input the ID needs verified: ";
        cin >> id;
        cout << endl;
        if (user->VerifyCert(id, *ca))
            cout << "Verify: Success" << endl;
        else
            cout << "Verify: Fail" << endl;
        status = MENU;
        wait();
        break;
    case SIGN:
        cout << "Input the path" << endl;
        cin >> path;
        cout << endl;
        user->Sign(path);
        status = MENU;
        wait();
        break;
    case VS:
        cout << "Input the path" << endl;
        cin >> path;
        cout << endl;
        cout << "Input the ID needs verified: ";
        cin >> id;
        cout << endl;
        if (user->Verify(path, id, *ca))
            cout << "Verify: Success" << endl;
        else
            cout << "Verify: Fail" << endl;
        status = MENU;
        wait();
        break;
    case EN:
        cout << "Input the path" << endl;
        cin >> path;
        cout << endl;
        cout << "Input the key for encryption(8 BITS):";
        cin >> key;
        cout << endl;
        cout << "Input the ID of receiver:";
        cin >> id;
        cout << endl;
        user->Encrypt(path, key, id, *ca);
        status = MENU;
        wait();
        break;
    case DE:
        cout << "Input the path" << endl;
        cin >> path;
        cout << endl;
        user->Decrypt(path);
        status = MENU;
        wait();
        break;
    case QUIT:
        cout << "Exit...." << endl;
        break;
    default:
        cout << "illegal input" << endl;
        status = MENU;
        break;
    }
    return !(status == QUIT);
}

void Menu::Start()
{
    cout << "OpenPGP System" << endl;
    cout << "author: 1953246 Fang Ruo yu" << endl;
    wait();
    status = START;
    while (FA(status))
        ;
}
