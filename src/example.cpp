#include <iostream>
#include "eccfrog512.h"

int main() {
    try {
        ECCFrog512 ecc;

        std::cout << "===== EECCFrog512 Key Generation =====\n\n";

        std::cout << "[Private Key (k)]\n" << ecc.getHex(ecc.getPrivateKey()) << "\n\n";

        std::cout << "[Public Key Q]\n";
        std::cout << "Qx: " << ecc.getPublicKeyX() << "\n";
        std::cout << "Qy: " << ecc.getPublicKeyY() << "\n\n";

        std::cout << "[Base Point G]\n";
        std::cout << "Gx: " << ecc.getBasePointX() << "\n";
        std::cout << "Gy: " << ecc.getBasePointY() << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
