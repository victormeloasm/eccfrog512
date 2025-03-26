#include "eccfrog512.h"
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>

ECCFrog512::ECCFrog512() {
    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    // Primo de 512 bits fornecido pelo usuário
    p = BN_new();
    BN_dec2bn(&p, "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042159");

    // Coeficiente a = -3
    a = BN_new();
    BN_set_word(a, 3);
    BN_set_negative(a, 1);

    // Coeficiente b = SHA256("EECCFrog512 forever") mod p
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)"EECCFrog512 forever", 22, hash);
    b = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, b);
    BN_mod(b, b, p, ctx);

    // Cria grupo com a curva sobre Fp
    group = EC_GROUP_new_curve_GFp(p, a, b, ctx);

    // Gera ponto base G aleatório
    G = generateBasePoint();
    EC_GROUP_set_generator(group, G, BN_value_one(), BN_value_one());

    // Gera chave privada
    privKey = secureRandomBN(p);

    // Calcula chave pública: Q = privKey * G
    pubKey = EC_POINT_new(group);
    EC_POINT_mul(group, pubKey, privKey, NULL, NULL, ctx);
}

ECCFrog512::~ECCFrog512() {
    EC_POINT_free(G);
    EC_POINT_free(pubKey);
    EC_GROUP_free(group);
    BN_free(privKey);
    BN_free(a);
    BN_free(b);
    BN_free(p);
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
}

BIGNUM* ECCFrog512::secureRandomBN(const BIGNUM* max) {
    BIGNUM* rnd = BN_new();
    do {
        unsigned char buf[64];
        RAND_bytes(buf, sizeof(buf));
        BN_bin2bn(buf, sizeof(buf), rnd);
        BN_mod(rnd, rnd, max, ctx);
    } while (BN_is_zero(rnd));
    return rnd;
}

EC_POINT* ECCFrog512::generateBasePoint() {
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT* point = EC_POINT_new(group);

    while (true) {
        BN_rand_range(x, p);
        BIGNUM* rhs = BN_new();
        BIGNUM* x3 = BN_new();
        BN_mod_sqr(rhs, x, p, ctx);
        BN_mod_mul(x3, rhs, x, p, ctx); // x^3
        BN_mod_mul(rhs, a, x, p, ctx);  // ax
        BN_mod_add(rhs, rhs, b, p, ctx);
        BN_mod_add(rhs, rhs, x3, p, ctx); // x^3 + ax + b

        if (BN_mod_sqrt(y, rhs, p, ctx)) {
            EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
            if (EC_POINT_is_on_curve(group, point, ctx)) {
                BN_free(rhs);
                BN_free(x3);
                BN_free(x);
                BN_free(y);
                return point;
            }
        }
        BN_free(rhs);
        BN_free(x3);
    }
}

const BIGNUM* ECCFrog512::getPrivateKey() const { return privKey; }
const EC_POINT* ECCFrog512::getPublicKey() const { return pubKey; }
const EC_POINT* ECCFrog512::getBasePoint() const { return G; }

std::string ECCFrog512::getHex(const BIGNUM* bn) const {
    char* hex = BN_bn2hex(bn);
    std::string s(hex);
    OPENSSL_free(hex);
    return s;
}

std::string ECCFrog512::getPublicKeyX() const {
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pubKey, x, y, ctx);
    std::string result = getHex(x);
    BN_free(x); BN_free(y);
    return result;
}

std::string ECCFrog512::getPublicKeyY() const {
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, pubKey, x, y, ctx);
    std::string result = getHex(y);
    BN_free(x); BN_free(y);
    return result;
}

std::string ECCFrog512::getBasePointX() const {
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, G, x, y, ctx);
    std::string result = getHex(x);
    BN_free(x); BN_free(y);
    return result;
}

std::string ECCFrog512::getBasePointY() const {
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates_GFp(group, G, x, y, ctx);
    std::string result = getHex(y);
    BN_free(x); BN_free(y);
    return result;
}
