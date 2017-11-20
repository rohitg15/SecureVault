#ifndef _LIBSECURITY_GLOBAL_H_
#define _LIBSECURITY_GLOBAL_H_

enum e_HmacType
{
    HMACSHA256,
    HMACSHA512
};


class CryptoAlgorithm
{
public:
    
    enum class MacType
    {
        HMAC_SHA_256,
        HMAC_SHA_512,
    };

    enum class EncType
    {
        AES_CBC_256,
        AES_CTR_256
    };

};


#endif  // _LIBSECURITY_GLOBAL_H_
