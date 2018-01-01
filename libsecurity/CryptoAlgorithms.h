#ifndef _LIBSECURITY_CRYPTOALGORITHMS_H_
#define _LIBSECURITY_CRYPTOALGORITHMS_H_

// #include "Global.h"
#include <stdlib.h>
#include <openssl/evp.h>

namespace svsecurity
{
    class Algorithm
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

    class MacAlgorithm
    {
    public:
        MacAlgorithm(
            Algorithm::MacType algType
        );

        uint32_t
        GetKeySize() const;

        const EVP_MD*
        GetHashMethod() const;

    private:
        uint32_t m_keySize;
        const EVP_MD* m_hash;
    };

    class EncryptionAlgorithm
    {
    public:
        EncryptionAlgorithm(
            Algorithm::EncType algType
        );

        uint32_t
        GetKeySize() const;

        uint32_t
        GetIvSize() const;

        uint32_t
        GetBlockSize() const;

        bool
        IsBlockCipher() const;

        /*
            Add methods for Padding mode
        */

    private:
        uint32_t m_keySize;
        uint32_t m_blockSize;
        uint32_t m_ivSize;
        bool m_isBlockCipher;
        const EVP_CIPHER* m_cipherType;
    };

} // namespace svsecurity

#endif // _LIBSECURITY_CRYPTOALGORITHMS_H_