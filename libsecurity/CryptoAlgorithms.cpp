#include "CryptoAlgorithms.h"
#include "VaultException.h"

namespace svsecurity
{
    
    MacAlgorithm::MacAlgorithm(
        Algorithm::MacType algType
    )
    {
        switch(algType)
        {
            case Algorithm::MacType::HMAC_SHA_256:
                m_keySize = 256;
                m_hash = EVP_sha256();
                break;
            default:
                m_keySize = 512;
                m_hash = EVP_sha512();
                break;
        }
    }

    uint32_t
    MacAlgorithm::GetKeySize() const
    {
        return m_keySize;
    }

    const EVP_MD*
    MacAlgorithm::GetHashMethod() const
    {
        return m_hash;
    }

    EncryptionAlgorithm::EncryptionAlgorithm(
        Algorithm::EncType algType
    ) : m_cipherType(nullptr)
    {
        switch(algType)
        {
            case Algorithm::EncType::AES_CBC_256:
                m_keySize = 256;
                m_isBlockCipher = true;
                m_blockSize = 128;
                m_ivSize = 128;
                m_cipherType = EVP_aes_256_cbc();
                break;

            case Algorithm::EncType::AES_CTR_256:
                m_keySize = 256;
                m_isBlockCipher = false;
                m_blockSize = 0; /* CTR mode behaves like a stream cipher */
                m_ivSize = 128;
                m_cipherType = EVP_aes_256_ctr();
                break;

            default:
                const char* msg = "Unrecognized cryptographic Encryption algorithm type specified";
                throw VaultException("CryptoAlgorithms.cpp", msg, msg);
                break;
        }
    }

    uint32_t
    EncryptionAlgorithm::GetKeySize() const
    {
        return m_keySize;
    }

    uint32_t
    EncryptionAlgorithm::GetIvSize() const
    {
        return m_ivSize;
    }

    uint32_t
    EncryptionAlgorithm::GetBlockSize() const
    {
        if ( !m_isBlockCipher )
        {
            const char *msg = "BlockSize is undefined for stream ciphers";
            throw VaultException("CryptoAlgorithms.cpp", msg, msg );
        }
        return m_blockSize;
    }

    bool
    EncryptionAlgorithm::IsBlockCipher() const
    {
        return m_isBlockCipher;
    }

} // namespace svsecurity