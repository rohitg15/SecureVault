#include "AesProvider.h"
#include "CryptoAlgorithms.h"

namespace svsecurity
{
    
    AesProvider::AesProvider(
        const EncryptionAlgorithm& alg
    ) 
    {
        m_keySize = alg.GetKeySize();
        m_ivSize = alg.GetIvSize();
        m_isBlockCipher = alg.IsBlockCipher();
        if ( m_isBlockCipher )
        {
            m_blockSize = alg.GetBlockSize();    
        }
        else
        {
            m_blockSize = 0; /* undefined for stream ciphers */
        }
    }

    AesProvider::~AesProvider()
    {
        EVP_CIPHER_CTX_cleanup(&m_ctx);
    }

    void
    AesProvider::InitEncryptor(
        const std::vector<unsigned char>& key,
        const std::vector<unsigned char>& iv
    )
    {
        EVP_CIPHER_CTX_init(&m_ctx);
        if ( !EVP_EncryptInit(&m_ctx, m_cipherType,
                                key.data(), iv.data()) 
            )
            {
                /* m_ctx must be cleaned */
                const char* msg = "EVP_EncryptInit_ex failed";
                throw VaultException("AesProvider.cpp", "Cryptographic Exception", msg );
            }
    }

    void
    AesProvider::UpdateEncryptor(
        const std::vector<unsigned char>& payload,
        uint32_t payloadSize
    )
    {
        if (m_isBlockCipher) /* check padding */
        {
            payloadSize = 1;
        }
    }

    std::vector<unsigned char>
    GetFinalCiphertext()
    {
        std::vector<unsigned char> ciphertext;
        return ciphertext;
    }

}