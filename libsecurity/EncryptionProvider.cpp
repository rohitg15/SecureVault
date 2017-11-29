#include "EncryptionProvider.h"
#include "CryptoAlgorithms.h"
#include <sstream>

namespace svsecurity
{
    
    EncryptionProvider::EncryptionProvider(
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

    EncryptionProvider::~EncryptionProvider()
    {
        EVP_CIPHER_CTX_cleanup(&m_ctx);
    }

    void
    EncryptionProvider::InitEncryptor(
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

    std::vector<unsigned char>
    EncryptionProvider::UpdateEncryptor(
        const std::vector<unsigned char>& payload,
        uint32_t payloadSize
    )
    {
        if ( payloadSize > payload.size() )
        {
            std::stringstream ss;
            ss << "Invalid payload length in argument " << payloadSize << " is > " << payload.size();
            throw VaultException("AesProvider.cpp", "Invalid Length specified", ss.str().c_str());
        }
        int ciphertextMaxSize = payloadSize + m_blockSize - 1; /* Account for padding */
        int outBytes = 0;
        std::vector<unsigned char> ciphertext(ciphertextMaxSize, 0x0);
        if ( EVP_EncryptUpdate(&m_ctx,ciphertext.data(), &outBytes,
                                payload.data(), payloadSize) != 1 )
        {
            /* 
             * Exception is only for logging. Application must NOT expose this
             * to users as it could lead to padding oracle attacks.
             */
          throw VaultException("AesProvider.cpp", "Cryptographic Exception", "EVP_EncryptUpdate failed!");
        }

        /* Remove unused padding bytes */
        for(int i = outBytes; i < ciphertextMaxSize; ++i)
        {
            ciphertext.pop_back();
        }
        return ciphertext;
    }

    std::vector<unsigned char>
    EncryptionProvider::GetFinalCiphertext()
    {
        int outBytes = 0;
        std::vector<unsigned char> ciphertext(m_blockSize, 0x0); /* Returns atmost blockSize bytes */
        if ( EVP_EncryptFinal_ex(&m_ctx, ciphertext.data(), &outBytes) != 1 )
        {
            /*
             *  The exception here is for logging, debugging purposes only.
             *  It must not be returned back to the user as it could lead to padding
             *  oracle attacks against CBC mode.
             */
            throw VaultException("AesProvider.cpp", "Cryptographic Exception", "EVP_EncryptFinal_ex failed!");
        }
        return ciphertext;
    }

}