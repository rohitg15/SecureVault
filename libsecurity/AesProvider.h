#include "IEncryptionProvider.h"
#include "VaultException.h"

namespace svsecurity
{    
    class AesProvider : IEncryptionProvider
    {
    public:
        AesProvider(
            const EncryptionAlgorithm& alg
        );
        ~AesProvider();

        void
        InitEncryptor(
            const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& iv
        ) override;

        void
        UpdateEncryptor(
            const std::vector<unsigned char>& payload,
            uint32_t payloadSize
        ) override;

        std::vector<unsigned char>
        GetFinalCiphertext() override;

    private:
        EVP_CIPHER_CTX m_ctx;
        uint32_t m_keySize, m_ivSize, m_blockSize;
        bool m_isBlockCipher;
        const EVP_CIPHER* m_cipherType;
    };

}