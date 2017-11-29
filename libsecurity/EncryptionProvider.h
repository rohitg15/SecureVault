#include "IEncryptionProvider.h"
#include "VaultException.h"

namespace svsecurity
{    
    class EncryptionProvider : IEncryptionProvider
    {
    public:
        explicit EncryptionProvider(
            const EncryptionAlgorithm& alg
        );
        ~EncryptionProvider();

        void
        InitEncryptor(
            const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& iv
        ) override;

        std::vector<unsigned char>
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