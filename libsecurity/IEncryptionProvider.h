#ifndef _LIBSECURITY_ENCRYPTIONPROVIDER_H_
#define _LIBSECURITY_ENCRYPTIONPROVIDER_H_

#include <memory>
#include <vector>
#include "CryptoAlgorithms.h"

namespace svsecurity
{        
    class IEncryptionProvider {
    public:
        typedef std::unique_ptr<IEncryptionProvider> Ptr;

        virtual
        ~IEncryptionProvider(); /* This class is Polymorphic */

        virtual
        void
        InitEncryptor(
            const std::vector<unsigned char>& key, /* Expected to have extra NULL byte */
            const std::vector<unsigned char>& iv
        ) = 0;

        virtual
        void
        UpdateEncryptor(
            const std::vector<unsigned char>& payload, /* Expected to have extra NULL byte */
            uint32_t payloadLen
        ) = 0;

        virtual
        std::vector<unsigned char>
        GetFinalCiphertext() = 0;
    };
} // namespace svsecurity

#endif  // _LIBSECURITY_ENCRYPTIONPROVIDER_H_
