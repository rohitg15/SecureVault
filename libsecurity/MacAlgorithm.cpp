#include "MacAlgorithm.h"
#include "VaultException.h"

MacAlgorithm::MacAlgorithm(
    CryptoAlgorithm::MacType algType
)
{
    switch(algType)
    {
        case CryptoAlgorithm::MacType::HMAC_SHA_256:
            m_keySize = 256;
            break;
        case CryptoAlgorithm::MacType::HMAC_SHA_512:
            m_keySize = 512;
            break;
        default:
            const char* msg = "Unrecognized cryptographic MAC algorithm type specified";
            throw VaultException("SymmetricAlgorithm.cpp", msg, msg);
    }
}

uint32_t
MacAlgorithm::GetKeySize() const
{
    return m_keySize;
}
