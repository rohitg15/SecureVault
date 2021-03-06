#include "HmacProvider.h"
#include "VaultException.h"
#include <iostream>
#include <string.h>
#include <sstream>

namespace svsecurity
{
    
    HmacProvider::HmacProvider()
    : m_hashLenBytes(0),
      m_hash(NULL)
    {}

    void
    HmacProvider::InitMac(
        const std::vector<unsigned char>& key,
        const MacAlgorithm& alg
        )
    {
        uint32_t keyLen = key.size();
        m_hash = alg.GetHashMethod();
        if ( keyLen != (alg.GetKeySize() >> 3) + 1) /* adding 1 for NULL byte */
        {
            std::stringstream ss;
            ss << "Error in InitMac, invalid key size. Expected key of size " << (alg.GetKeySize() >> 3) + 1 
            << " bytes, got " << keyLen << " bytes";
            throw VaultException("HmacProvider.cpp", "Cryptographic Exception", ss.str().c_str());
        }
        m_hashLenBytes = keyLen;

        HMAC_CTX_init(&m_ctx);
        if ( !HMAC_Init_ex(&m_ctx, key.data(), keyLen, m_hash, NULL) )
        {
            std::stringstream ss;
            ss << "error in HMAC_Init_ex, key size = " << keyLen << std::endl; 
            throw VaultException("HmacProvider.cpp", "Cryptographic Exception", ss.str().c_str());
        }
    }

    void
    HmacProvider::UpdateMac(
        const std::vector<unsigned char>&  payload,
        uint32_t payloadSize
        )
    { 
        if ( payload.size() == 0 || payloadSize > payload.size() )
        {
            std::stringstream ss;
            ss  << "error in HmacProvider::UpdateMac payload's requested size " << payloadSize << " is invalid.";
            throw VaultException("HmacProvider.cpp", "InputRangeException", ss.str().c_str());
        }
        if ( !HMAC_Update(&m_ctx, payload.data(), payloadSize) )
        {
            std::stringstream ss;
            ss  << "error in HmacProvider::UpdateMac Hmac_Update, payload size = " << payloadSize;
            throw VaultException("HmacProvider.cpp", "Cryptographic Exception", ss.str().c_str());
        }
    }

    std::vector<unsigned char>
    HmacProvider::GetFinalMac()
    {
        std::unique_ptr<unsigned char[]> result = std::make_unique<unsigned char[]>(m_hashLenBytes);
        if ( !HMAC_Final(&m_ctx, result.get(), &m_hashLenBytes) )
        {
            /* Is unique_ptr Exception safe? Double Check!!! */
            std::stringstream ss;
            ss << "error in HmacProvider::UpdateMac Hmac_Final, hash size in bytes = " << m_hashLenBytes;
            throw VaultException("HmacProvider.cpp", "Cryptographic Exception", ss.str().c_str());
        }
        std::vector<unsigned char> hashVec;
        for(int i = 0; i < m_hashLenBytes; ++i)
        {
            hashVec.push_back(result[i]);
        }
        return hashVec;
    }

    bool
    HmacProvider::VerifyMac(
        const std::vector<unsigned char>& expMac,
        const std::vector<unsigned char>& realMac
        )
    {
        uint32_t eSize = expMac.size();
        uint32_t rSize = realMac.size();
        uint32_t result = (uint32_t)(eSize ^ rSize);
        
        /* No early exit, to prevent side-channels */
        for (uint32_t i = 0, j = 0; (i < eSize) && (j < rSize); ++i, ++j) 
        {
            result |= (uint32_t)(expMac[i] ^ realMac[j]);
        }
        return (result == 0);
    }

    HmacProvider::~HmacProvider()
    {
       HMAC_CTX_cleanup(&m_ctx); 
    }

} // namespace svsecurity