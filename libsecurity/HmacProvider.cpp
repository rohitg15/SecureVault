#include "HmacProvider.h"
#include "VaultException.h"
#include <iostream>
#include <string.h>
#include <sstream>

HmacProvider::HmacProvider()
: m_hashLenBytes(0) {}

void
HmacProvider::InitMac(
    const std::vector<unsigned char>& key,
    const MacAlgorithm& alg
    )
{
    uint32_t keyLen = key.size();
    if ( keyLen != (alg.GetKeySize() >> 3) + 1) /* adding 1 for NULL byte */
    {
        std::stringstream ss;
        ss << "Error in InitMac, invalid key size. Expected key of size " << (alg.GetKeySize() >> 3) 
           << " bytes, got " << keyLen << " bytes";
        throw VaultException("HmacProvider.cpp", "Cryptographic Exception", ss.str().c_str());
    }
    m_hashLenBytes = keyLen;
    HMAC_CTX_init(&m_ctx);
    if ( !HMAC_Init_ex(&m_ctx, key.data(), keyLen, EVP_sha256(), NULL) )
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

    std::vector<unsigned char>::const_iterator eIt = expMac.begin(), rIt = realMac.begin();
    uint32_t result = (expMac.size() ^ realMac.size());

    /* No early exit comparisons, to prevent side-channels */
    while(eIt != expMac.end() && rIt != realMac.end()) 
    {
        result |= (*eIt ^ *rIt) & 0xFF; /* avoid branching */
        ++eIt;
        ++rIt;
    }
    return (result == 0);
}

HmacProvider::~HmacProvider()
{
    HMAC_CTX_cleanup(&m_ctx);
}