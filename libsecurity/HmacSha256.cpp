#include "HmacSha256.h"
#include "VaultException.h"
#include <iostream>
#include <string.h>
#include <sstream>

HmacSha256::HmacSha256()
: m_hashLenBytes(0) {}

void
HmacSha256::InitMac(
    const std::vector<unsigned char>& key,
    uint32_t keyLen = 0
    )
{
    //std::cout << "hmac key strlen : " << strlen((const char*)key) << std::endl;
    if (keyLen != HmacSha256::HMAC_SHA256_KEY_LEN_BYTES)
    {
        /* Log error message in logfile and exit */
    
    }
    m_hashLenBytes = keyLen;
    HMAC_CTX_init(&m_ctx);
    if ( !HMAC_Init_ex(&m_ctx, key.data(), keyLen, EVP_sha256(), NULL) )
    {
        std::stringstream ss;
        ss << "error in HMAC_Init_ex, key size = " << keyLen << std::endl; 
        throw VaultException("HmacSha256.cpp", "Cryptographic Exception", ss.str().c_str());
    }
}

void
HmacSha256::UpdateMac(
    const std::vector<unsigned char>&  payload,
    uint32_t payloadSize
    )
{ 
    if ( !HMAC_Update(&m_ctx, payload.data(), payloadSize) )
    {
        std::stringstream ss;
        ss  << "error in HmacSha256::UpdateMac Hmac_Update, payload size = " << payloadSize;
        throw VaultException("HmacSha256.cpp", "Cryptographic Exception", ss.str().c_str());
    }
}

std::vector<unsigned char>
HmacSha256::GetFinalMac()
{
    std::unique_ptr<unsigned char[]> result = std::make_unique<unsigned char[]>(m_hashLenBytes);
    if ( !HMAC_Final(&m_ctx, result.get(), &m_hashLenBytes) )
    {
        /* Is unique_ptr Exception safe? Double Check!!! */
        std::stringstream ss;
        ss << "error in HmacSha256::UpdateMac Hmac_Final, hash size in bytes = " << m_hashLenBytes;
        throw VaultException("HmacSha256.cpp", "Cryptographic Exception", ss.str().c_str());
    }
    std::vector<unsigned char> hashVec;
    for(int i = 0; i < m_hashLenBytes; ++i)
    {
        hashVec.push_back(result[i]);
    }
    return hashVec;
}

bool
HmacSha256::VerifyMac(
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

HmacSha256::~HmacSha256()
{
    HMAC_CTX_cleanup(&m_ctx);
}