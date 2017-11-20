#ifndef _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_HMACSHA256_H_
#define _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_HMACSHA256_H_

#include "MacProvider.h"
#include <vector>
#include <openssl/hmac.h>

class HmacSha256 : public MacProvider {
 public:
    HmacSha256();
    ~HmacSha256();
    
    void
    InitMac(
        const std::vector<unsigned char>& key,
        uint32_t keyLenBytes
        );

    void
    UpdateMac(
        const std::vector<unsigned char>& payload,
        uint32_t payloadLen
        );

    std::vector<unsigned char>
    GetFinalMac();

    virtual
    bool
    VerifyMac(
        const std::vector<unsigned char>& expMac,
        const std::vector<unsigned char>& realMac
    );
    
 private:
    static const uint32_t HMAC_SHA256_KEY_LEN_BYTES = 32;
    HMAC_CTX m_ctx;
    uint32_t m_hashLenBytes;
};

#endif  // _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_HMACSHA256_H_

