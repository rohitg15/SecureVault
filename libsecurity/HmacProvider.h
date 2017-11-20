#ifndef _LIBSECURITY_HMACPROVIDER_H_
#define _LIBSECURITY_HMACPROVIDER_H_

#include "MacProvider.h"
#include <vector>
#include <openssl/hmac.h>

class HmacProvider : public MacProvider {
 public:
    HmacProvider();
    ~HmacProvider();
    
    void
    InitMac(
        const std::vector<unsigned char>& key,
        const MacAlgorithm& alg
        ) override;

    void
    UpdateMac(
        const std::vector<unsigned char>& payload,
        uint32_t payloadLen
        ) override;

    std::vector<unsigned char>
    GetFinalMac() override;

    virtual
    bool
    VerifyMac(
        const std::vector<unsigned char>& expMac,
        const std::vector<unsigned char>& realMac
    ) override;
    
 private:
    static const uint32_t HMAC_SHA256_KEY_LEN_BYTES = 32;
    HMAC_CTX m_ctx;
    uint32_t m_hashLenBytes;
};

#endif  // _LIBSECURITY_HMACPROVIDER_H_

