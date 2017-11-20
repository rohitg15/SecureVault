#ifndef _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_ENCRYPTIONPROVIDER_H_
#define _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_ENCRYPTIONPROVIDER_H_

#include <memory>
#include <vector>

class EncryptionProvider {
 public:
    typedef std::unique_ptr<EncryptionProvider> Ptr;
    virtual std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& iv) = 0;
    virtual std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv) = 0;
};

#endif  // _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_ENCRYPTIONPROVIDER_H_
