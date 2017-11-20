#ifndef _LIBSECURITY_MACALGORITHM_H_
#define _LIBSECURITY_MACALGORITHM_H_

#include "Global.h"
#include <stdlib.h>

class MacAlgorithm
{
public:
    MacAlgorithm(
        CryptoAlgorithm::MacType algType
    );

    uint32_t
    GetKeySize() const;

private:
    uint32_t m_keySize;
};

#endif // _LIBSECURITY_MACALGORITHM_H_