#ifndef _LIBSECURITY_MACPROVIDER_H_
#define _LIBSECURITY_MACPROVIDER_H_


#include <memory>
#include <vector>
#include "CryptoAlgorithms.h"

namespace svsecurity
{
    

    class MacProvider {
    public:
        typedef std::unique_ptr<MacProvider> Ptr;
        virtual
        ~MacProvider() {}; /* This class is Polymorphic, virtual destructor is needed for cleaning up unique_ptr */

        virtual
        void
        InitMac(
            const std::vector<unsigned char>& key,
            const MacAlgorithm& alg
            ) = 0;

        virtual
        void
        UpdateMac(
            const std::vector<unsigned char>& payload,
            uint32_t payloadLen
            ) = 0;

        virtual
        std::vector<unsigned char>
        GetFinalMac() = 0; 

        virtual
        bool
        VerifyMac(
            const std::vector<unsigned char>& expMac,
            const std::vector<unsigned char>& realMac
            ) = 0;
    };

} //  namespace svsecurity

#endif  // _LIBSECURITY_MACPROVIDER_H_
