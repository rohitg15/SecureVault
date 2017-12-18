#ifndef _LIBEXCEPTION_VAULTEXCEPTION_H_
#define _LIBEXCEPTION_VAULTEXCEPTION_H_

#include <stdexcept>
#include <string>

class VaultException : public std::runtime_error
{
public:
    VaultException(
        const char* fileName,
        const char* logMsg,
        const char* debugMsg
    );

    ~VaultException() throw();

    std::string
    GetLogMessage();

    std::string
    GetVerboseError() const;

private:
    std::string m_debugMsg;
    std::string m_logMsg;
    std::string m_fileName;
};

#endif // _LIBEXCEPTION_VAULTEXCEPTION_H_