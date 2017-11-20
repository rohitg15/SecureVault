#include "VaultException.h"
#include <sstream>


VaultException::VaultException(
    const char* fileName,
    const char* logMsg,
    const char* debugMsg
    ) : std::runtime_error(logMsg),
        m_fileName(fileName),
        m_logMsg(logMsg),
        m_debugMsg(debugMsg)
{}

std::string
VaultException::GetLogMessage()
{
    return m_logMsg;
}

std::string
VaultException::GetVerboseError()
{
    std::stringstream ss;
    ss << "[ " << m_fileName << " ]" << m_logMsg << " . " << m_debugMsg;
    return ss.str();
}

VaultException::~VaultException() throw() 
{}

