#ifndef _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKREADER_H_
#define _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKREADER_H_

#include <string>
#include <fstream>
#include <vector>
#include <memory>

class FileChunkReader {
 public:
    typedef std::unique_ptr<FileChunkReader> Ptr;
    static const uint32_t CHUNK_MAX_SIZE;    

    FileChunkReader(
        const std::string& fileName
        );
    ~FileChunkReader();
    
    std::streamsize
    ReadNextChunk(
        uint32_t chunkSize,
        std::vector<unsigned char>& chunkData
        );
        
    bool
    IsEof();
 private:
    std::string m_fileName;
    std::ifstream m_in;
};

#endif  // _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKREADER_H_
