#ifndef _LIBIO_FILECHUNKREADER_H_
#define _LIBIO_FILECHUNKREADER_H_

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

#endif  // _LIBIO_FILECHUNKREADER_H_
