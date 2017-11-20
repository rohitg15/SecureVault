#ifndef _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKWRITER_H_
#define _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKWRITER_H_

#include <string>
#include <fstream>
#include <memory>

class FileChunkWriter {
 public:
    typedef std::unique_ptr<FileChunkWriter> Ptr;
    static const uint32_t CHUNK_MAX_SIZE;    
    FileChunkWriter() {};
    static FileChunkWriter::Ptr GetInstance(const std::string& fileName);
    void WriteNextChunk(const std::string& chunkData);
    void Close();       // it is recommended to call Close explicitly to ensure writeback to the underlying storage
    ~FileChunkWriter();
 private:
    std::string m_fileName;
    std::ofstream m_out;
};

#endif  // _USERS_MORPHEUS_DOCUMENTS_PROGRAMS_CPP_SECUREVAULT_INCLUDE_FILECHUNKWRITER_H_