#include "FileChunkWriter.h"


const uint32_t FileChunkWriter::CHUNK_MAX_SIZE = 4096;

FileChunkWriter::Ptr 
FileChunkWriter::GetInstance(
    const std::string& fileName
    ) 
{
    FileChunkWriter::Ptr filePtr = std::make_unique<FileChunkWriter>();
    filePtr->m_fileName = fileName;
    filePtr->m_out.open(filePtr->m_fileName, std::ios::out | std::ios::binary);
    return filePtr;
}

void
FileChunkWriter::WriteNextChunk(
    const std::string& chunkData
    ) 
{
    m_out.write(chunkData.c_str(), chunkData.size());
}

void
FileChunkWriter::Close() 
{
    if (m_out.is_open()) {
        m_out.close();
    }
}

FileChunkWriter::~FileChunkWriter() 
{
    Close();
}