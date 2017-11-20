#include "FileChunkReader.h"
#include <vector>
#include <algorithm>

const uint32_t FileChunkReader::CHUNK_MAX_SIZE = 4096;

FileChunkReader::FileChunkReader(
    const std::string& fileName
    )
{
    m_fileName = fileName;
    m_in.open(m_fileName, std::ios::in | std::ios::binary);
}

std::streamsize
FileChunkReader::ReadNextChunk(
    uint32_t chunkSize,
    std::vector<unsigned char>& chunkData
    )
{
    uint32_t chunkMinSize = std::min(chunkSize, FileChunkReader::CHUNK_MAX_SIZE);
    m_in.read((char*)chunkData.data(), chunkMinSize);
    return m_in.gcount();
}

bool
FileChunkReader::IsEof()
{
    return m_in.eof();
}

FileChunkReader::~FileChunkReader() 
{
    if (m_in.is_open()) {
        m_in.close();
        /* handle error in close() */
    }
}