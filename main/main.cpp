#include <iostream>
#include <memory>
#include <string.h>
#include "FileChunkReader.h"
#include "FileChunkWriter.h"
#include "HmacProvider.h"



int main(int argc, char **argv)
{
    
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " input_file output_file" << std::endl;
        return -1;
    }


    FileChunkReader::Ptr inFilePtr = std::make_unique<FileChunkReader>(argv[1]);
    FileChunkWriter::Ptr outFilePtr = FileChunkWriter::GetInstance(argv[2]);
    size_t chunkSize = 64;
    std::string data = "";
    
    size_t hmacKeyLen = 32;
    std::vector<unsigned char> hmacKey(hmacKeyLen + 1, 0x01);
    hmacKey[hmacKeyLen] = 0x0;
    MacProvider::Ptr pHmac = std::make_unique<HmacProvider>();
    MacAlgorithm alg(CryptoAlgorithm::MacType::HMAC_SHA_256);
    pHmac->InitMac(hmacKey, alg);
    
    std::vector<unsigned char> chunkVec(chunkSize + 1, 0);
    while ( !inFilePtr->IsEof() ) {
        int readBytes = inFilePtr->ReadNextChunk(chunkSize, chunkVec);
        if (readBytes > 0)
        {
            pHmac->UpdateMac(chunkVec, readBytes);
            std::fill(chunkVec.begin(), chunkVec.end(), 0);
        }
    }
    
    std::vector<unsigned char> mac = pHmac->GetFinalMac();
    for(unsigned char c : mac)
    {
        printf("%02x", c);
    }
    std::cout << std::endl;
    outFilePtr->Close();
    return 0;
}