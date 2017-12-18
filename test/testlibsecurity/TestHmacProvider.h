#ifndef _TEST_TESTHMACPROVIDER_H_
#define _TEST_TESTHMACPROVIDER_H_

#include "gtest/gtest.h"
#include <vector>
#include <HmacProvider.h>
#include <CryptoAlgorithms.h>

    
class TestHmacProvider : public ::testing::Test {

protected:

    // You can do set-up work for each test here.
    TestHmacProvider();

    // You can do clean-up work that doesn't throw exceptions here.
    virtual ~TestHmacProvider();

    
    // Code here will be called immediately after the constructor (right
    // before each test).
    virtual void SetUp() override;

    // Code here will be called immediately after each test (right
    // before the destructor).
    virtual void TearDown() override;

    int m_hs256SizeBytes, m_hs512SizeBytes;
    std::vector<unsigned char> m_hs256Key1, m_hs256Key2, m_hs512Key1, m_hs512Key2;
    svsecurity::MacAlgorithm *m_hs256, *m_hs512;
    svsecurity::MacProvider *m_mac;
    
};

#endif 