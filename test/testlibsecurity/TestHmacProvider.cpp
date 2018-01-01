#include "TestHmacProvider.h"
#include "gtest/gtest.h"

    
// using ::testing::Return;

TestHmacProvider::TestHmacProvider()
{
    /* Initialize key lengths  */
    m_hs256SizeBytes = 32;
    m_hs512SizeBytes = 64;

    /* Initialize keys for Hmac */
    m_hs256Key1.resize(m_hs256SizeBytes + 1, '\x1');
    m_hs256Key2.resize(m_hs256SizeBytes + 1, '\x2');
    m_hs512Key1.resize(m_hs512SizeBytes + 1, '\x1');
    m_hs512Key2.resize(m_hs512SizeBytes + 1, '\x2');
}

void
TestHmacProvider::SetUp()
{
    m_mac = new svsecurity::HmacProvider();
    
    /* initialize algorithms */
    m_hs256 = new svsecurity::MacAlgorithm(svsecurity::Algorithm::MacType::HMAC_SHA_256);
    m_hs512 = new svsecurity::MacAlgorithm(svsecurity::Algorithm::MacType::HMAC_SHA_512);
}

void
TestHmacProvider::TearDown()
{
    delete m_hs256;
    delete m_hs512;
    delete m_mac;
}

TestHmacProvider::~TestHmacProvider()
{
}

TEST_F(TestHmacProvider, InitMacThrowsForInvalidKeySize) {
    std::vector<unsigned char> invalidKey(10, '\x1');
    ASSERT_ANY_THROW((m_mac->InitMac(invalidKey, *m_hs512)));
}

TEST_F(TestHmacProvider, UpdateMacThrowsForWrongPayloadSize) {
    m_mac->InitMac(m_hs256Key1, *m_hs256);
    std::vector<unsigned char> payload(100, '\x1');
    ASSERT_ANY_THROW((m_mac->UpdateMac(payload, payload.size() + 10)));
}

TEST_F(TestHmacProvider, GetFinalMacValueIsAlwaysDeterministic) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        mac1 = m_mac->GetFinalMac();
    });

    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        mac2 = m_mac->GetFinalMac();    
    });
    ASSERT_EQ(mac1, mac2);
}

TEST_F(TestHmacProvider, GetFinalMacValueWithMultipleUpdates) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac1 = m_mac->GetFinalMac();        
    });
    
    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac2 = m_mac->GetFinalMac();        
    });
    ASSERT_EQ(mac1, mac2);
}


TEST_F(TestHmacProvider, VerifyMacWithMatchingHs256Macs) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac1 = m_mac->GetFinalMac();        
    });
    
    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac2 = m_mac->GetFinalMac();        
    });
    ASSERT_TRUE(svsecurity::HmacProvider::VerifyMac(mac1, mac2));
}

TEST_F(TestHmacProvider, VerifyMacWithMatchingHs512Macs) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs512Key1, *m_hs512);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac1 = m_mac->GetFinalMac();        
    });
    
    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs512Key1, *m_hs512);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac2 = m_mac->GetFinalMac();        
    });
    ASSERT_TRUE(svsecurity::HmacProvider::VerifyMac(mac1, mac2));
}

TEST_F(TestHmacProvider, VerifyMacWithNonMatchingHs256Macs) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac1 = m_mac->GetFinalMac();        
    });
    
    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key2, *m_hs256);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac2 = m_mac->GetFinalMac();        
    });
    ASSERT_FALSE(svsecurity::HmacProvider::VerifyMac(mac1, mac2));
}

TEST_F(TestHmacProvider, VerifyMacWithNonMatchingHs512Macs) {
    std::vector<unsigned char> payload(100, '\x1');
    payload[payload.size() - 1] = 0;
    std::vector<unsigned char> mac1, mac2;

    /* first round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs512Key1, *m_hs512);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac1 = m_mac->GetFinalMac();        
    });
    
    /* second round */
    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs512Key2, *m_hs512);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 1);
        m_mac->UpdateMac(payload, payload.size() - 25);
        mac2 = m_mac->GetFinalMac();        
    });
    ASSERT_FALSE(svsecurity::HmacProvider::VerifyMac(mac1, mac2));
}

TEST_F(TestHmacProvider, VerifyHmacSha512Length) {
    std::vector<unsigned char> payload(10, '\x1');
    std::vector<unsigned char> mac;

    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs512Key1, *m_hs512);
        m_mac->UpdateMac(payload, payload.size());
        mac = m_mac->GetFinalMac();
    });
    ASSERT_EQ(m_hs512SizeBytes, mac.size());
}

TEST_F(TestHmacProvider, VerifyHmacSha256Length) {
    std::vector<unsigned char> payload(10, '\x1');
    std::vector<unsigned char> mac;

    ASSERT_NO_THROW({
        m_mac->InitMac(m_hs256Key1, *m_hs256);
        m_mac->UpdateMac(payload, payload.size());
        mac = m_mac->GetFinalMac();
    });
    ASSERT_EQ(m_hs256SizeBytes, mac.size());
}