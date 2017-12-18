file(GLOB SRCS *.cpp)


add_executable(testlibsecurity ${SRCS})

# Include references to and link with openssl
include_directories("/usr/local/opt/openssl/include/")

link_libraries("-lcrypto")

target_link_libraries(testlibsecurity
    libsecurity
    ${OPENSSL_CRYPTO_LIBRARY}
    libgtest
    libgmock
)

install(TARGETS testlibsecurity DESTINATION bin)