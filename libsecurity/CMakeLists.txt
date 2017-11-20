set(libsecurity_SRCS
    Global.h
    MacProvider.h
    HmacSha256.h
    HmacSha256.cpp
    EncryptionProvider.h
)


# Include references to and link with openssl
include_directories("/usr/local/opt/openssl/include/")

# Declare the library
add_library(libsecurity STATIC
    ${libsecurity_SRCS}
)

link_libraries("-lcrypto")


target_link_libraries(libsecurity
    libexception
)


# Specify here the include directories exported
# by this library
target_include_directories(libsecurity PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
