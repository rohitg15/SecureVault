set(Main_SRCS
    main.cpp
)


add_compile_options("-g")
add_compile_options("-std=c++14")


add_executable(myApp
    ${Main_SRCS}
)

find_package(openssl)
include_directories(${OPENSSL_INCLUDE_DIR})

#link_libraries("-lcrypto")
#add_subdirectory("/usr/local/opt/openssl/lib/")
# Specify here the libraries this program depends on
target_link_libraries(myApp
    libsecurity
    ${OPENSSL_CRYPTO_LIBRARY}
    libio
    libexception
)

install(TARGETS myApp DESTINATION bin)
