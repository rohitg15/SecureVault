set(libexception_SRCS
    VaultException.h
    VaultException.cpp
)

# Declare the library
add_library(libexception STATIC
    ${libexception_SRCS}
)

# Specify here the include directories exported
# by this library
target_include_directories(libexception PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
