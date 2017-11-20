set(libio_SRCS
    FileChunkReader.h
    FileChunkWriter.h
    FileChunkReader.cpp
    FileChunkWriter.cpp
)

# Declare the library
add_library(libio STATIC
    ${libio_SRCS}
)

target_link_libraries(libio
    libexception
)

# Specify here the include directories exported
# by this library
target_include_directories(libio PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
