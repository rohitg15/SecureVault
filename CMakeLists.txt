cmake_minimum_required(VERSION 2.8)
#cmake_minimum_required(VERSION 3.9.4)
project(myProject)

enable_testing()


add_compile_options("-g")
add_compile_options("-std=c++14")



add_subdirectory(main)
add_subdirectory(libsecurity)
add_subdirectory(libio)
add_subdirectory(libexception)
add_subdirectory(test)
