cmake_minimum_required(VERSION 3.22)
include(ExternalProject)

project(console_app)

set(CMAKE_CXX_STANDARD 20)

ExternalProject_Add(CryptoPP
        GIT_REPOSITORY  https://github.com/weidai11/cryptopp
        GIT_TAG         CRYPTOPP_8_9_0
        CONFIGURE_COMMAND ""
        BUILD_COMMAND   make -j12 -C <SOURCE_DIR>
        INSTALL_COMMAND make install -C <SOURCE_DIR> PREFIX=<INSTALL_DIR>
        PREFIX          ${CMAKE_BINARY_DIR}/external
)


add_executable(console_app main.cpp)

ExternalProject_Get_Property(CryptoPP INSTALL_DIR)
target_include_directories(console_app PRIVATE ${INSTALL_DIR}/include)
target_link_libraries(console_app PRIVATE ${INSTALL_DIR}/lib/libcryptopp.a)
add_dependencies(console_app CryptoPP)