project(EncProt)
cmake_minimum_required(VERSION 3.4)

#USED TO GENERATE __decl_spec(dllexport/dllimport) for MSVC compiler
set (CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS TRUE)

set (ARCH "x86_64" CACHE FILEPATH "Sets the architecture, default 64bit")

set (SOURCES
    src/main.cpp
    src/encprot.h
    src/encprot.cpp
    src/encfile.cpp
    src/libdef.h
)

if (UNIX AND NOT APPLE)
        set (LIBS
            ssl
            crypto
        )
    set (OS LINUX)
endif()
if(WIN32)
    set (LIBS
        libcrypto.lib
        libssl.lib)
    set (OS WIN32)
endif()

link_directories(${CMAKE_SOURCE_DIR}/lib/${ARCH}/${OS})
include_directories(${CMAKE_SOURCE_DIR}/include/EncProt ${CMAKE_SOURCE_DIR}/include)


add_library(${PROJECT_NAME} SHARED ${SOURCES})

target_link_libraries(${PROJECT_NAME} ${LIBS})
