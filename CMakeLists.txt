cmake_minimum_required(VERSION 2.8)
project(relic_hom)

INCLUDE_DIRECTORIES(/usr/local/include)

find_library(RELIC_LOC relic PATHS /usr/local/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -std=c++11 -o2" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -g -Wall -march=native -Wl,-rpath=/usr/local/lib -o2")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin )

set(SOURCE_FILES main.cpp pre-hom.c pre-hom.h)
add_executable(relic_hom ${SOURCE_FILES})

target_link_libraries(relic_hom ${RELIC_LOC})
