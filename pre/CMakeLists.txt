cmake_minimum_required(VERSION 2.8)
project(relic_hom)

INCLUDE_DIRECTORIES(/usr/local/include)

find_library(RELIC_LOC relic PATHS /usr/local/lib)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-omit-frame-pointer -std=c++11 -o2" )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -g -Wall -march=native -Wl,-rpath=/usr/local/lib -o2")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../bin )
set(SOURCE_FILES keygen.c encryption.c encoding.c utils.c pre-afgh-relic.h)

add_library(pre-afgh-relic SHARED ${SOURCE_FILES})

add_executable(test_pre test.cpp ${SOURCE_FILES})
add_executable(benchmark_pre benchmark.cpp ${SOURCE_FILES})

target_link_libraries(relic_pre ${RELIC_LOC})
target_link_libraries(relic_pre_re_enc_benchmark ${RELIC_LOC})
