cmake_minimum_required(VERSION 3.10)
project(leptjson C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -Wall -Werror -Wno-unused-function")

add_library(leptjson STATIC leptjson.c)
add_executable(test test.c)
target_link_libraries(test leptjson)
