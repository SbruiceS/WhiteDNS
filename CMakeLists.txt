cmake_minimum_required(VERSION 3.10)

project(WhiteDNS LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find jsoncpp package
find_package(jsoncpp CONFIG REQUIRED)
if(NOT jsoncpp_FOUND)
  find_package(jsoncpp REQUIRED)
endif()

# Source files
set(SOURCES WhiteDNS.cpp PortScanner.cpp)

add_executable(whitedns ${SOURCES})


# Link jsoncpp
target_link_libraries(whitedns PRIVATE jsoncpp_lib)

# Link resolv library on Unix-like systems
if(UNIX)
  target_link_libraries(whitedns PRIVATE resolv)
endif()

# Installation rules
install(TARGETS whitedns
  RUNTIME DESTINATION bin
)

# Optionally add a 'make install' step for Windows (using CPack or other)
