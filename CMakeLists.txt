cmake_minimum_required(VERSION 3.16)

project(WhiteDNS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(WHITEDNS_ENABLE_NETWORK_TESTS "Enable live DNS smoke tests against public domains" OFF)

add_executable(whitedns
  src/main.cpp
  src/DnsClient.cpp
  src/Analyzer.cpp
  src/PortScanner.cpp
  src/SubdomainScanner.cpp
  src/HttpScanner.cpp
  src/FrameworkAudit.cpp
  src/Dnssec.cpp
  src/core/Wire.cpp
  src/core/Transport.cpp
  src/core/ResolverEngine.cpp
  src/core/DohClient.cpp
  src/core/Odoh.cpp
  src/core/OdohFilter.cpp
  src/core/OdohPolicy.cpp
  src/core/OdohLeakModels.cpp
  src/core/ResolverIntel.cpp
  src/core/DnssecPath.cpp
  src/core/PoisonClassifier.cpp
  src/core/ThreatEngine.cpp
  src/core/FaultReport.cpp
  src/core/VendorControls.cpp
  src/core/Intelligence.cpp
  src/core/ProtocolEngine.cpp
)

target_include_directories(whitedns PRIVATE include)

option(WHITEDNS_RELEASE "Require OpenSSL for a release build" OFF)
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR WHITEDNS_RELEASE)
  find_package(OpenSSL REQUIRED)
else()
  find_package(OpenSSL)
endif()
if(OpenSSL_FOUND)
  message(STATUS "WhiteDNS: OpenSSL ${OPENSSL_VERSION} linked for DNSSEC and ODoH.")
  target_link_libraries(whitedns PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(whitedns PRIVATE WHITEDNS_HAVE_OPENSSL)
else()
  message(WARNING "WhiteDNS: OpenSSL not found. Debug build continues. A Release build requires it. Install libssl-dev, openssl-dev, or openssl-devel and reconfigure.")
endif()

add_executable(whitedns_test_wire tests/test_wire.cpp src/core/Wire.cpp src/DnsClient.cpp)
target_include_directories(whitedns_test_wire PRIVATE include)

add_executable(whitedns_test_odoh tests/test_odoh.cpp src/core/Odoh.cpp src/core/Wire.cpp src/DnsClient.cpp)
target_include_directories(whitedns_test_odoh PRIVATE include)
if(OpenSSL_FOUND)
  target_link_libraries(whitedns_test_odoh PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  target_compile_definitions(whitedns_test_odoh PRIVATE WHITEDNS_HAVE_OPENSSL)
endif()

if(WIN32)
  target_link_libraries(whitedns PRIVATE ws2_32 winhttp)
endif()

install(TARGETS whitedns RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
  add_test(NAME whitedns_help COMMAND whitedns -h)
  add_test(NAME whitedns_wire COMMAND whitedns_test_wire)
  add_test(NAME whitedns_odoh COMMAND whitedns_test_odoh)

  if(WHITEDNS_ENABLE_NETWORK_TESTS)
    foreach(domain IN ITEMS google.com facebook.com microsoft.com)
      add_test(
        NAME "whitedns_live_${domain}"
        COMMAND whitedns -j -r -n -w -x -t A,AAAA,NS,MX,TXT ${domain}
      )
    endforeach()
  endif()
endif()
