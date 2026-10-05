cmake_minimum_required(VERSION 3.24)
project(fidolizer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Debug or Release" FORCE)
endif()

if(APPLE AND NOT OPENSSL_ROOT_DIR AND EXISTS "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib")
  set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3" CACHE PATH "Homebrew OpenSSL" FORCE)
endif()

find_package(OpenSSL 3 REQUIRED)
find_package(Threads REQUIRED)

add_library(fidolizer_core
  src/cbor.cpp
  src/crypto.cpp
  src/store.cpp
  src/authenticator.cpp
  src/ctaphid.cpp
  src/presence.cpp
  src/transport.cpp
  src/json.cpp
  src/webauthn.cpp
)
target_include_directories(fidolizer_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(fidolizer_core PUBLIC OpenSSL::Crypto Threads::Threads)
target_compile_options(fidolizer_core PRIVATE -Wall -Wextra -Wpedantic)

if(APPLE)
  target_sources(fidolizer_core PRIVATE src/hid_macos.mm src/presence_mac.mm)
  target_link_libraries(fidolizer_core PUBLIC "-framework CoreFoundation" "-framework IOKit" "-framework AppKit")
  set_source_files_properties(src/hid_macos.mm PROPERTIES COMPILE_FLAGS "-fno-objc-arc")
  set_source_files_properties(src/presence_mac.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc")
elseif(UNIX)
  target_sources(fidolizer_core PRIVATE src/hid_linux.cpp)
else()
  message(FATAL_ERROR "fidolizer supports macOS and Linux")
endif()

add_executable(fidolizer src/main.cpp)
target_link_libraries(fidolizer PRIVATE fidolizer_core)
target_compile_options(fidolizer PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(fidolizer_tests tests/test_authenticator.cpp)
target_link_libraries(fidolizer_tests PRIVATE fidolizer_core)
target_compile_options(fidolizer_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME authenticator COMMAND fidolizer_tests)

include(GNUInstallDirs)
install(TARGETS fidolizer RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(PROGRAMS extension/fidolizer-webauthn DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES cmake/fidolizer.entitlements DESTINATION "${CMAKE_INSTALL_DATADIR}/fidolizer")
install(DIRECTORY extension/
        DESTINATION "${CMAKE_INSTALL_DATADIR}/fidolizer/extension"
        PATTERN "fidolizer-webauthn" EXCLUDE
        PATTERN "*.test.js" EXCLUDE)

add_custom_target(uninstall
  COMMAND "${CMAKE_COMMAND}" -E rm -f "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/fidolizer"
  COMMAND "${CMAKE_COMMAND}" -E rm -f "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/fidolizer-webauthn"
  COMMAND "${CMAKE_COMMAND}" -E rm -rf
          "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/fidolizer"
  COMMENT "Removing installed fidolizer files"
)
