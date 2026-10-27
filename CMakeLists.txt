
cmake_minimum_required(VERSION 3.20)
project(hidi)

option(HIDI_ENABLE_TESTING  "Set to ON to enable tests"      OFF)
option(HIDI_USE_CPM "Set to ON to enable use CPM for get dependencies" ON)
option(HIDI_ENABLE_SANITIZERS "build with sanitizers" OFF)

# file for storing SSL keys, useful for debugging SSL connection via Wireshark. Disabled by default
set(HIDI_DEBUG_SSL_KEYS_FILE "" CACHE FILEPATH "")

if (HIDI_DEBUG_SSL_KEYS_FILE)
  message(STATUS "Debug SSL keys storing enabled, HIDI_DEBUG_SSL_KEYS_FILE = ${HIDI_DEBUG_SSL_KEYS_FILE}")
endif()

if (HIDI_ENABLE_SANITIZERS)
  # enable sanitize flags globally, all targets require to be compiled with them

  # fno omit frame pointer to improve trace from sanitizers
  add_compile_options(-fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address -fsanitize=undefined)

endif()

if (HIDI_USE_CPM)
  include(cmake/deps.cmake)
endif()

add_library(hidilib ${CMAKE_CURRENT_SOURCE_DIR}/src/http_base.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2client.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/request_context.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/memory_queue.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/buffered_connection.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2protocol.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2connection.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2connection_establishment.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2send_frames.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2server_reader.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2writer.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2server_session.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/h2server.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/asio/timer.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/utils/unique_name.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/asio/io_impl.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/asio/io.cpp
                  ${CMAKE_CURRENT_SOURCE_DIR}/src/asio/ssl_context.cpp
            )

target_include_directories(hidilib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries(hidilib PUBLIC
    ${CMAKE_THREAD_LIBS_INIT}
    ssl crypto
    anyanylib
    kelcorolib
    hpacklib
    zallib
    strswitchlib
    Boost::stacktrace
    Boost::intrusive
    Boost::smart_ptr
    Boost::asio
)
target_compile_definitions(hidilib PUBLIC -DOPENSSL_API_COMPAT=0x30000000L)

if (HIDI_DEBUG_SSL_KEYS_FILE)
   target_compile_definitions(hidilib PRIVATE "HIDI_DEBUG_SSL_KEYS_FILE=${HIDI_DEBUG_SSL_KEYS_FILE}")
endif()

set_target_properties(hidilib PROPERTIES
	CMAKE_CXX_EXTENSIONS OFF
	LINKER_LANGUAGE CXX
	CMAKE_CXX_STANDARD_REQUIRED ON
	CXX_STANDARD 20)

if (WIN32)
    if (NOT DEFINED HIDI_WINDOWS_VERSION) 
        set(HIDI_WINDOWS_VERSION 0x0A00 CACHE STRING "windows version for boost asio")
    endif()
    target_compile_definitions(hidilib PUBLIC _WIN32_WINNT=${HIDI_WINDOWS_VERSION})
endif()

if (HIDI_ENABLE_TESTING)
    include(CTest)
    add_subdirectory(tests)
endif()

ccozy_on_configuration_end_vscode()
