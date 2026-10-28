
include(cmake/get_cpm.cmake)

if (HIDI_SSL_LIBRARY STREQUAL "aws-lc")
  # AWS-LC: OpenSSL-совместимый API (libssl / libcrypto), сборка через CMake с ассемблером,
  # Perl и Go при сборке не нужны.
  # small-aws-lc - AWS-LC без тестов и утилит (~50 МБ вместо ~300 МБ), одна ветка: неглубокий клон ~8 МБ
  CPMAddPackage(
    NAME AWSLC
    GITHUB_REPOSITORY kelbon/small-aws-lc
    GIT_TAG v5.12.0-2
    GIT_SHALLOW TRUE
    OPTIONS "BUILD_TESTING OFF"
            "BUILD_TOOL OFF"
            "DISABLE_GO ON"
            "DISABLE_PERL ON"
    EXCLUDE_FROM_ALL YES
    SYSTEM OFF
  )

  # Boost.Context (зависимость Boost.Asio, hidi его не использует) на Windows собирается из ассемблера в
  # файлах .asm, как и AWS-LC (NASM). Расширение -> язык в CMake одно на весь проект, и последний включённый
  # язык ассемблера забирает .asm себе, ломая сборку другого (CMAKE_ASM_COMPILE_OBJECT not set).
  # Реализация на Windows fibers ассемблер не требует
  if (WIN32)
    set(BOOST_CONTEXT_IMPLEMENTATION winfib CACHE STRING "Boost.Context implementation (fcontext, ucontext, winfib)")
  endif()
elseif (HIDI_SSL_LIBRARY STREQUAL "openssl")
  CPMAddPackage(
    NAME OPENSSL
    GITHUB_REPOSITORY janbar/openssl-cmake
    GIT_TAG 1.1.1w-20231130
    OPTIONS "WITH_APPS OFF"
    EXCLUDE_FROM_ALL YES
    SYSTEM OFF
  )
else()
  message(FATAL_ERROR "HIDI_SSL_LIBRARY must be aws-lc or openssl, got: '${HIDI_SSL_LIBRARY}'")
endif()

CPMAddPackage(
  NAME KELCORO
  GIT_REPOSITORY https://github.com/kelbon/kelcoro
  GIT_TAG v1.4.7
  OPTIONS "KELCORO_ENABLE_TESTING OFF"
)

CPMAddPackage(
  NAME ANYANY
  GIT_REPOSITORY https://github.com/kelbon/AnyAny
  GIT_TAG v1.3.0
  OPTIONS "AA_ENABLE_TESTING OFF"
)

# BEFORE hpack, so dependency with name 'Boost' will contain
# both intrusive required for HPACK and other deps, required for HTTP/2
# process and stacktrace required only for tests, so user-library may not download it
set(BOOST_INCLUDE_LIBRARIES intrusive system smart_ptr asio process stacktrace)
CPMAddPackage(
  NAME BOOST
  VERSION 1.87.0
  URL https://github.com/boostorg/boost/releases/download/boost-1.87.0/boost-1.87.0-cmake.tar.xz
  OPTIONS "BOOST_ENABLE_CMAKE ON"
)
unset(BOOST_INCLUDE_LIBRARIES)

CPMAddPackage(
  NAME HPACK
  GITHUB_REPOSITORY kelbon/HPACK
  GIT_TAG         v1.2.0
  OPTIONS "HPACK_ENABLE_TESTING OFF"
          "HPACK_USE_CPM OFF"
)

CPMAddPackage(
  NAME LOGIC_GUARDS
  GITHUB_REPOSITORY kelbon/logic_guards
  GIT_TAG        v1.0.0
  OPTIONS "ZAL_ENABLE_TESTING OFF"
)

find_package(Threads REQUIRED)

CPMAddPackage(
  NAME STRSWITCH
  GITHUB_REPOSITORY kelbon/strswitch
  GIT_TAG        v1.1.1
  OPTIONS "STRSWITCH_ENABLE_TESTING OFF"
)

CPMAddPackage(
  NAME CCOZY
  GITHUB_REPOSITORY kelbon/ccozy
  GIT_TAG v0.8.2
)

if (HIDI_ENABLE_TESTING)
  CPMAddPackage(
    NAME MOKO3
    GITHUB_REPOSITORY kelbon/moko3
    GIT_TAG v0.10.2
  )
endif()

include(${CCOZY_SOURCE_DIR}/ccozy_tools.cmake)
