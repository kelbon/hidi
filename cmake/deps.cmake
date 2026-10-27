
include(cmake/get_cpm.cmake)

CPMAddPackage(
  NAME OPENSSL
  GITHUB_REPOSITORY janbar/openssl-cmake
  GIT_TAG 1.1.1w-20231130
  OPTIONS "WITH_APPS OFF"
  EXCLUDE_FROM_ALL YES
  SYSTEM OFF
)

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
