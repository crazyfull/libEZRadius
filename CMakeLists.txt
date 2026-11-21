cmake_minimum_required(VERSION 3.14)

project(libEZRadius
    VERSION 2.0.0
    DESCRIPTION "Asynchronous RADIUS client / server / CoA library on netRector"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(EZRADIUS_BUILD_EXAMPLES "Build the example programs" ON)
option(EZRADIUS_BUILD_TESTS "Build the tests" ON)
option(EZRADIUS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)

# netRector (https://github.com/crazyfull/netRector):
#   -DEZRADIUS_NETRECTOR_DIR=/path/to/netRector   (source tree, built together)
# or a netRector target / package that already exists in the parent project.
set(EZRADIUS_NETRECTOR_DIR "" CACHE PATH "netRector source directory")
option(EZRADIUS_FETCH_NETRECTOR "Download netRector with FetchContent when it is not found" OFF)
if(NOT TARGET netRector)
    if(EZRADIUS_NETRECTOR_DIR)
        set(NETRECTOR_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        add_subdirectory(${EZRADIUS_NETRECTOR_DIR} netRector EXCLUDE_FROM_ALL)
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/netRector/CMakeLists.txt")
        set(NETRECTOR_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        add_subdirectory(third_party/netRector netRector EXCLUDE_FROM_ALL)
    elseif(EZRADIUS_FETCH_NETRECTOR)
        include(FetchContent)
        FetchContent_Declare(netRector GIT_REPOSITORY https://github.com/crazyfull/netRector.git GIT_TAG master)
        set(NETRECTOR_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(netRector)
    else()
        message(FATAL_ERROR "netRector not found: set -DEZRADIUS_NETRECTOR_DIR=<path>, put it in third_party/netRector, or use -DEZRADIUS_FETCH_NETRECTOR=ON")
    endif()
endif()

file(GLOB EZRADIUS_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB EZRADIUS_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")

add_library(EZRadius ${EZRADIUS_SOURCES})
add_library(EZRadius::EZRadius ALIAS EZRadius)
target_include_directories(EZRadius PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/EZRadius>)
target_link_libraries(EZRadius PUBLIC netRector)
target_compile_options(EZRadius PRIVATE -Wall)

if(EZRADIUS_SANITIZE)
    target_compile_options(EZRadius PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer -g)
    target_link_options(EZRadius PUBLIC -fsanitize=address,undefined)
endif()

if(EZRADIUS_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()

if(EZRADIUS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

include(GNUInstallDirs)
install(TARGETS EZRadius ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${EZRADIUS_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/EZRadius)
