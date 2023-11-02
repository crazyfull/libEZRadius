cmake_minimum_required(VERSION 3.5)

project(libEZRadius
    VERSION 1.1.5
    DESCRIPTION "radius Library"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
#set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall")
#set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -O2")

#set(CMAKE_POSITION_INDEPENDENT_CODE ON)
option(BUILD_SHARED_LIBS "Build shared librarie" OFF)
#add_definitions(-D USE_FOR_TEST=1)
#add_subdirectory(src)
set(USE_FOR_TEST ON)

# Dependent Libraries
file(GLOB SOURCES "./src/*.cpp")
file(GLOB HEADERS "./src/*.h")

# Set include directories for the library, baraye include header haye ye library
#target_include_directories(libEZRadius PUBLIC "./src")


set(HEADERS ${HEADERS}
    #WebSocketClient.h
)

if (USE_FOR_TEST)
    message(STATUS "Using execute: YES")

    #add main file
    set(SOURCES ${SOURCES}
        main.cpp
    )

    #
    add_executable(libEZRadius ${SOURCES} ${HEADERS}
        src/EZRadiusServer.h src/EZRadiusServer.cpp)

    #link Dependent Libraries
    target_link_libraries(libEZRadius
        -llibWrench
        -lpthread -lssl -lcrypto
    )

else()
    message(STATUS "Using library project: YES")

    #for library project
    if(BUILD_SHARED_LIBS)
        add_library(libEZRadius SHARED ${SOURCES} ${HEADERS})
    else()
        add_library(libEZRadius STATIC ${SOURCES} ${HEADERS})
    endif()
endif()




if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    message(STATUS "Full static compile: YES")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

set_target_properties(libEZRadius PROPERTIES OUTPUT_NAME "libEZRadius")

include(GNUInstallDirs)
install(TARGETS libEZRadius
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)


