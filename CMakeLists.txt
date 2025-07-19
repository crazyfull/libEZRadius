cmake_minimum_required(VERSION 3.5)

project(libEZRadius
    VERSION 1.4.6
    DESCRIPTION "radius Library"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall -O2")

option(BUILD_SHARED_LIBS "Build shared librarie" ON)

## #### #### ##add_definitions(-D USE_FOR_TEST=1)

#test project or library compile
set(USE_FOR_TEST ON)
option(USE_FOR_TEST "Build test project" ON)

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
    add_executable(libEZRadius ${SOURCES} ${HEADERS})

    #link Dependent Libraries
    target_link_libraries(libEZRadius
        -llibWrench
        -lpthread -lssl -lcrypto
    )

    if (${CMAKE_BUILD_TYPE} STREQUAL "Release")
        message(STATUS "Full static compile: YES")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    endif()

else()
    message(STATUS "Using library project: YES")

    #for library project
    if(BUILD_SHARED_LIBS)
        add_library(libEZRadius SHARED ${SOURCES} ${HEADERS})
    else()
        add_library(libEZRadius STATIC ${SOURCES} ${HEADERS})
        message(STATUS "Using library static: YES")
    endif()
endif()

## Set include directories for the library, [baraye include header haye ye library]
include_directories(${CMAKE_SOURCE_DIR}/src)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_SOURCE_DIR}/src)


set_target_properties(libEZRadius PROPERTIES OUTPUT_NAME libEZRadius)

include(GNUInstallDirs)
#install(TARGETS libEZRadius  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr")
endif()

#دستور سفارشی را برای پاک کردن فایل های قدیمی اضافه کنید.
#add_custom_command(TARGET libEZRadius PRE_BUILD COMMAND rm -f ${CMAKE_SOURCE_DIR}/build)

# هدف my_target را در دایرکتوری /usr/bin نصب کنید.
#install(TARGETS libEZRadius DESTINATION ${CMAKE_INSTALL_BINDIR})

# کتابخانه my_library را در دایرکتوری /usr/lib نصب کنید.
install(TARGETS libEZRadius DESTINATION ${CMAKE_INSTALL_LIBDIR})

# فایل هدر my_header.h را در دایرکتوری /usr/include نصب کنید.
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/EZRadius)

message(STATUS "build options:
    Install prefix:  ${CMAKE_INSTALL_PREFIX}
    Target system:   ${CMAKE_SYSTEM_NAME}
    C compiler:    ${CMAKE_C_COMPILER}
    Install library path:   ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
    Install library include path:    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}
    ")
