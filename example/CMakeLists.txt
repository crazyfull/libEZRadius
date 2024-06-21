cmake_minimum_required(VERSION 3.5)

project(EZRadiusServer_test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(EZRadiusServer_test server.cpp
    client.cpp)

include(GNUInstallDirs)
install(TARGETS EZRadiusServer_test
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

#link Dependent Libraries
target_link_libraries(EZRadiusServer_test
    -llibEZRadius
    -llibWrench
    -lpthread -lssl -lcrypto
)
