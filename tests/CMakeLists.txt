add_executable(test_packet test_packet.cpp)
target_link_libraries(test_packet PRIVATE EZRadius)
add_test(NAME packet COMMAND test_packet)

add_executable(test_loopback test_loopback.cpp)
target_link_libraries(test_loopback PRIVATE EZRadius)
add_test(NAME loopback COMMAND test_loopback)

add_executable(fuzz_packet fuzz_packet.cpp)
target_link_libraries(fuzz_packet PRIVATE EZRadius)
add_test(NAME fuzz_smoke COMMAND fuzz_packet 20000)

add_executable(test_mschap test_mschap.cpp)
target_link_libraries(test_mschap PRIVATE EZRadius)
add_test(NAME mschap COMMAND test_mschap)

add_executable(test_vendor test_vendor.cpp)
target_link_libraries(test_vendor PRIVATE EZRadius)
add_test(NAME vendor COMMAND test_vendor)

add_executable(test_eap test_eap.cpp)
target_link_libraries(test_eap PRIVATE EZRadius)
add_test(NAME eap COMMAND test_eap)

add_executable(test_transport test_transport.cpp)
target_link_libraries(test_transport PRIVATE EZRadius)
add_test(NAME transport COMMAND test_transport)

if(EZRADIUS_HAS_TLS)
    add_executable(test_radsec test_radsec.cpp)
    target_link_libraries(test_radsec PRIVATE EZRadius)
    add_test(NAME radsec COMMAND test_radsec)
    add_executable(test_dtls test_dtls.cpp)
    target_link_libraries(test_dtls PRIVATE EZRadius)
    add_test(NAME dtls COMMAND test_dtls)
    add_executable(test_radius11 test_radius11.cpp)
    target_link_libraries(test_radius11 PRIVATE EZRadius)
    add_test(NAME radius11 COMMAND test_radius11)
endif()
