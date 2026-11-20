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
