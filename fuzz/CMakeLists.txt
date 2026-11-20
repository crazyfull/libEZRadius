# libFuzzer needs clang: -DCMAKE_CXX_COMPILER=clang++ -DEZRADIUS_BUILD_FUZZER=ON
add_executable(ezradius_libfuzzer fuzz_libfuzzer.cpp)
target_link_libraries(ezradius_libfuzzer PRIVATE EZRadius)
target_compile_options(ezradius_libfuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(ezradius_libfuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
