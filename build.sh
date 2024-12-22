rm -rf build && mkdir build
cd build && cmake .. && cmake --build .
./test
./test_full