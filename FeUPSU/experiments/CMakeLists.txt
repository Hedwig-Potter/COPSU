# 该 CMake 工程仅用于构建 experiments 中的模拟程序 script.cpp
cmake_minimum_required(VERSION 3.12)

project (main VERSION 1.0)

find_package(OpenMP)

# 编译生成名为 script 的可执行文件，实验中用于离线模拟装载率
add_executable(script script.cpp)

target_link_libraries(script OpenMP::OpenMP_CXX) 
