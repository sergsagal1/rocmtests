cmake_minimum_required(VERSION 2.8)

project(cmatest)


ADD_DEFINITIONS(-D_GNU_SOURCE)

include_directories(/opt/rocm/hsa/include /opt/rocm/libhsakmt/include/libhsakmt ../common)

link_directories(/opt/rocm/hsa/lib)

add_executable(cmatest cmatest.c ../common/roctb.c)
target_link_libraries(cmatest pthread hsa-runtime64 hsakmt  rt)
