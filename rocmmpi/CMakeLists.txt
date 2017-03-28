cmake_minimum_required(VERSION 2.8)

project(rocmmpi)

# Require MPI for this project:
find_package(MPI REQUIRED)

ADD_DEFINITIONS(-D_GNU_SOURCE)


include_directories(${MPI_C_INCLUDE_PATH})
include_directories(/opt/rocm/hsa/include /opt/rocm/libhsakmt/include/libhsakmt ../common)


set(CMAKE_C_COMPILE_FLAGS ${CMAKE_C_COMPILE_FLAGS} ${MPI_C_COMPILE_FLAGS})
set(CMAKE_C_LINK_FLAGS ${CMAKE_C_LINK_FLAGS} ${MPI_C_LINK_FLAGS})

link_directories(/opt/rocm/hsa/lib)

add_executable(rocmmpi rocmmpi.c ../common/roctb.c)
target_link_libraries(rocmmpi pthread hsa-runtime64 hsakmt ${MPI_C_LIBRARIES})
