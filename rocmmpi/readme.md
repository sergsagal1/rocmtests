# MPI Test application to validate working with ROCm

## Prerequisites

The following dependencies must be satisfied:
- UCX with ROCm support
- OpenMPI build with UCX support
- ROCm stack
- Mellanox OFED with PeerDirect
- AMD GPU(s) with large BAR enabled

## Build

$ cmake CMakeLists.txt
$ make

Note:
=============
cmake must find the correct MPI in the path (PATH and LD).


## Running test application

Example of command line:

$ mpirun -np 3 -host localhost,localhost,localhost -mca pml ucx -x UCX_TLS=mm,rocmcma ./rocmmpi -v -s 1M -0 0 -r 1


## Command line options

- -s or --size=<size[K|M]>  
    Size of memory to allocate (default 4096). Where  K - size in KB, M - size in MB
- -p, --pattern=<uint8_t>  
    Specify pattern to fill memory to validate transfer
- -0, --rank0=<agent_index>  
    Allocate HSA memory for agent
    (Agent 0 - CPU Agent / host memory allocation)
    (default: System memory will be used)
- -r, --rank=<agent_index>  
    Allocate  HSA memory for all other ranks. (Agent 0 - CPU Agent  / host memory  allocation. (default: System memory will be used)
- -v, --verbose  
   Print additional information during execution





