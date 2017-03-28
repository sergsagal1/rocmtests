/*
 * Copyright 2017 Advanced Micro Devices, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <getopt.h>
#include <immintrin.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>


#include "roctb.h"


struct _params {
    unsigned char           pattern;
    unsigned long long      buffer_size;
    bool                    verbose;
    long                    rank0_agent;
    long                    rank_agent;
};


struct _params params = {
    .pattern        = 0x55,
    .buffer_size    = 1024,
    .verbose        = false,
    .rank0_agent    = -1,
    .rank_agent     = -1,
};

static void  *alloc_memory(size_t _size, int world_rank) 
{
    void *p = NULL;

    int  gpu_index     = 0;

    if (world_rank == 0)
        gpu_index = (int) params.rank0_agent;
    else
        gpu_index = (int) params.rank_agent;

    switch (gpu_index) {
        case -1:    // System memory
            p = malloc(_size);
            break;
        case 0:
            p = roctb_alloc_memory_host(_size);
            break;
        default:
            if (gpu_index > 0)
                p = roctb_alloc_memory_device(_size, gpu_index-1);
            else {
                fprintf(stderr, "Invalid GPU Index: %d", gpu_index);
                exit(EXIT_FAILURE);
            }
            break;
    }

    if (!p)  {
        fprintf(stderr, "Failed to allocate memory\n");
        exit(EXIT_FAILURE);
    }

    //  We assume that we are dealing only with large-BAR systems. 
    //  It means that memory is CPU accessible 
    memset(p, 0, _size);

    if (params.verbose)
        printf("ROCMMPI: rank %d: Allocated buffer address: %p\n", world_rank, p);

    return p;
}

static void free_memory(void *p, int world_rank)
{
    int  gpu_index     = 0;

    if (world_rank == 0)
        gpu_index = (int) params.rank0_agent;
    else
        gpu_index = (int) params.rank_agent;

    switch (gpu_index) {
        case -1: 
            free(p);
            break;
        default:
            roctb_free_memory(p);
            break;
    }
}

static void usage(const char *argv0)
{
    printf("Options:\n");
    printf("  -s, --size=<size[K|M]>  Size of memory to allocate (default 4096)\n");
    printf("                K - size in KB\n");
    printf("                M - size in MB\n");
    printf("  -p, --pattern=<uint8_t> Specify pattern to fill memory to validate\n");
    printf("                          result. (default: 0x55)\n");
    printf("  -0, --rank0=<agent_index> Allocate HSA memory for agent\n");
    printf("                         (Agent 0 - CPU Agent / host memory allocation)\n");
    printf("                         (default: System memory will be used)\n");
    printf("  -r, --rank=<agent_index> Allocate  HSA memory for all other ranks\n");
    printf("                         (Agent 0 - CPU Agent  / host memory allocation)\n");
    printf("                         (default: System memory will be used)\n");
    printf("  -v, --verbose          Print additional information during execution\n");
}

int main(int argc, char** argv) 
{

    while (1) {

        int c;

        static struct option long_options[] = {
            { .name = "size",       .has_arg = 1, .val = 's'},
            { .name = "rank0",      .has_arg = 1, .val = '0'},
            { .name = "rank",       .has_arg = 1, .val = 'r'},
            { .name=  "pattern",    .has_arg = 1, .val = 'p'},
            { .name = "verbose",    .has_arg = 0, .val = 'v'},
            { 0 }
        };

        c = getopt_long(argc, argv, "s:0:r:p:v", long_options, NULL);

        if (c == -1)
            break;

        switch (c) {

            case 's': {
                size_t size_len = (int)strlen(optarg);
                unsigned long size_factor = 1;
                if (optarg[size_len-1] == 'K') {
                    optarg[size_len-1] = '\0';
                    size_factor = 1024;
                }
                if (optarg[size_len-1] == 'M') {
                    optarg[size_len-1] = '\0';
                    size_factor = 1024*1024;
                }
                params.buffer_size = strtoull(optarg, NULL, 0) * size_factor;
                if (params.buffer_size < 1 || params.buffer_size > (UINT_MAX / 2)) {
                    fprintf(stderr," Size should be between %d and %d\n",1,UINT_MAX/2);
                    exit(EXIT_FAILURE);
                }
            }
            break;

            case '0': {
                params.rank0_agent  = strtol(optarg,NULL,0);
            }
            break;

            case 'r': {
                params.rank_agent  = strtol(optarg,NULL,0);
            }
            break;

            case 'p': {
                params.pattern  = (unsigned char) strtol(optarg,NULL,0);
            }
            break;

            case 'v':
                params.verbose = true;
                break;


            default:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    if (roctb_init(0)) {
        fprintf(stderr, "Failure to initialize ROCm subsystem\n");
        exit(EXIT_FAILURE);
    }
    
    // Initialize the MPI environment
    MPI_Init(NULL, NULL);
    // Find out rank, size
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    if (params.verbose) {
        printf("ROCMMPI: rank %d: Allocate 0x%llx bytes. Pattern 0x%02X\n",
               world_rank,  params.buffer_size, params.pattern);

        if ( (world_rank == 0 ? params.rank0_agent : params.rank_agent) == -1)
            printf("ROCMMPI: rank %d: Allocate system memory\n", world_rank);
        else
            printf("ROCMMPI: rank %d: GPU Agent %d\n",
               world_rank,
               (int) ((world_rank == 0) ? params.rank0_agent : params.rank_agent));
    }

    // We are assuming at least 2 processes for this task
    if (world_size < 2) {
        fprintf(stderr, "ROCMMPI: World size must be greater than 1 for %s\n", argv[0]);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }


    unsigned char *buf = alloc_memory(params.buffer_size, world_rank);

    MPI_Barrier(MPI_COMM_WORLD);

    if (world_rank == 0) {
        // If we are rank 0 then broadcast to other processes

        memset(buf, params.pattern, params.buffer_size);

        int rank_count = 0;
        for (rank_count = 1; rank_count < world_size; rank_count++) {
            MPI_Send(buf, params.buffer_size, MPI_CHAR, rank_count, 0, MPI_COMM_WORLD);
        }
    } else {
        MPI_Recv(buf, params.buffer_size, MPI_CHAR, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

        if (params.verbose)
            printf("ROCMMPI: rank %d: received 0x%x\n", world_rank, (int) buf[0]);

        unsigned long long index = 0;

        for (index = 0; index < params.buffer_size; index++) {
            if (buf[index] != params.pattern) {
                fprintf(stderr, "ROCMMPI: rank %d: Corruption detected.\n"
                                "         Offset 0x%llx, Received 0x%02X, Expected 0x%02X\n",
                                world_rank, index, buf[index], params.pattern);
                exit(EXIT_FAILURE);
            }
        }
    }

    MPI_Barrier(MPI_COMM_WORLD);

    MPI_Finalize();

    free_memory(buf, world_rank);

    return 0;
}

