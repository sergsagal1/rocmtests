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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE     /* Obtain O_DIRECT definition from <fcntl.h> */
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>
#include <ctype.h>
#include <getopt.h>
#include <immintrin.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
// ------------------------ HSA  includes ----------------------------------

#include <hsa.h>
#include <hsa_ext_amd.h>
#include "roctb.h"


struct _params {
    unsigned long long      buffer_size;
    bool                    verbose;
    bool                    use_system_memory;
    unsigned long           agent;
    bool                    wait;  
    bool                    read;  
    unsigned long           count;
};


struct _params params = {
    .buffer_size            = 4096,
    .verbose                = false,
    .use_system_memory      = true,
    .agent                  = 0,
    .wait                   = false,
    .read                   = false,
    .count                  = 1,
};


static void usage(const char *argv0)
{
    printf("Options:\n");
    printf("  -s, --size=<size[K|M]>  Size of memory to allocate (default 4096)\n");
    printf("                K - size in KB\n");
    printf("                M - size in MB\n");
    printf("  -a, --agent=<agent>  Allocate HSA global memory pool for agent\n");
    printf("                      0 - CPU agent, 1 - GPU0, etc.\n");
    printf("                      (default: System memory will be used)\n");
    printf("  -w, --wait    Wait for CMA operation from another application\n");
    printf("                 (server mode)\n");
    printf("  -r, --read    Issue read  CMA operation\n");
    printf("                (default: Issue write CMA operation)\n");
    printf("  -c, --count   How many times to issue CMA operation\n");
    printf("                (default: 1)\n");
//    printf("  -v, --verbose Print additional information during execution\n");
}


int main(int argc, char *argv[])
{
    while (1) {

        int c;

        static struct option long_options[] = {
            { .name = "size",       .has_arg = 1, .val = 's'},
            { .name = "agent",      .has_arg = 1, .val = 'a'},
            { .name = "count",      .has_arg = 1, .val = 'c'},
            { .name = "wait",       .has_arg = 0, .val = 'w'},
            { .name = "read",       .has_arg = 0, .val = 'r'},
//            { .name = "verbose",    .has_arg = 0, .val = 'v'},
            { 0 }
        };

        c = getopt_long(argc, argv, "s:a:c:wr", long_options, NULL);

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
                params.buffer_size = (uint64_t)strtoul(optarg, NULL, 0) * size_factor;
                if (params.buffer_size < 1 || params.buffer_size > (UINT_MAX / 2)) {
                    fprintf(stderr," Size should be between %d and %d\n",1,UINT_MAX/2);
                    return 1;
                }
            }
                break;


            case 'a':
                params.agent = strtoul(optarg, NULL, 0);
                params.use_system_memory = false;
                break;

            case 'c':
                params.count  = strtoul(optarg, NULL, 0);
                break;

            case 'r':
                params.read  = true;
                break;

            case 'w':
                params.wait = true;
                break;

            case 'v':
                params.verbose = true;
                break;


            default:
                usage(argv[0]);
                exit(EXIT_SUCCESS);
        }
    }

    pid_t   current_pid = getpid();

    printf("Memory page size     : %d\n", getpagesize());
    printf("Buffer size          : 0x%llx\n", params.buffer_size); 
    if (!params.use_system_memory)
        printf("HSA Agent            : %d\n", (int) params.agent);
    else
        printf("Use system memory for allocation\n");

    printf("Process id           : %d\n", current_pid);

    roctb_init(0);

    void *ptr    = NULL;
    void *gpu_ptr = NULL;

    if (!params.use_system_memory)  {

        if (params.agent == 0)
            ptr = roctb_alloc_memory_host(params.buffer_size);
        else 
            ptr = roctb_alloc_memory_device(params.buffer_size, params.agent - 1);

        if (ptr == NULL) {
            fprintf(stderr, "Failure to allocate HSA memory");
            exit(EXIT_FAILURE);
        }            

        gpu_ptr = ptr;

    } else {
        ptr = malloc(params.buffer_size);
        if (roctb_register_memory(ptr, params.buffer_size, &gpu_ptr )) {
            fprintf(stderr, "Failure to lock memory");
            exit(EXIT_FAILURE);
        }
    }

    printf("Allocated memory: PTR %p, GPU PTR %p\n", ptr, gpu_ptr);


    const char *name = "cmatest0";

	/* open the shared memory segment */
	int shm_fd;
    
    if (params.wait)
        shm_fd = shm_open(name, O_CREAT | O_RDWR, S_IRWXU);
    else   
        shm_fd = shm_open(name, O_RDWR, S_IRWXU);

	if (shm_fd == -1) {
		fprintf(stderr, "Failure to open shared memory\n");
		exit(EXIT_FAILURE);
	}

    if (params.wait) {
        if(ftruncate(shm_fd, 4096) == -1) {
            fprintf(stderr, "ftruncate failed\n");
            exit(EXIT_FAILURE);
        }
    }

	/* Map the shared memory segment in the address space of the process */
	void *shmem_ptr = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

	if (!shmem_ptr) {
		fprintf(stderr, "Failure to map shmem to address space\n");
		exit(EXIT_FAILURE);
	}

    printf("shmem_ptr %p\n", shmem_ptr);

    if (params.wait) {
        sprintf(shmem_ptr, "%d %p", (int) current_pid, gpu_ptr);
        printf("Press <Enter>  to terminate testing\n");
        getchar();
    } else {
        void *remote_ptr    = NULL;
        pid_t remote_pid    = NULL;

        sscanf(shmem_ptr, "%d %p", (int *)&remote_pid, &remote_ptr);

        if (params.read)
            printf("Read remote memory.\n");
        else
            printf("Write remote memory.\n");
        
        printf("Remote info: pid %d ptr %p\n", remote_pid, remote_ptr);
        printf("Number of loops to run: %lu\n", params.count);

        unsigned int n = 0;
        for (n = 0; n < params.count; n++) {
            if (!roctb_cma_operation(remote_pid, gpu_ptr, remote_ptr, 
                                      params.buffer_size, params.read)) {

                fprintf(stderr, "CMA operation failed. Exit..");
                exit(EXIT_FAILURE);
            }
        }
        printf("Done...\n");
    }

    close(shm_fd);

    if (params.wait) {
        /* remove the shared memory segment */
        if (shm_unlink(name) == -1) {
	        fprintf(stderr, "Error removing shared memory segment %s\n",name);
	        exit(EXIT_FAILURE);
        }
    }

    return 0;
}
 