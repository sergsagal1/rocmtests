/*
 * Copyright 2016 - 2017 Advanced Micro Devices, Inc.
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

#ifndef ROCM_TB_H
#define ROCM_TB_H


#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    /** There is no information about given memory type.
     * Assumed as CPU one */
    ROCTB_PTR_UNKNOWN       = 0,
    /** GPU Accessible pointer for allocation in host memory */
    ROCTB_PTR_GPU_HOST      = 1,
    /** GPU Accessible pointer for allocation in device memory */
    ROCTB_PTR_GPU_DEVICE    = 2,
    /** Memory is GPU accessible but we do not know its' location */
    ROCTB_PTR_GPU_ACCESSIBLE = 3,

} roctb_ptr_type;

int         roctb_init(uint64_t settings);

int         roctb_get_gpus_number();

void       *roctb_alloc_memory_host     (size_t size);
void       *roctb_alloc_memory_device   (size_t size, int gpu);
void        roctb_free_memory           (void *ptr);

int         roctb_register_memory       (void *ptr,size_t size,
                                        void **gpu_address);
void        roctb_unregister_memory     (void *ptr);

ssize_t     roctb_copy_memory           (void *dst, void *src, size_t size);

roctb_ptr_type roctb_get_ptr_type       (void *ptr);
int         roctb_is_ptr_gpu_accessible (void *ptr);
bool        roctb_cma_operation         (pid_t pid, void *local, void *remote, 
                                         size_t size, bool read);


#ifdef __cplusplus
}
#endif


#endif                                      // #ifdef ROCM_TB_H

