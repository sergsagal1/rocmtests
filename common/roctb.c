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


#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hsa.h>
#include <hsa_ext_amd.h>
#include <hsakmt.h>

#include "roctb.h"

#define DBG_LEVEL_NONE  0
#define DBG_LEVEL_ERR   1
#define DBG_LEVEL_WARN  2
#define DBG_LEVEL_INFO  3
#define DBG_LEVEL_DBG   4

static int debug_level = DBG_LEVEL_DBG;

#define MSG_DBG(fmt, args ...)  \
            { if (debug_level >= DBG_LEVEL_DBG) \
                fprintf(stderr, "roctb: "fmt, ## args); \
            }

#define MSG_INFO(fmt, args ...) \
            { if (debug_level >= DBG_LEVEL_INFO) \
                fprintf(stderr, "roctb: "fmt, ## args); \
            }

#define MSG_WARN(fmt, args ...) \
            { if (debug_level >= DBG_LEVEL_WARN) \
                fprintf(stderr, "roctb: "fmt, ## args); \
            }

#define MSG_ERR(fmt, args ...)  \
            { if (debug_level >= DBG_LEVEL_ERR) \
                fprintf(stderr, "roctb: " fmt, ## args); \
            }


#define MAX_HSA_AGENTS         64          // Max. number of HSA agents supported


static struct {
    struct {
        struct {
            uint32_t                bus;    /**< PCI Bus id */
            uint32_t                device; /**< PCI Device id */
            uint32_t                func;   /**< PCI Function id */
            hsa_amd_memory_pool_t   pool;   /**< Global pool associated with agent.
                                              @note Current we assume that there
                                              is only one global pool per agent
                                              base on the current behaviour */
        } gpu_info[MAX_HSA_AGENTS];
        hsa_agent_t gpu_agent[MAX_HSA_AGENTS];/**< HSA GPU Agent handles */
        struct {
            hsa_agent_t           agent;    /**< HSA Agent handle for CPU */
            hsa_amd_memory_pool_t pool;     /**< Global pool associated with agent.
                                             @note Current we assume that there 
                                             is only one global pool per agent
                                             base on the current behaviour */
        } cpu;
    } agents;
    int num_of_gpu;
} roctb_cfg;


typedef struct {
    void                    *ptr;
    hsa_amd_pointer_info_t   info;
    uint32_t                 num_agents_accessible;
    hsa_agent_t              accessible[MAX_HSA_AGENTS];
} rocm_ptr_t;


#define MEMORY_CPU_ACCESSIBLE 0x01
#define MEMORY_GPU_ACCESSIBLE 0x02


static hsa_status_t hsa_amd_memory_pool_callback(
                                hsa_amd_memory_pool_t memory_pool, void* data)
{
    hsa_status_t status;
    hsa_amd_segment_t amd_segment;

    status = hsa_amd_memory_pool_get_info(memory_pool,
                                         HSA_AMD_MEMORY_POOL_INFO_SEGMENT,
                                         &amd_segment);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to get pool info: 0x%x\n", status);
        return status;
    }

    if (amd_segment ==  HSA_AMD_SEGMENT_GLOBAL) {
        *(hsa_amd_memory_pool_t *)data = memory_pool;
        MSG_INFO("Found global pool: 0x%lx\n", memory_pool.handle);
        return HSA_STATUS_INFO_BREAK;
    }

    return HSA_STATUS_SUCCESS;
}
//******************************************************************************
//                           -- hsa_agent_callback --
/**
 *  Callback to enumerate all agents
 *
*/
//******************************************************************************
static hsa_status_t hsa_agent_callback(hsa_agent_t agent, void* data)
{
    uint32_t bdfid;
    hsa_device_type_t device_type;
    hsa_status_t status;

    MSG_DBG("hsa_agent_callback: Agent  0x%lx\n", agent.handle);

    status = hsa_agent_get_info(agent, HSA_AGENT_INFO_DEVICE, &device_type);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to get device type: 0x%x\n", status);
        return status;
    }

    if (device_type == HSA_DEVICE_TYPE_GPU) {

        status = hsa_agent_get_info(agent, HSA_AMD_AGENT_INFO_BDFID, &bdfid);

        if (status != HSA_STATUS_SUCCESS) {
            MSG_ERR("Failure to get pci info: 0x%x\n", status);
            return status;
        }

        roctb_cfg.agents.gpu_agent[roctb_cfg.num_of_gpu] = agent;
        roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].bus    = (bdfid >> 8) & 0xff;
        roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].device = (bdfid >> 3) & 0x1F;
        roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].func   = bdfid & 0x7;

        MSG_INFO("Found GPU agent : 0x%lx. [ B#%02d, D#%02d, F#%02d ]\n",
                roctb_cfg.agents.gpu_agent[roctb_cfg.num_of_gpu].handle,
                roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].bus,
                roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].device,
                roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].func);


        roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].pool.handle = (uint64_t) -1;
        status = hsa_amd_agent_iterate_memory_pools(agent,
                                                    hsa_amd_memory_pool_callback,
                                                    &roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].pool);

        if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
            MSG_ERR("Failure to iterate regions: 0x%x\n", status);
            return status;
        }

        if (roctb_cfg.agents.gpu_info[roctb_cfg.num_of_gpu].pool.handle == (uint64_t)-1) {
            MSG_ERR("Could not find memory pool with given index\n");
            return status;
        }

        roctb_cfg.num_of_gpu++;             // Increment GPU agent index

    } else  if (device_type == HSA_DEVICE_TYPE_CPU) {
        roctb_cfg.agents.cpu.agent = agent;
        MSG_INFO("Found CPU agent : 0x%lx.\n", roctb_cfg.agents.cpu.agent.handle);

        roctb_cfg.agents.cpu.pool.handle = (uint64_t) -1;
        status = hsa_amd_agent_iterate_memory_pools(agent,
                                                    hsa_amd_memory_pool_callback,
                                                    &roctb_cfg.agents.cpu.pool);

        if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
            MSG_ERR("Failure to iterate regions: 0x%x\n", status);
            return status;
        }

        if (roctb_cfg.agents.cpu.pool.handle == (uint64_t)-1) {
            MSG_ERR("Could not find memory pool with given index\n");
            return status;
        }
    }

    // Keep iterating
    return HSA_STATUS_SUCCESS;
}


// ---------------------------  Toolbox functions -----------------------------

//******************************************************************************
//                      -- roctb_get_default_gpu_agent --
/**
 *   Get default GPU agent
 *
 *   @return  Default GPU Agent
 *
*/
//******************************************************************************
hsa_agent_t roctb_get_default_gpu_agent()
{
    MSG_DBG("Default GPU Agent: 0x%lx\n", roctb_cfg.agents.gpu_agent[0].handle);

    return  roctb_cfg.agents.gpu_agent[0];
}
//******************************************************************************
//                      -- roctb_get_number_gpu_agents --
/**
 *   Return number of GPU agents
 *
 *   @return Number of GPU agents
 *
*/
//******************************************************************************
int roctb_get_number_gpu_agents()
{
    return  roctb_cfg.num_of_gpu;
}
//******************************************************************************
//                      -- roctb_get_cpu_agent --
/**
 *   Get CPU agent
 *
 *   @return  CPU Agent
 *
*/
//******************************************************************************
hsa_agent_t roctb_get_cpu_agent()
{
    MSG_DBG("CPU Agent: 0x%lx\n", roctb_cfg.agents.cpu.agent.handle);

    return  roctb_cfg.agents.cpu.agent;
}

//******************************************************************************
//                           -- roctb_is_gpu_agent --
/**
 *   Check if given agent is GPU one
 *
 *   @param   agent - \c [in]  HSA agent
 *
 *   @return  true if this gpu agent
 *            false otherwise
 *
*/
//******************************************************************************
bool roctb_is_gpu_agent(hsa_agent_t agent)
{
    if (agent.handle != roctb_cfg.agents.cpu.agent.handle)
        return true;
    else
        return false;
}
//******************************************************************************
//                           -- roctb_is_cpu_agent --
/**
 *   Check if given agent is CPU one
 *
 *   @param   agent - \c [in]  HSA agent
 *
 *   @return  true if this cpu agent
 *            false otherwise
 *
*/
//******************************************************************************
bool roctb_is_cpu_agent(hsa_agent_t agent)
{
    if (agent.handle == roctb_cfg.agents.cpu.agent.handle)
        return true;
    else
        return false;
}


//******************************************************************************
//                      -- roctb_is_gpu_accessible --
/**
 *  Check if GPU access is enabled
 *
 *   @param   rocm_ptr - \c [in]  Pointer to structure describing memory
 *
 *   @return  true if GPU access is enabled
 *
*/
//******************************************************************************
bool roctb_is_gpu_accessible(rocm_ptr_t * rocm_ptr)
{
    int i;
    for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
        if (roctb_is_gpu_agent(rocm_ptr->accessible[i]))
            return true;
    }

    return false;
}
//******************************************************************************
//                      -- roctb_is_cpu_accessible --
/**
 *  Check if CPU access is enabled
 *
 *   @param   rocm_ptr - \c [in]  Pointer to structure describing memory
 *
 *   @return  true if CPU access is enabled
 *
*/
//******************************************************************************
bool roctb_is_cpu_accessible(rocm_ptr_t * rocm_ptr)
{
    int i;
    for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
        if (roctb_is_cpu_agent(rocm_ptr->accessible[i]))
            return true;
    }

    return false;
}

//******************************************************************************
//                       -- roctb_get_accessible_mask --
/**
 *   Get mask about GPU accessibility
 *
 *   @param   rocm_ptr        - \c [in]  Desribe memory
 *   @param   accessible_mask - \c [out] Return accessibility mask
 *   @param   gpu_agent       - \c [out] Return first GPU agent
 *
*/
//******************************************************************************
void roctb_get_accessible_mask(rocm_ptr_t * rocm_ptr, uint32_t *accessible_mask,
                               hsa_agent_t *gpu)
{
    *accessible_mask = 0;

    int i;
    for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
        if (roctb_is_gpu_agent(rocm_ptr->accessible[i])) {
            if (!(*accessible_mask & MEMORY_GPU_ACCESSIBLE)) {
                // This is the first GPU agent
                *accessible_mask |= MEMORY_GPU_ACCESSIBLE;
                if (gpu)
                    *gpu = rocm_ptr->accessible[i];
            }
        }
        else
            *accessible_mask |= MEMORY_CPU_ACCESSIBLE;
    }
}

//******************************************************************************
//                      -- roctb_get_gpu_agent  --
/**
 *   Get GPU agent to be used for access
 *
 *   @param   rocm_ptr - \c [in]  Pointer to structure describing memory
 *
 *   @return  true if GPU agent will be found
 *
*/
//******************************************************************************
bool roctb_get_gpu_agent(rocm_ptr_t * rocm_ptr, hsa_agent_t * gpu_agent)
{
    // Note: Currently we returned the first found GPU agent which
    // may be incorrect in multi-GPU case from performance perspective.
    int i;
    for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
        if (roctb_is_gpu_agent(rocm_ptr->accessible[i]))
            return true;
    }

    return false;
}

//******************************************************************************
//                   -- roctb_find_common_gpu_agent --
/**
 *   Try to find GPU agent which could be used for access to both memory
 *   locations.
 *
 *   @param   ptr0  - \c [in] Structure describing the first location
 *   @param   ptr1  - \c [in] Structure describing the second location
 *   @param   agent - \c [out] GPU Agent
 *
 *   @return  true - GPU agent was found
 *            false - otherwise
 *
*/
//******************************************************************************
bool roctb_find_common_gpu_agent(rocm_ptr_t * ptr0, rocm_ptr_t *ptr1,
                                 hsa_agent_t * agent)
{
    // Try to find agent which could access both the source and destination
    // buffers in their current locations.

    int i, j;

    MSG_DBG("roctb_find_common_gpu_agent\n");

    if (!ptr0->num_agents_accessible || !ptr0->num_agents_accessible) {
        MSG_DBG("At least one allocation doesn't have any agents\n");
        return false;
    }


    for (i = 0; i <  ptr0->num_agents_accessible; i++) {

        MSG_DBG("roctb_find_common_gpu_agent. ptr0 agent: 0x%lx\n",
                                            ptr0->accessible[i].handle);

        if (ptr0->accessible[i].handle != roctb_cfg.agents.cpu.agent.handle) {
            // This is GPU agent.

        }

        if (roctb_is_gpu_agent(ptr0->accessible[i])) {

            MSG_DBG("roctb_find_common_gpu_agent: Ptr 0 GPU agent: 0x%lx\n",
                                    ptr0->accessible[i].handle);

            for (j = 0; j < ptr1->num_agents_accessible; j++) {

                MSG_DBG("roctb_find_common_gpu_agent: Ptr 1 agent: 0x%lx\n",
                                                    ptr1->accessible[j].handle);

                if (ptr0->accessible[i].handle == ptr1->accessible[j].handle) {
                    *agent = ptr0->accessible[i];
                    MSG_DBG("roctb_find_common_gpu_agent: Found GPU agent: 0x%lx\n",
                                                    ptr0->accessible[i].handle);
                    return true;
                }
            }
        }
    }

    return false;
}

static void *alloc_callback(size_t _size) { return malloc(_size); }
//******************************************************************************
//                       -- roctb_query_ptr_info --
/**
 *   Query information about pointer
 *
 *   @param   address  - \c [in]  Pointer
 *   @param   ptr_info - \c [out] Information describing pointer
 *
 *   @return  HSA_STATUS_SUCCESS if operation was sucessful\n
 *            HSA error code otherwise
 *
*/
//******************************************************************************
hsa_status_t roctb_query_ptr_info(void *address, rocm_ptr_t *rocm_ptr)
{
    hsa_status_t    status;
    hsa_agent_t    *accessible = NULL;

    MSG_DBG("roctb_query_ptr_info: Address %p\n", address);

    memset(rocm_ptr, 0, sizeof(rocm_ptr_t));
    rocm_ptr->info.size = sizeof(hsa_amd_pointer_info_t);

    rocm_ptr->ptr                   = address; // Save address in structure
    rocm_ptr->num_agents_accessible = 0;

    status = hsa_amd_pointer_info(rocm_ptr->ptr, &rocm_ptr->info,
                                  alloc_callback,
                                  &rocm_ptr->num_agents_accessible,
                                  &accessible);

    if (status == HSA_STATUS_SUCCESS) {

        MSG_DBG("roctb_query_ptr_info: Info type %d\n",         rocm_ptr->info.type);
        MSG_DBG("roctb_query_ptr_info: agentBaseAddress %p\n",  rocm_ptr->info.agentBaseAddress);
        MSG_DBG("roctb_query_ptr_info: hostBaseAddress %p\n",   rocm_ptr->info.hostBaseAddress);
        MSG_DBG("roctb_query_ptr_info: sizeInBytes  0x%lx\n",   rocm_ptr->info.sizeInBytes);

        int i;
        for (i=0; i < rocm_ptr->num_agents_accessible; i++) {
            MSG_DBG("roctb_query_ptr_info: [%d] Accessible agent: 0x%lx\n",
                        i, accessible[i].handle);
        }

        if (rocm_ptr->num_agents_accessible < MAX_HSA_AGENTS) {
            memcpy(rocm_ptr->accessible, accessible,
                        sizeof(hsa_agent_t) * rocm_ptr->num_agents_accessible);

        }
        else {
            MSG_ERR("roctb_query_ptr_info %d for address %p\n",
                    (int) rocm_ptr->num_agents_accessible, address);

            rocm_ptr->num_agents_accessible = 0;
            status = HSA_STATUS_ERROR;
        }

        free(accessible);

    } else {
        MSG_ERR("Could not query pointer %p info. Status 0x%x\n", address, status);
    }

    return status;
}

///////////////////////////////////////////////////////////////////////////////
// ----------------------------  Internal helpers -----------------------------
///////////////////////////////////////////////////////////////////////////////
//******************************************************************************
//                        -- enable_all_gpus_access --
/**
 *   Enable access from all GPUs to this memory
 *
 *   @param   ptr - \c [in] Pointer to memory
 *
 *   @return  HSA status
 *
*/
//******************************************************************************
static hsa_status_t enable_all_gpus_access(void *ptr)
{
    hsa_status_t status = hsa_amd_agents_allow_access(roctb_cfg.num_of_gpu,
                                             roctb_cfg.agents.gpu_agent,
                                             NULL,  ptr);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to allow access for all GPUs agent. Status 0x%x\n",
                    status);
    }

    return status;
}

///////////////////////////////////////////////////////////////////////////////
// -----------------------   Toolbox public functions -------------------------
///////////////////////////////////////////////////////////////////////////////

//******************************************************************************
//                              -- roctb_init --
/**
 *  Initialize ROC ToolBox library
 *
 *
 *   @return  0 if library was initialized successfully
 *            -1 otherwise
 *
*/
//******************************************************************************
int roctb_init(uint64_t attrib)
{
    int status = -1;                        // Assume initialization failure

    // Query message debug level ----------------------------------------------


    char *trace_level = secure_getenv ("ROCTB_TRACE");

    if (trace_level) {
        if (strcmp(trace_level, "none") == 0)
                debug_level = DBG_LEVEL_NONE;
        else if (strcmp(trace_level, "err") == 0)
                debug_level = DBG_LEVEL_ERR;
        else if (strcmp(trace_level, "warn") == 0)
                debug_level = DBG_LEVEL_WARN;
        else if (strcmp(trace_level, "info") == 0)
                debug_level = DBG_LEVEL_INFO;
        else if (strcmp(trace_level, "dbg") == 0)
                debug_level = DBG_LEVEL_DBG;
    }

    MSG_INFO("Initialize\n");

    hsa_status_t hsa_status;

    hsa_status = hsa_init();

    if (hsa_status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to open HSA connection: 0x%x\n", status);
        goto end;
    }

    // Collect information about GPU agents -----------------------------------

    status = hsa_iterate_agents(hsa_agent_callback, NULL);

    if (status != HSA_STATUS_SUCCESS && status != HSA_STATUS_INFO_BREAK) {
        MSG_ERR("Failure to iterate HSA agents: 0x%x\n", status);
        goto end;
    }



    // Success ----------------------------------------------------------------

    status = 0;


end:

    return status;
}

//******************************************************************************
//                           -- roctb_get_gpus_number --
/**
 * Return number of GPUs detected
 *
 *
 *   @return Number of GPUs
 *
*/
//******************************************************************************
int roctb_get_gpus_number()
{
    return roctb_cfg.num_of_gpu;
}
//******************************************************************************
//                         -- roctb_register_memory --
/**
 *   Register external allocated memory with ROCm library
 *
 *   @param   ptr         - \c [in] Pointer to register
 *   @param   size        - \c [in] Memory size
 *   @param   gpu_address - \c [out] Return GPU address to be used for access
 *                                   to such memory
 *
 *   @return  0 - if operation was sucessful\n
 *            1 - otherwise
 *
*/
//******************************************************************************
int roctb_register_memory(void *ptr, size_t size, void **gpu_address)
{
    void *_gpu;
    hsa_status_t status;


    if (gpu_address)
        status = hsa_amd_memory_lock(ptr, size, &roctb_cfg.agents.gpu_agent[0],
                                                 roctb_cfg.num_of_gpu,
                                                gpu_address);
    else
        status = hsa_amd_memory_lock(ptr, size, roctb_cfg.agents.gpu_agent,
                                                 roctb_cfg.num_of_gpu,
                                                &_gpu);

    if (status == HSA_STATUS_SUCCESS)
        return 0;
    else {
        MSG_ERR("Failed to lock memory.  Status 0x%x\n", status);
        return -1;
    }
}

//******************************************************************************
//                        -- roctb_unregister_memory --
/**
 *   Unregister previously registered memory
 *
 *   @param   ptr - \c [in] Pointer to memory
 *
*/
//******************************************************************************
void roctb_unregister_memory(void *ptr)
{
    hsa_status_t status = hsa_amd_memory_unlock(ptr);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failed to unlock memory.  Status 0x%x\n", status);
    }
}

//******************************************************************************
//                        -- roctb_alloc_memory_host --
/**
 *  Allocate host (system) memory for GPU access
 *
 *   @param   size - \c [in]  Size to allocate
 *
 *   @return Pointer to memory or NULL if failure
 *
 *   @note All GPUs will get access to this memory
 *
*/
//******************************************************************************
void *roctb_alloc_memory_host(size_t size)
{
    void *p;
    hsa_status_t status;

    status = hsa_amd_memory_pool_allocate(roctb_cfg.agents.cpu.pool, size,
                                            0, &p);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to allocate host memory.  Status 0x%x\n", status);
    } else {
        MSG_DBG("Allocate host memory.  Address %p\n", p);

        // Allow access to the buffer from all agents
        status = enable_all_gpus_access(p);

        if (status != HSA_STATUS_SUCCESS) {
            MSG_ERR("Failure to allow access for all GPUs agent. Status 0x%x\n",
                    status);

            roctb_free_memory(p);
            p = NULL;
        }
    }

    return p;
}

//******************************************************************************
//                       -- roctb_alloc_memory_device --
/**
 *   Allocate memory in local
 *
 *   @param   size - \c [in] Size of memory to allocate
 *   @param   gpu  - \c [in] GPU index (0-based)
 *
 *   @return  Pointer to memory or NULL if faiure
 *
*/
//******************************************************************************
void *roctb_alloc_memory_device(size_t size, int gpu)
{
    void *p;
    hsa_status_t status;

    if (gpu < 0 || gpu >  roctb_get_gpus_number()) {
        MSG_ERR("Invalid GPU index: %d\n", gpu);
        return NULL;
    }

    status = hsa_amd_memory_pool_allocate(roctb_cfg.agents.gpu_info[gpu].pool,
                                          size, 0, &p);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to allocate host memory.  Status 0x%x\n", status);
    } else {
        MSG_DBG("Allocate device memory.  Address %p\n", p);

        // Allow access to the buffer from all agents
        status = enable_all_gpus_access(p);

        if (status != HSA_STATUS_SUCCESS) {
            MSG_ERR("Failure to allow access for all GPUs agent. Status 0x%x\n",
                    status);

            roctb_free_memory(p);
            p = NULL;
        }
    }

    return p;
}

//******************************************************************************
//                           -- roctb_free_memory --
/**
 *   Free previously allocated memory
 *
 *   @param   ptr - \c [in] Pointer to memory to free
 *
*/
//******************************************************************************
void roctb_free_memory(void *ptr)
{
    if (ptr) {
        hsa_status_t status = hsa_amd_memory_pool_free(ptr);

        if (status != HSA_STATUS_SUCCESS)
            MSG_ERR("Failure to free HSA memory %p: 0x%x\n", ptr, status);
    }
}

//******************************************************************************
//                      -- roctb_is_ptr_gpu_accessible --
/**
 *   Check if memory GPU accessible
 *
 *   @param   rocm_ptr - \c [in]  Pointer to structure describing memory
 *
 *   @return  1 if GPU accessible, 0 otherwise
 *
*/
//******************************************************************************
int roctb_is_ptr_gpu_accessible(void *ptr)
{
    hsa_amd_pointer_info_t info;
    info.size = sizeof(hsa_amd_pointer_info_t);

    int  result = 0;                        // Assume non-GPU pointer

    hsa_status_t status = hsa_amd_pointer_info(ptr, &info,
                                          NULL, NULL, NULL);

    if (status == HSA_STATUS_SUCCESS) {
        if (info.type != HSA_EXT_POINTER_TYPE_UNKNOWN)
            result = 1;
    }

    MSG_DBG("roctb_is_ptr_gpu_accessible: Address %p. GPU access %d \n",
            ptr, result);

    return result;
}
//******************************************************************************
//                           -- roctb_get_ptr_type --
/**
 *   Return type of pointer
 *
 *   @param   ptr - \c [in] Pointer to query
 *
 *   @return Pointer type
 *
*/
//******************************************************************************
roctb_ptr_type roctb_get_ptr_type(void *ptr)
{
    roctb_ptr_type ptr_type = ROCTB_PTR_UNKNOWN;
    rocm_ptr_t rocm_ptr;

    hsa_status_t status = roctb_query_ptr_info(ptr, &rocm_ptr);

    if (status == HSA_STATUS_SUCCESS) {
        if ((rocm_ptr.info.type != HSA_EXT_POINTER_TYPE_UNKNOWN)) {
            ptr_type = ROCTB_PTR_GPU_ACCESSIBLE;
        }
    }

    return ptr_type;
}

//******************************************************************************
//                          -- roctb_copy_memory --
/**
 *   Copy memory
 *
 *   @param   dst  - \c [in]  Destination address
 *   @param   src  - \c [in]  Source address
 *   @param   size - \c [in]  Number of bytes to copy
 *
 *   @return  -1 if failure, otherwise number of bytes copied
 *
*/
//******************************************************************************
ssize_t roctb_copy_memory(void *dst, void *src, size_t size)
{
    ssize_t     result = -1;
    hsa_status_t status;
    rocm_ptr_t  dst_ptr;
    rocm_ptr_t  src_ptr;

    hsa_agent_t src_agent;
    hsa_agent_t dst_agent;

    hsa_agent_t common_gpu_agent;

    MSG_DBG("roctb_copy_memory: dst %p, src %p, size 0x%lx\n", dst, src, size);

    if (roctb_query_ptr_info(dst, &dst_ptr) != HSA_STATUS_SUCCESS
        ||
        roctb_query_ptr_info(src, &src_ptr) != HSA_STATUS_SUCCESS) {
        return result;
    }

    // Find and set correct GPU agent -----------------------------------------

    if (!roctb_find_common_gpu_agent(&dst_ptr, &src_ptr, &common_gpu_agent)) {

        uint32_t    accessible_mask_src;
        uint32_t    accessible_mask_dst;

        hsa_agent_t gpu_agent_src;
        hsa_agent_t gpu_agent_dst;

        roctb_get_accessible_mask(&src_ptr, &accessible_mask_src, &gpu_agent_src);
        roctb_get_accessible_mask(&dst_ptr, &accessible_mask_dst, &gpu_agent_dst);
        MSG_DBG("accessible_mask_src -1x%x\n", accessible_mask_src);
        MSG_DBG("accessible_mask_dst -1x%x\n", accessible_mask_dst);


        if ((accessible_mask_src & MEMORY_GPU_ACCESSIBLE) &&
            (accessible_mask_dst & MEMORY_GPU_ACCESSIBLE)) {
            MSG_DBG("Both source %p and destination %p is GPU accessible\n", src, dst);

            // If both GPU accessible -----------------------------------------

            src_agent = gpu_agent_src;
            dst_agent = gpu_agent_src;

            status = hsa_amd_agents_allow_access(0, &src_agent, NULL, dst);

            if (status != HSA_STATUS_SUCCESS) {
                MSG_ERR("Could not allow access to pointer %p Agent 0x%lx. Status 0x%x\n",
                dst, src_agent.handle, status);
                goto end;
            }
        } else if (!(accessible_mask_src & MEMORY_GPU_ACCESSIBLE)) {

            MSG_DBG("Source %p is not GPU accessible\n", src);

            // Source is not GPU accessible -----------------------------------

            src_agent = roctb_get_cpu_agent();

            if (!(accessible_mask_dst & MEMORY_GPU_ACCESSIBLE)) {
                dst_agent = roctb_get_cpu_agent();
                MSG_DBG("Destimation %p is not GPU accessible\n", src);
            } else if (!(accessible_mask_dst & MEMORY_CPU_ACCESSIBLE)) {

                MSG_DBG("Destimation %p also is not CPU accessible\n", src);

                dst_agent = gpu_agent_dst;

                status = hsa_amd_agents_allow_access(0, &src_agent, NULL, dst);
                                                // Allow CPU Access

                if (status != HSA_STATUS_SUCCESS) {
                    MSG_ERR("Could not allow CPU access to pointer %p Agent 0x%lx. Status 0x%x\n",
                    dst, src_agent.handle, status);
                    goto end;
                }
            }
        } else if (!(accessible_mask_dst & MEMORY_GPU_ACCESSIBLE)) {

            MSG_DBG("Destination %p is not GPU accessible\n", dst);

            // Destination is not GPU accessible ------------------------------

            dst_agent = roctb_get_cpu_agent();

            if (!(accessible_mask_src & MEMORY_GPU_ACCESSIBLE))
                src_agent = roctb_get_cpu_agent();
            else if (!(accessible_mask_src & MEMORY_CPU_ACCESSIBLE)) {

                src_agent = gpu_agent_src;

                status = hsa_amd_agents_allow_access(0, &dst_agent, NULL, src);
                                                // Allow CPU Access

                if (status != HSA_STATUS_SUCCESS) {
                    MSG_ERR("Could not allow CPU access to pointer %p Agent 0x%lx. Status 0x%x\n",
                    src, dst_agent.handle, status);
                    goto end;
                }
            }
        }
    } else {

        src_agent = common_gpu_agent;
        dst_agent = common_gpu_agent;
    }

     // Create a completion signal --------------------------------------------

    hsa_signal_t completion_signal;
    status = hsa_signal_create(0, 0, NULL, &completion_signal);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failed to create HSA signal.  Status 0xx%x\n", status);
        goto end;
    }


    hsa_signal_store_release(completion_signal, 0);
                                            // Set the completion signal value to 0


    // Perform an async copy --------------------------------------------------

    status = hsa_amd_memory_async_copy(dst, dst_agent, src, src_agent, size,
                                       0, NULL, completion_signal);

    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failure to async. copy.  Status 0x%x\n", status);
        goto destroy_signal;
    }

    status = hsa_signal_wait_acquire(completion_signal,
                                     HSA_SIGNAL_CONDITION_EQ,
                                     0, UINT64_MAX, HSA_WAIT_STATE_BLOCKED);

    if (status == HSA_STATUS_SUCCESS) {
        result = size;
    } else {
        MSG_ERR("Failure to wait copy completion.  Status 0x%x\n", status);
    }

destroy_signal:
    status = hsa_signal_destroy(completion_signal);
    if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("Failed to destroy signal.  Status 0x%x\n", status);
    }

end:
    return result;
}


//******************************************************************************
//                        -- roctb_ipc_memory_attach --
/**
 *   Import shared memory in the current process
 *
 *   @param   handle - \c [in] IPC memory handle
 *   @param   len    - \c [in] Length of memory
 *   @param   ptr    - \c [out] Address to use.
 *
 *   @return  HSA status
 *
*/
//******************************************************************************
hsa_status_t  roctb_ipc_memory_attach(const hsa_amd_ipc_memory_t* handle,
                                      size_t len, void **ptr)
{

    hsa_status_t status = hsa_amd_ipc_memory_attach(handle,
                              len,
                              roctb_cfg.num_of_gpu,
                              roctb_cfg.agents.gpu_agent,
                              ptr);


    return status;
}


//******************************************************************************
//                        -- roctb_ipc_memory_detach --
/**
 *   Decrement reference count for sharing
 *
 *   @param   ptr - \c [in]  Pointer to shared memory
 *
*/
//******************************************************************************
void roctb_ipc_memory_detach(void *ptr)
{
   hsa_status_t status = hsa_amd_ipc_memory_detach(ptr);

   if (status != HSA_STATUS_SUCCESS) {
        MSG_ERR("hsa_amd_ipc_memory_detach failure. Ptr %p. Status 0x%x\n", 
                ptr, status);
   }
}

//******************************************************************************
//                        -- roctb_cma_operation --
/**
 *   Issue CMA read/write request
 *
 *   @param   pid    - \c [in] Process id for remote memory address
 *   @param   local  - \c [in] Address in local process address space
 *   @param   remote - \c [in] Address in remote process address space
 *   @param   size   - \c [in] Size of memory
 *   @param   read   - \c [in] true if it is read operation, false - otherwise
 *
 *   @return  true if operation was sucessfull 
 *            false otherwise 
 */
//******************************************************************************
bool roctb_cma_operation(pid_t pid, void *local, void *remote, 
                        size_t size, bool read)
{
    HSAKMT_STATUS   status;
    bool            ret = true;
    HSAuint64       SizeCopied;
    HsaMemoryRange  local_iov;
    HsaMemoryRange  remote_iov;

    local_iov.MemoryAddress = local;
    local_iov.SizeInBytes   = size;

    remote_iov.MemoryAddress = remote;
    remote_iov.SizeInBytes   = size;
    
    if (read)
        status = hsaKmtProcessVMRead(pid, &local_iov, 1, &remote_iov, 1, &SizeCopied);
    else        
        status = hsaKmtProcessVMWrite(pid, &local_iov, 1, &remote_iov, 1, &SizeCopied);

    if (status  != HSAKMT_STATUS_SUCCESS) {
            MSG_ERR("CMA operation failed. Status  %d", status);
            ret = false;
    } else {
        if (SizeCopied != size) {
            MSG_ERR("Doesn't copy all data\n");
            ret = true;
        }

    }

    return ret;
}                             
