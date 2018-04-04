#include "stdint.h"
#include "stdbool.h"
#include "string.h"

void crete_enable_fork();
void crete_disable_fork();
void crete_enable_symbolic_execution();
void crete_disable_symbolic_execution();

struct CPUStateElement
{
    uint32_t m_offset;
    uint32_t m_size;
    char *m_data;
};

struct MemoryElement
{
    uint8_t m_value;
    uint64_t m_static_addr;
};

extern uint64_t crete_get_dynamic_addr(uint64_t);

__attribute__((noinline)) static void internal_sync_cpu_state(uint8_t *cpu_state, uint32_t cs_size,
        const struct CPUStateElement *sync_table, uint32_t st_size)
{
    const struct CPUStateElement *current_element;
    for(uint32_t i = 0; i < st_size; ++i)
    {
        current_element = sync_table + i;
        uint32_t offset = current_element->m_offset;
        uint32_t size = current_element->m_size;
        char *data = current_element->m_data;
        for(uint32_t j = 0; j < size; ++j)
        {
            cpu_state[offset+j] = data[j];
        }
    }
}

__attribute__((noinline)) static void internal_crete_sync_memory(const struct MemoryElement *sync_table, uint32_t st_size)
{
    const struct MemoryElement *current_element;
    for(uint32_t i = 0; i < st_size; ++i)
    {
        current_element = sync_table + i;
        uint64_t static_addr = current_element->m_static_addr;
        uint8_t value = current_element->m_value;

        uint64_t dynamic_addr = crete_get_dynamic_addr(static_addr);
        uint8_t *ptr_current_value = (uint8_t *)dynamic_addr;

        if(*ptr_current_value != value)
        {
            *ptr_current_value = value;
        }
    }
}

void crete_sync_cpu_state(uint8_t *cpu_state, uint32_t cs_size,
        const struct CPUStateElement *sync_table, uint32_t st_size)
{
    crete_disable_fork();
    internal_sync_cpu_state(cpu_state, cs_size, sync_table, st_size);
    crete_enable_fork();
}

void crete_sync_memory(const struct MemoryElement *sync_table, uint32_t st_size)
{
    crete_disable_fork();
    internal_crete_sync_memory(sync_table, st_size);
    crete_enable_fork();
}

struct VirtualDeviceOps
{
    uint64_t m_virt_addr;
    uint64_t m_phys_addr;
};

// Updated by captured trace, check llvm-translator
const struct VirtualDeviceOps *vd_ops_table;
uint32_t vd_ops_table_size;

static const struct VirtualDeviceOps *get_current_vd_entry_func_op(uint64_t addr)
{
    const struct VirtualDeviceOps *current_vd_op;
    for(uint32_t i = 0; i < vd_ops_table_size; ++i)
    {
        current_vd_op = vd_ops_table + i;
        if(addr == current_vd_op->m_virt_addr)
        {
            return current_vd_op;
        }
    }

    return 0;
}

static const struct VirtualDeviceOps *get_current_vd_dma_op(uint64_t dma_addr)
{
    const struct VirtualDeviceOps *current_vd_op;
    for(uint32_t i = 0; i < vd_ops_table_size; ++i)
    {
        current_vd_op = vd_ops_table + i;
        if(dma_addr == current_vd_op->m_phys_addr)
        {
            return current_vd_op;
        }
    }

    return 0;
}

__attribute__((noinline)) static void internal_crete_sync_device(
        const struct VirtualDeviceOps *sync_table, uint32_t st_size)
{
    // Update vd_ops_table
    vd_ops_table = sync_table;
    vd_ops_table_size = st_size;
}

void crete_sync_device(const struct VirtualDeviceOps *sync_table, uint32_t st_size)
{
    crete_disable_fork();
    internal_crete_sync_device(sync_table, st_size);
    crete_enable_fork();
}

extern uint64_t dispatch_vd_op(uint64_t v_addr, uint64_t p_addr, int size, uint64_t value, int is_write);
extern void crete_bc_print(const char *);
extern bool crete_is_symbolic(uint64_t);

uint64_t crete_try_device_memory_access(uint64_t addr, int size, uint64_t value, int is_write, int *is_device_access)
{
    crete_disable_fork();
    const struct VirtualDeviceOps *current_vd_op = get_current_vd_entry_func_op(addr);
    if(!current_vd_op)
    {
        *is_device_access = 0;
        crete_enable_fork();
        return 0;
    }
    crete_enable_fork();

    *is_device_access = 1;

#if defined(CRETE_BC_DEBUG) || 1
//    crete_bc_print("calling dispatch_vd_op():");

    if(crete_is_symbolic(value))
    {
        crete_bc_print("symbolic input 'value' !");
    }
    if(crete_is_symbolic(addr))
    {
        crete_bc_print("symbolic input 'addr' !");
    }
#endif
    crete_enable_symbolic_execution();
    uint64_t ret = dispatch_vd_op(addr, current_vd_op->m_phys_addr, size, value, is_write);
    crete_disable_symbolic_execution();

    return ret;
}

typedef struct CPUStateElement VDStateElement;
void crete_sync_vd_state(uint8_t *vd_state, uint32_t es_size,
        const VDStateElement *sync_table, uint32_t st_size)
{
    crete_disable_fork();
    internal_sync_cpu_state(vd_state, es_size, sync_table, st_size);
    crete_enable_fork();
}

bool crete_replay_dma(uint64_t dma_addr, uint8_t *buf, int len, bool is_write)
{
    crete_disable_fork();

    const struct VirtualDeviceOps *current_vd_op = get_current_vd_dma_op(dma_addr);
    if(!current_vd_op)
    {
        crete_enable_fork();
        return false;
    }

    uint64_t guest_virt_addr = current_vd_op->m_virt_addr;
    uint64_t dynamic_addr = crete_get_dynamic_addr(guest_virt_addr);

    {
        uint8_t *check_symbolic;
        if(is_write)
        {
            check_symbolic = buf;
        } else {
            check_symbolic = (uint8_t *)dynamic_addr;
        }

        for(int i = 0; i < len; ++i)
        {
            if(crete_is_symbolic(*(check_symbolic+i)))
            {
                if(is_write)
                {
                    crete_bc_print("crete_replay_dma(): symbolic dma write (dev -> ram)!");
                } else {
                    crete_bc_print("crete_replay_dma(): symbolic dma read (ram -> dma)!");
                }
            }
        }
    }

    if(is_write)
    {
        memcpy((void *)dynamic_addr, buf, len);
    } else {
        memcpy(buf, (void *)dynamic_addr, len);
    }

    crete_enable_fork();

    return true;
}
