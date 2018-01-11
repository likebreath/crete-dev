#include "stdint.h"

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
    internal_sync_cpu_state(cpu_state, cs_size, sync_table, st_size);
}

void crete_sync_memory(const struct MemoryElement *sync_table, uint32_t st_size)
{
    internal_crete_sync_memory(sync_table, st_size);
}

struct VirtualDeviceOps
{
    uint64_t m_virt_addr;
    uint64_t m_phys_addr;
};

// Updated by captured trace, check llvm-translator
const struct VirtualDeviceOps *vd_ops_table;
uint32_t vd_ops_table_size;

static int is_vd_op(uint64_t addr)
{
    const struct VirtualDeviceOps *current_vd_op;
    for(uint32_t i = 0; i < vd_ops_table_size; ++i)
    {
        current_vd_op = vd_ops_table + i;
        if(addr == current_vd_op->m_virt_addr)
        {
            return 1;
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
    internal_crete_sync_device(sync_table, st_size);
}

extern int replay_vd(uint64_t virt_addr, int size, int is_write);
uint64_t crete_try_device_memory_access(uint64_t addr, int size, int *is_device_access, int is_write)
{
    if(!is_vd_op(addr))
    {
        *is_device_access = 0;
        return 0;
    }

    *is_device_access = 1;
    return replay_vd(addr, size, is_write);
}
