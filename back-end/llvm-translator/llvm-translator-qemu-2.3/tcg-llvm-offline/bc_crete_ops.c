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

// uint64_t e1000_mmio_read(void *opaque, hwaddr addr, unsigned size);

static const struct VirtualDeviceOps *get_current_vd_op(uint64_t addr)
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

extern uint64_t dispatch_vd_op(uint64_t v_addr, uint64_t p_addr, int size, uint64_t value, int is_write);
uint64_t crete_try_device_memory_access(uint64_t addr, int size, uint64_t value, int is_write, int *is_device_access)
{
    const struct VirtualDeviceOps *current_vd_op = get_current_vd_op(addr);
    if(!current_vd_op)
    {
        *is_device_access = 0;
        return 0;
    }

    *is_device_access = 1;
    return dispatch_vd_op(addr, current_vd_op->m_phys_addr, size, value, is_write);
}

typedef struct CPUStateElement E1000StateElement;
void crete_sync_e1000_state(uint8_t *e1000_state, uint32_t es_size,
        const E1000StateElement *sync_table, uint32_t st_size)
{
    internal_sync_cpu_state(e1000_state, es_size, sync_table, st_size);
}
