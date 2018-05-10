#include "stdint.h"
#include "assert.h"

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

struct PortIOElement
{
    uint64_t m_port;
    uint64_t m_value;
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

const struct PortIOElement *crete_pio_table;
uint32_t crete_pio_table_size;

uint64_t crete_port_io_read(uint32_t port_addr)
{
    assert(crete_pio_table_size != 0);
    assert(port_addr == crete_pio_table->m_port);

    uint64_t ret = crete_pio_table->m_value;

    crete_pio_table++;
    crete_pio_table_size--;

    return ret;
}

void set_current_pio_table(const struct PortIOElement *table, uint32_t size)
{
    crete_pio_table = table;
    crete_pio_table_size = size;
}
