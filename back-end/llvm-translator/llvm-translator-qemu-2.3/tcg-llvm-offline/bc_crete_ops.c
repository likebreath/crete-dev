#include "stdint.h"
#include "string.h"

struct CPUStateElement{
  uint32_t m_offset;
  uint32_t m_size;
  char *m_data;
};

void internal_sync_cpu_state(uint8_t *cpu_state, uint32_t cs_size,
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

void sync_cpu_state(uint8_t *cpu_state, uint32_t cs_size,
                    const struct CPUStateElement *sync_table, uint32_t st_size)
{
  internal_sync_cpu_state(cpu_state, cs_size, sync_table, st_size);
}
