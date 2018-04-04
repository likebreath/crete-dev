/*
 * bc_crete_dma.h
 *
 *  Created on: Apr 4, 2018
 *      Author: chenbo
 */

#ifndef RUNTIME_DUMP_BC_CRETE_DMA_H_
#define RUNTIME_DUMP_BC_CRETE_DMA_H_

extern bool crete_replay_dma(uint64_t addr, uint8_t *buf, int len, bool is_write);

inline bool crete_dma_address_space_rw(void *_as, hwaddr addr, uint8_t *buf,
        int len, bool is_write)
{
    bool ret = crete_replay_dma(addr, buf, len, is_write);
    assert(ret);
    return ret;
}

#endif /* RUNTIME_DUMP_BC_CRETE_DMA_H_ */
