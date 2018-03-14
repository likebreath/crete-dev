/*
 * QEMU AMD PC-Net II (Am79C970A) PCI emulation
 *
 * Copyright (c) 2004 Antony T Curtis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* This software was written to be compatible with the specification:
 * AMD Am79C970A PCnet-PCI II Ethernet Controller Data-Sheet
 * AMD Publication# 19436  Rev:E  Amendment/0  Issue Date: June 2000
 */

#include "hw/pci/pci.h"
#include "net/net.h"
#include "hw/loader.h"
#include "qemu/timer.h"
#include "sysemu/dma.h"
#include "sysemu/sysemu.h"
#include "trace.h"

#include "pcnet.h"
#include "bc_pcnet.c"

//#define PCNET_DEBUG
//#define PCNET_DEBUG_IO
//#define PCNET_DEBUG_BCR
//#define PCNET_DEBUG_CSR
//#define PCNET_DEBUG_RMD
//#define PCNET_DEBUG_TMD
//#define PCNET_DEBUG_MATCH

#define TYPE_PCI_PCNET "pcnet"

#define PCI_PCNET(obj) \
     OBJECT_CHECK(PCIPCNetState, (obj), TYPE_PCI_PCNET)

typedef struct {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    PCNetState state;
    MemoryRegion io_bar;
} PCIPCNetState;

static void pcnet_aprom_writeb(void *opaque, uint32_t addr, uint32_t val)
{
    PCNetState *s = opaque;

    trace_pcnet_aprom_writeb(opaque, addr, val);
    if (BCR_APROMWE(s)) {
        s->prom[addr & 15] = val;
    }
}

static uint32_t pcnet_aprom_readb(void *opaque, uint32_t addr)
{
    PCNetState *s = opaque;
    uint32_t val = s->prom[addr & 15];

    trace_pcnet_aprom_readb(opaque, addr, val);
    return val;
}

static uint64_t pcnet_ioport_read(void *opaque, hwaddr addr,
                                  unsigned size)
{
    PCNetState *d = opaque;

    trace_pcnet_ioport_read(opaque, addr, size);
    if (addr < 0x10) {
        if (!BCR_DWIO(d) && size == 1) {
            return pcnet_aprom_readb(d, addr);
        } else if (!BCR_DWIO(d) && (addr & 1) == 0 && size == 2) {
            return pcnet_aprom_readb(d, addr) |
                   (pcnet_aprom_readb(d, addr + 1) << 8);
        } else if (BCR_DWIO(d) && (addr & 3) == 0 && size == 4) {
            return pcnet_aprom_readb(d, addr) |
                   (pcnet_aprom_readb(d, addr + 1) << 8) |
                   (pcnet_aprom_readb(d, addr + 2) << 16) |
                   (pcnet_aprom_readb(d, addr + 3) << 24);
        }
    } else {
        if (size == 2) {
            return pcnet_ioport_readw(d, addr);
        } else if (size == 4) {
            return pcnet_ioport_readl(d, addr);
        }
    }
    return ((uint64_t)1 << (size * 8)) - 1;
}

static void pcnet_ioport_write(void *opaque, hwaddr addr,
                               uint64_t data, unsigned size)
{
    PCNetState *d = opaque;

    trace_pcnet_ioport_write(opaque, addr, data, size);
    if (addr < 0x10) {
        if (!BCR_DWIO(d) && size == 1) {
            pcnet_aprom_writeb(d, addr, data);
        } else if (!BCR_DWIO(d) && (addr & 1) == 0 && size == 2) {
            pcnet_aprom_writeb(d, addr, data & 0xff);
            pcnet_aprom_writeb(d, addr + 1, data >> 8);
        } else if (BCR_DWIO(d) && (addr & 3) == 0 && size == 4) {
            pcnet_aprom_writeb(d, addr, data & 0xff);
            pcnet_aprom_writeb(d, addr + 1, (data >> 8) & 0xff);
            pcnet_aprom_writeb(d, addr + 2, (data >> 16) & 0xff);
            pcnet_aprom_writeb(d, addr + 3, data >> 24);
        }
    } else {
        if (size == 2) {
            pcnet_ioport_writew(d, addr, data);
        } else if (size == 4) {
            pcnet_ioport_writel(d, addr, data);
        }
    }
}

extern char crete_vd_state[sizeof(PCNetState)];
extern void crete_bc_print(const char *);
extern bool crete_is_symbolic(uint64_t);

uint64_t dispatch_vd_op(uint64_t v_addr, uint64_t p_addr, int size, uint64_t value, int is_write)
{
    if(crete_is_symbolic(value))
    {
        crete_bc_print("dispatch_vd_op(): symbolic input 'value'");
    } else {
        crete_bc_print("dispatch_vd_op(): concrete input 'value'");
    }
    if(is_write)
    {
        pcnet_ioport_write(crete_vd_state, p_addr, value, size);
        return 0;
    } else {
        return pcnet_ioport_read(crete_vd_state, p_addr, size);
    }
}
