/*
 *  x86 misc helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "cpu.h"

uint64_t crete_try_device_memory_access(uint64_t addr, int size, uint64_t value, int is_write, int *is_device_access);

void helper_outb(uint32_t port, uint32_t data)
{
    int is_device_access;
    crete_try_device_memory_access(port, 1, data & 0xff, 1, &is_device_access);
    assert(is_device_access);
}

target_ulong helper_inb(uint32_t port)
{
    int is_device_access;
    target_ulong ret = crete_try_device_memory_access(port, 1, 0, 0, &is_device_access);
    assert(is_device_access);

    return ret;
}

void helper_outw(uint32_t port, uint32_t data)
{
    int is_device_access;
    crete_try_device_memory_access(port, 2, data & 0xffff, 1, &is_device_access);
    assert(is_device_access);
}

target_ulong helper_inw(uint32_t port)
{
    int is_device_access;
    target_ulong ret = crete_try_device_memory_access(port, 2, 0, 0, &is_device_access);
    assert(is_device_access);

    return ret;
}

void helper_outl(uint32_t port, uint32_t data)
{
    int is_device_access;
    crete_try_device_memory_access(port, 4, data, 1, &is_device_access);
    assert(is_device_access);
}

target_ulong helper_inl(uint32_t port)
{
    int is_device_access;
    target_ulong ret = crete_try_device_memory_access(port, 4, 0, 0, &is_device_access);
    assert(is_device_access);

    return ret;
}
