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

uint64_t crete_port_io_read(uint32_t port_addr);

target_ulong helper_inb(uint32_t port)
{
    return crete_port_io_read(port);
}

target_ulong helper_inw(uint32_t port)
{
    return crete_port_io_read(port);
}

target_ulong helper_inl(uint32_t port)
{
    return crete_port_io_read(port);
}

void helper_outb(uint32_t port, uint32_t data)
{
    ;
}

void helper_outw(uint32_t port, uint32_t data)
{
    ;
}


void helper_outl(uint32_t port, uint32_t data)
{
    ;
}
