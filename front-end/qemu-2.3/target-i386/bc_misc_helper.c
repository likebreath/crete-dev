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

void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0)
{
#ifdef TARGET_X86_64
    if (!(env->cr[0] & CR0_PG_MASK) && (new_cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME)) {
        /* enter in long mode */
        /* XXX: generate an exception */
        if (!(env->cr[4] & CR4_PAE_MASK))
            return;
        env->efer |= MSR_EFER_LMA;
        env->hflags |= HF_LMA_MASK;
    } else if ((env->cr[0] & CR0_PG_MASK) && !(new_cr0 & CR0_PG_MASK) &&
               (env->efer & MSR_EFER_LMA)) {
        /* exit long mode */
        env->efer &= ~MSR_EFER_LMA;
        env->hflags &= ~(HF_LMA_MASK | HF_CS64_MASK);
        env->eip &= 0xffffffff;
    }
#endif
    env->cr[0] = new_cr0 | CR0_ET_MASK;
}

void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3)
{
    env->cr[3] = new_cr3;
}

void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4)
{
    /* SSE handling */
    if (!(env->features[FEAT_1_EDX] & CPUID_SSE)) {
        new_cr4 &= ~CR4_OSFXSR_MASK;
    }
    env->hflags &= ~HF_OSFXSR_MASK;
    if (new_cr4 & CR4_OSFXSR_MASK) {
        env->hflags |= HF_OSFXSR_MASK;
    }

    if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SMAP)) {
        new_cr4 &= ~CR4_SMAP_MASK;
    }
    env->hflags &= ~HF_SMAP_MASK;
    if (new_cr4 & CR4_SMAP_MASK) {
        env->hflags |= HF_SMAP_MASK;
    }

    env->cr[4] = new_cr4;
}

void helper_write_crN(CPUX86State *env, int reg, target_ulong t0)
{
//    cpu_svm_check_intercept_param(env, SVM_EXIT_WRITE_CR0 + reg, 0);
    switch (reg) {
    case 0:
        cpu_x86_update_cr0(env, t0);
        break;
    case 3:
        cpu_x86_update_cr3(env, t0);
        break;
    case 4:
        cpu_x86_update_cr4(env, t0);
        break;
    case 8:
//        if (!(env->hflags2 & HF2_VINTR_MASK)) {
//            cpu_set_apic_tpr(x86_env_get_cpu(env)->apic_state, t0);
//        }
        env->v_tpr = t0 & 0x0f;
        break;
    default:
        env->cr[reg] = t0;
        break;
    }
}
