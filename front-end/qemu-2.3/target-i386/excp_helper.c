/*
 *  x86 exception helpers
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
#include "qemu/log.h"
#include "sysemu/sysemu.h"
#include "exec/helper-proto.h"

#if defined(CRETE_CONFIG) && !defined(CRETE_LLVM_LIB) || 1
#include "runtime-dump/runtime-dump.h"
extern CPUArchState *g_cpuState_bct;
#endif // #if defined(CRETE_CONFIG) && !defined(CRETE_LLVM_LIB)
//#define DEBUG_PCALL

#if 0
#define raise_exception_err(env, a, b)                                  \
    do {                                                                \
        qemu_log("raise_exception line=%d\n", __LINE__);                \
        (raise_exception_err)(env, a, b);                               \
    } while (0)
#endif

void helper_raise_interrupt(CPUX86State *env, int intno, int next_eip_addend)
{
    raise_interrupt(env, intno, 1, 0, next_eip_addend);
}

void helper_raise_exception(CPUX86State *env, int exception_index)
{
    raise_exception(env, exception_index);
}

/*
 * Check nested exceptions and change to double or triple fault if
 * needed. It should only be called, if this is not an interrupt.
 * Returns the new exception number.
 */
static int check_exception(CPUX86State *env, int intno, int *error_code)
{
    int first_contributory = env->old_exception == 0 ||
                              (env->old_exception >= 10 &&
                               env->old_exception <= 13);
    int second_contributory = intno == 0 ||
                               (intno >= 10 && intno <= 13);

    qemu_log_mask(CPU_LOG_INT, "check_exception old: 0x%x new 0x%x\n",
                env->old_exception, intno);

#if !defined(CONFIG_USER_ONLY)
    if (env->old_exception == EXCP08_DBLE) {
        if (env->hflags & HF_SVMI_MASK) {
            cpu_vmexit(env, SVM_EXIT_SHUTDOWN, 0); /* does not return */
        }

        qemu_log_mask(CPU_LOG_RESET, "Triple fault\n");

        qemu_system_reset_request();
        return EXCP_HLT;
    }
#endif

    if ((first_contributory && second_contributory)
        || (env->old_exception == EXCP0E_PAGE &&
            (second_contributory || (intno == EXCP0E_PAGE)))) {
        intno = EXCP08_DBLE;
        *error_code = 0;
    }

    if (second_contributory || (intno == EXCP0E_PAGE) ||
        (intno == EXCP08_DBLE)) {
        env->old_exception = intno;
    }

    return intno;
}

/*
 * Signal an interruption. It is executed in the main CPU loop.
 * is_int is TRUE if coming from the int instruction. next_eip is the
 * env->eip value AFTER the interrupt instruction. It is only relevant if
 * is_int is TRUE.
 */
static void QEMU_NORETURN raise_interrupt2(CPUX86State *env, int intno,
                                           int is_int, int error_code,
                                           int next_eip_addend)
{
    //CRETE: for interrupt offline replay
#if defined(CRETE_CONFIG) || 1
    /* BOBO:xxx assumption: all the interrupts/exceptions should finally get here
     * */
    if(flag_rt_dump_enable) {
        assert(env == g_cpuState_bct && "[CRETE ERROR] Global pointer to CPU State is changed.\n");

        // 0 means the current TB is being executed (but being interrupted)
        if(crete_post_cpu_tb_exec(env, rt_dump_tb, 0, env->eip)) {
            add_qemu_interrupt_state(runtime_env, intno, is_int, error_code, next_eip_addend);

#if defined(CRETE_DEBUG)
            if(is_int && next_eip_addend){
                fprintf(stderr, "[CRETE Warning] next_eip_addend is not zero. Check whether the precise "
                        "interrupt reply is correct. [check gen_intermediate_code_crete()]\n");
            }

            fprintf(stderr, "tb-%lu (pc-%p) is interrupted.\n",
                    rt_dump_tb_count - 1, (void *)(uint64_t)rt_dump_tb->pc);

            fprintf(stderr, "[raise_interrupt] intno = %d, is_int = %d, "
                    "error_code = %d, next_eip_addend = %d,"
                    "env->eip = %p\n",
                    intno, is_int, error_code,
                    next_eip_addend, (void *)(uint64_t)env->eip);
#endif
        }
    }
#endif

    CPUState *cs = CPU(x86_env_get_cpu(env));

    if (!is_int) {
        cpu_svm_check_intercept_param(env, SVM_EXIT_EXCP_BASE + intno,
                                      error_code);
        intno = check_exception(env, intno, &error_code);
    } else {
        cpu_svm_check_intercept_param(env, SVM_EXIT_SWINT, 0);
    }

    cs->exception_index = intno;
    env->error_code = error_code;
    env->exception_is_int = is_int;
    env->exception_next_eip = env->eip + next_eip_addend;
    cpu_loop_exit(cs);
}

/* shortcuts to generate exceptions */

void QEMU_NORETURN raise_interrupt(CPUX86State *env, int intno, int is_int,
                                   int error_code, int next_eip_addend)
{
    raise_interrupt2(env, intno, is_int, error_code, next_eip_addend);
}

void raise_exception_err(CPUX86State *env, int exception_index,
                         int error_code)
{
    raise_interrupt2(env, exception_index, 0, error_code, 0);
}

void raise_exception(CPUX86State *env, int exception_index)
{
    raise_interrupt2(env, exception_index, 0, 0, 0);
}