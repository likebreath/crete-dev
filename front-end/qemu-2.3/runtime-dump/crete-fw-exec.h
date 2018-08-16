/*
 * crete-fw-exec.h
 *
 *  Created on: Aug 13, 2018
 *      Author: chenbo
 */

#ifndef RUNTIME_DUMP_CRETE_FW_EXEC_H_
#define RUNTIME_DUMP_CRETE_FW_EXEC_H_

#include "stdint.h"

/*****************************/
/* C code */
#ifdef __cplusplus
extern "C" {
#endif

// For qemu main
int crete_launch_fw(void);
void crete_clear_fw(void);

// For crete tracing and VD
struct em8051 *crete_get_fw_emu_state(void);
uint64_t crete_fw_trans_exec(struct em8051 *emu, uint64_t val);
uint32_t crete_get_fw_trans_count(void);
void crete_reset_fw_trans_count(void);

#ifdef __cplusplus
}
#endif

/*****************************/
/* C++ code */
#ifdef __cplusplus

#include "crete_emu8051_tracing.hpp"

#endif  /* __cplusplus end*/

#endif /* RUNTIME_DUMP_CRETE_FW_EXEC_H_ */
