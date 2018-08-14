/*
 * crete-fw-exec.cpp
 *
 *  Created on: Aug 13, 2018
 *      Author: chenbo
 */

#include "crete-fw-exec.h"

#include <stdio.h>
#include <cstdlib>
using namespace std;

static struct em8051 *fw_emu = 0;

int crete_launch_fw()
{
    char *p_fw= getenv("CRETE_E2E_FW_PATH");
    if(!p_fw)
    {
        fprintf(stderr, "[CRETE ERROR] crete_launch_fw(): 'CRETE_E2E_FW_PATH' is not set.\n");
        return -1;
    }

    fw_emu = alloc_em8051();

    reset(fw_emu, 1);
    if(load_obj(fw_emu, p_fw) !=0)
    {
        fprintf(stderr, "[CRETE ERROR] crete_launch_fw(): load fw file error, '%s'\n", p_fw);
        return -1;
    }

    return 0;
}

void crete_clear_fw()
{
    free_em8051(fw_emu);
}

struct em8051 *crete_get_fw_emu_state()
{
    return fw_emu;
}

uint64_t crete_fw_trans_exec(struct em8051 *emu, uint64_t val)
{
    return emu8051_trans_exec(emu, val);
}
