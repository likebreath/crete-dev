#include "crete-replayer/crete_debug.h"
#include "crete-replayer/qemu_rt_info.h"

#include <fstream>

namespace crete
{
namespace debug
{

void print_trace_tag(const crete::creteTraceTag_ty& trace_tag)
{
    for(crete::creteTraceTag_ty::const_iterator it = trace_tag.begin();
            it != trace_tag.end(); ++it) {
        fprintf(stderr, "tb-%lu: pc=%p, last_opc = %p",
                it->m_tb_count, (void *)it->m_tb_pc,
                (void *)(uint64_t)it->m_last_opc);
        fprintf(stderr, ", br_taken = ");
        crete::print_br_taken(it->m_br_taken);
        fprintf(stderr,"\n");
    }
}

} // namespace debug
} // namespace crete
