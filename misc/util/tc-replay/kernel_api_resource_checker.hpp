/*
 * kernel_api_resource_checker.hpp
 *
 *  Created on: Jun 6, 2018
 *      Author: chenbo
 */

#ifndef UTIL_TC_REPLAY_KERNEL_API_RESOURCE_CHECKER_HPP_
#define UTIL_TC_REPLAY_KERNEL_API_RESOURCE_CHECKER_HPP_

#include <stdint.h>

#include <boost/filesystem/path.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>

#include <crete/kernel_api_resource_monitor.h>

namespace crete
{
using namespace std;
namespace fs = boost::filesystem;

// <func_name, failure_type>
typedef boost::unordered_map<string, int> kapi_set_ty;
// <alloc_func, dealloc_func>
typedef boost::unordered_multimap<string, string> alloc_dealloc_pair_ty;
// <alloc/dealloc_func, rm_info *>
typedef boost::unordered_multimap<string, const CRETE_RM_INFO *> checkee_ty;

// TODO: 1. Combine __CRETE_KAPI_RC_ADD_ALLOC and __CRETE_KAPI_RC_ADD_FREE
//       2. Use static member and method in CC_ResourceLeak
class CC_ResourceLeak
{
private:
    kapi_set_ty m_alloc_kapis;
    kapi_set_ty m_dealloc_kapis;
    alloc_dealloc_pair_ty m_pairs;

public:
    CC_ResourceLeak();
    ~CC_ResourceLeak() {};

    void check_rm_array(const CRETE_RM_INFO *rm_array, int size,
            vector<string> &bug_info, vector<string> &warning_info);
};

class CreteKernalApiChecker
{
private:
    uint32_t m_buf_size;
    char *m_buffer;

    int m_rm_array_size;
    const CRETE_RM_INFO *m_rm_array;

    CC_ResourceLeak m_checker_rl;

    vector<string> m_bug_info;
    vector<string> m_warning_info;

public:
    CreteKernalApiChecker();
    ~CreteKernalApiChecker();

    void perform_check();
    const vector<string> &get_bug_info() const {return m_bug_info;}
    const vector<string> &get_warning_info() const {return m_warning_info;}

private:
    void read_from_procfs();
    void print_rm_array();
};

} // namespace crete

#endif /* UTIL_TC_REPLAY_KERNEL_API_RESOURCE_CHECKER_HPP_ */
