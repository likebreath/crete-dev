/*
 * tc_elem_checker.hpp
 *
 *  Created on: Nov 30, 2017
 *      Author: Bo Chen (chenbo@pdx.edu)
 */

#ifndef LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_
#define LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_

#include <vector>

using namespace std;

// Function return as pointer values
static vector<string> init_ptr_ret_funcs()
{
    static vector<string> list;

    list.push_back("__alloc_ei_netdev");
    list.push_back("alloc_etherdev_mqs");
    list.push_back("alloc_pages_current");
    list.push_back("__alloc_skb");
    list.push_back("dma_pool_alloc");
    list.push_back("__kmalloc");
    list.push_back("kmem_cache_alloc_trace");
    list.push_back("__napi_alloc_skb");
    list.push_back("netdev_alloc_frag");
    list.push_back("__netdev_alloc_skb");
    list.push_back("scsi_host_alloc");
    list.push_back("vzalloc");

    list.push_back("pci_get_device");
    list.push_back("pci_get_domain_bus_and_slot");
    list.push_back("pci_iomap");
    list.push_back("pci_ioremap_bar");
    list.push_back("snd_pci_quirk_lookup");

    list.push_back("dma_pool_create");

    return list;
};

const static vector<string> ptr_ret_funcs = init_ptr_ret_funcs();

static inline
bool match_ptr_ret_funcs(const string name)
{
    for(vector<string>::const_iterator it = ptr_ret_funcs.begin();
            it != ptr_ret_funcs.end(); ++it) {
        if(name.find(*it) != string::npos) return true;
    }

    return false;
}

// ------------------------------------------------
static inline
bool __CTCEM_ret_ptr(const vector<uint8_t> &data)
{
    if(data == vector<uint8_t>(data.size(), 0))
    {
        return true;
    } else {
        return false;
    }
}

// @ret: true, meaningful tc_elem; false, not meaningful tc_elem
static inline
bool check_tc_elem_meaningfulness(const vector<uint8_t> &data,
        const string &name)
{
    bool ret = true;

    if(match_ptr_ret_funcs(name))
    {
        ret = __CTCEM_ret_ptr(data);
    }

    return ret;
}

// ------------------------------------------------

#endif /* LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_ */
