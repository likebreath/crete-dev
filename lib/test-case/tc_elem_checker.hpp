/*
 * tc_elem_checker.hpp
 *
 *  Created on: Nov 30, 2017
 *      Author: Bo Chen (chenbo@pdx.edu)
 */

#ifndef LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_
#define LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_

#include <vector>
#include <assert.h>

using namespace std;

// Function return as pointer values
static set<string> init_ptr_ret_funcs()
{
    set<string> list;

    // Note: should be consistent with list of functions in
    // "guest/kernel-modules/kprobe_kernel_api"
    list.insert("__alloc_ei_netdev");
    list.insert("__alloc_pages_nodemask");
    list.insert("__alloc_skb");
    list.insert("__kmalloc");
    list.insert("__napi_alloc_skb");
    list.insert("__netdev_alloc_skb");
    list.insert("__pskb_pull_tail");
    list.insert("__request_region");
    list.insert("alloc_etherdev_mqs");
    list.insert("alloc_pages_current");
    list.insert("build_skb");
    list.insert("dev_get_drvdata");
    list.insert("dma_pool_alloc");
    list.insert("dma_pool_create");
    list.insert("ioremap_nocache");
    list.insert("kmem_cache_alloc_trace");
    list.insert("netdev_alloc_frag");
    list.insert("pci_get_device");
    list.insert("pci_get_domain_bus_and_slot");
    list.insert("pci_iomap");
    list.insert("pci_ioremap_bar");
    list.insert("scsi_host_alloc");
    list.insert("sg_next");
    list.insert("snd_ctl_new1");
    list.insert("snd_info_create_card_entry");
    list.insert("snd_pci_quirk_lookup");
    list.insert("trace_event_buffer_reserve");
    list.insert("vzalloc");

    return list;
};

const static set<string> ptr_ret_funcs = init_ptr_ret_funcs();

static inline
bool match_ptr_ret_funcs(const string name)
{
    // Note: xxx assumption on naming convention of concolic variable,
    // e.g. __kmalloc[e100.module_core+0x3fff]
    size_t ops = name.find('[');
    assert(ops != string::npos);
    if(ptr_ret_funcs.find(name.substr(0, ops)) != ptr_ret_funcs.end())
    {
        return true;
    } else {
        return false;
    }
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
