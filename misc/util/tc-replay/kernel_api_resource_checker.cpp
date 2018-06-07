/*
 * kernel_api_resource_checker.cpp
 *
 *  Created on: Jun 4, 2018
 *      Author: chenbo
 */

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>

#include <boost/exception/diagnostic_information.hpp>

#include "kernel_api_resource_checker.hpp"

//#define CRETE_DEBUG_RC

#ifdef CRETE_DEBUG_RC
#define CRETE_DBG_RC(x) do { x } while(0)
#else
#define CRETE_DBG_RC(x) do { } while(0)
#endif

extern "C" {
int crete_raw_read_file(const char *file_name, char *buf, int size);
}

#define __CRETE_KAPI_RC_ADD_ALLOC(name, ft)                     \
        m_alloc_kapis.insert(make_pair(#name, ft));

#define __CRETE_KAPI_RC_ADD_FREE(free, alloc)                   \
        m_dealloc_kapis.insert(make_pair(#free, RM_FT_VOID));   \
        m_pairs.insert(make_pair(#alloc, #free));               \

namespace crete
{
CC_ResourceLeak::CC_ResourceLeak()
{
    __CRETE_KAPI_RC_ADD_ALLOC(device_create_file, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(led_classdev_register, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(mod_timer, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_enable_device, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_enable_device_mem, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_enable_msi_block, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_enable_msix, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_enable_pcie_error_reporting, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(__pci_register_driver, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_request_regions, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_request_selected_regions, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_request_selected_regions_exclusive, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_set_mwi, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(register_netdev, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(request_threaded_irq, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(scsi_add_host_with_dma, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_ac97_pcm_open, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_card_create, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_card_proc_new, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_device_new, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_dma_alloc_pages, RM_FT_NORMAL);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_pcm_lib_malloc_pages, RM_FT_NORMAL);

    __CRETE_KAPI_RC_ADD_ALLOC(__alloc_ei_netdev, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(alloc_etherdev_mqs, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__alloc_pages_nodemask, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__alloc_skb, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__alloc_workqueue_key, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(dma_alloc_attrs, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(dma_pool_alloc, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(dma_pool_create, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(ieee80211_alloc_hw, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(ioremap, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(ioremap_nocache, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(iso_sched_alloc, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(iso_stream_get, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__kmalloc, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC( __kmalloc_node, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(kmalloc_order_trace, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(kmem_cache_alloc, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(kmem_cache_alloc_trace, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(netdev_alloc_frag, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__netdev_alloc_skb, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_get_device, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_iomap, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_ioremap_bar, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(pci_zalloc_consistent, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(__request_region, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(scsi_host_alloc, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(snd_ctl_new1, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(usb_alloc_coherent, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(usb_alloc_urb, RM_FT_NULL_PTR);
    __CRETE_KAPI_RC_ADD_ALLOC(vzalloc, RM_FT_NULL_PTR);

    __CRETE_KAPI_RC_ADD_ALLOC(add_timer, RM_FT_VOID);
    __CRETE_KAPI_RC_ADD_ALLOC(pm_qos_add_request, RM_FT_VOID);
    __CRETE_KAPI_RC_ADD_ALLOC(netif_napi_add, RM_FT_VOID);

    __CRETE_KAPI_RC_ADD_FREE(consume_skb, __alloc_skb);
    __CRETE_KAPI_RC_ADD_FREE(consume_skb, __netdev_alloc_skb);
    __CRETE_KAPI_RC_ADD_FREE(del_timer, add_timer);
    __CRETE_KAPI_RC_ADD_FREE(del_timer, mod_timer);
    __CRETE_KAPI_RC_ADD_FREE(del_timer_sync, add_timer);
    __CRETE_KAPI_RC_ADD_FREE(del_timer_sync, mod_timer);
    __CRETE_KAPI_RC_ADD_FREE(destroy_workqueue, __alloc_workqueue_key);
    __CRETE_KAPI_RC_ADD_FREE(device_remove_file, device_create_file);
    __CRETE_KAPI_RC_ADD_FREE(dev_kfree_skb_any, __netdev_alloc_skb);
    __CRETE_KAPI_RC_ADD_FREE(dev_kfree_skb_irq, __netdev_alloc_skb);
    __CRETE_KAPI_RC_ADD_FREE(dma_pool_destroy, dma_pool_create);
    __CRETE_KAPI_RC_ADD_FREE(dma_pool_free, dma_pool_alloc);
    __CRETE_KAPI_RC_ADD_FREE(free_irq, request_threaded_irq);
    __CRETE_KAPI_RC_ADD_FREE(free_netdev, __alloc_ei_netdev);
    __CRETE_KAPI_RC_ADD_FREE(free_netdev, alloc_etherdev_mqs);
    __CRETE_KAPI_RC_ADD_FREE(__free_pages, __alloc_pages_nodemask);
    __CRETE_KAPI_RC_ADD_FREE(ieee80211_free_hw, ieee80211_alloc_hw);
    __CRETE_KAPI_RC_ADD_FREE(ieee80211_unregister_hw, ieee80211_register_hw);
    __CRETE_KAPI_RC_ADD_FREE(iounmap, ioremap_nocache);
    __CRETE_KAPI_RC_ADD_FREE(iounmap, pci_iomap);
    __CRETE_KAPI_RC_ADD_FREE(iounmap, pci_ioremap_bar);
    __CRETE_KAPI_RC_ADD_FREE(kfree, __kmalloc);
    __CRETE_KAPI_RC_ADD_FREE(kfree,  __kmalloc_node);
    __CRETE_KAPI_RC_ADD_FREE(kfree, kmalloc_order_trace);
    __CRETE_KAPI_RC_ADD_FREE(kfree, kmem_cache_alloc);
    __CRETE_KAPI_RC_ADD_FREE(kfree, kmem_cache_alloc_trace);
    __CRETE_KAPI_RC_ADD_FREE(kfree_skb, __netdev_alloc_skb);
    __CRETE_KAPI_RC_ADD_FREE(led_classdev_unregister, led_classdev_register);
    __CRETE_KAPI_RC_ADD_FREE(netif_napi_del, netif_napi_add);
    __CRETE_KAPI_RC_ADD_FREE(non, pci_get_device);
    __CRETE_KAPI_RC_ADD_FREE(pci_clear_mwi, pci_set_mwi);
    __CRETE_KAPI_RC_ADD_FREE(pci_disable_device, pci_enable_device);
    __CRETE_KAPI_RC_ADD_FREE(pci_disable_device, pci_enable_device_mem);
    __CRETE_KAPI_RC_ADD_FREE(pci_disable_msi, pci_enable_msi_block);
    __CRETE_KAPI_RC_ADD_FREE(pci_disable_msix, pci_enable_msix);
    __CRETE_KAPI_RC_ADD_FREE(pci_disable_pcie_error_reporting, pci_enable_pcie_error_reporting);
    __CRETE_KAPI_RC_ADD_FREE(pci_iounmap, pci_iomap);
    __CRETE_KAPI_RC_ADD_FREE(pci_release_regions, pci_request_regions);
    __CRETE_KAPI_RC_ADD_FREE(pci_release_selected_regions, pci_request_selected_regions);
    __CRETE_KAPI_RC_ADD_FREE(pci_release_selected_regions, pci_request_selected_regions_exclusive);
    __CRETE_KAPI_RC_ADD_FREE(pci_unregister_driver, __pci_register_driver);
    __CRETE_KAPI_RC_ADD_FREE(pm_qos_remove_request, pm_qos_add_request);
    __CRETE_KAPI_RC_ADD_FREE(put_page, __alloc_pages_nodemask);
//    __CRETE_KAPI_RC_ADD_FREE(put_page/skb_free_frag, netdev_alloc_frag);
    __CRETE_KAPI_RC_ADD_FREE(__release_region, __request_region);
    __CRETE_KAPI_RC_ADD_FREE(scsi_host_put, scsi_host_alloc);
    __CRETE_KAPI_RC_ADD_FREE(scsi_remove_host, scsi_add_host_with_dma);
    __CRETE_KAPI_RC_ADD_FREE(snd_ac97_pcm_close, snd_ac97_pcm_open);
    __CRETE_KAPI_RC_ADD_FREE(snd_card_free, snd_card_create);
    __CRETE_KAPI_RC_ADD_FREE(snd_card_free, snd_device_new);
    __CRETE_KAPI_RC_ADD_FREE(snd_ctl_release, snd_ctl_new1);
    __CRETE_KAPI_RC_ADD_FREE(snd_device_free, snd_card_proc_new);
    __CRETE_KAPI_RC_ADD_FREE(snd_dma_free_pages, snd_dma_alloc_pages);
    __CRETE_KAPI_RC_ADD_FREE(snd_pcm_lib_free_pages, snd_pcm_lib_malloc_pages);
    __CRETE_KAPI_RC_ADD_FREE(unregister_netdev, register_netdev);
    __CRETE_KAPI_RC_ADD_FREE(usb_deregister, usb_register_driver);
    __CRETE_KAPI_RC_ADD_FREE(usb_free_coherent, usb_alloc_coherent);
    __CRETE_KAPI_RC_ADD_FREE(usb_free_urb, usb_alloc_urb);
    __CRETE_KAPI_RC_ADD_FREE(vfree, vzalloc);
}

void CC_ResourceLeak::check_rm_array(const CRETE_RM_INFO *rm_array, int size,
        vector<string> &bug_info, vector<string> &warning_info)
{
    static char *info_buf[CRETE_RESOUCE_MONITOR_NAME_SIZE*8];

    // 1. divide the input rm_array into allocs and de_allocs;
    checkee_ty allocs;
    checkee_ty de_allocs;

    for(int i = 0; i < size; i++)
    {
        string target_func(rm_array[i].m_target_func);
        if(m_alloc_kapis.find(target_func) != m_alloc_kapis.end())
        {
            allocs.insert(make_pair(target_func, &rm_array[i]));
        } else if (m_dealloc_kapis.find(target_func) != m_dealloc_kapis.end()) {
            de_allocs.insert(make_pair(target_func, &rm_array[i]));
        } else {
            fprintf(stderr, "[CRETE ERROR RC] Unkown function: %s .\n", target_func.c_str());
            BOOST_THROW_EXCEPTION(std::runtime_error("[CRETE ERROR RC] Neither alloc or de-alloc func!\n"));
        }
    }

    // 2. Iterate allocs and check with de_allocs
    for(checkee_ty::const_iterator it = allocs.begin(), ite = allocs.end(); it != ite; ++it) {
        bool freed = false;
        const string &alloc_func = it->first;
        const CRETE_RM_INFO *alloc_info = it->second;

        // 2.1 check with failure type
        try {
            int ft = m_alloc_kapis.at(alloc_func);
            bool alloc_failed = false;

            if (ft == RM_FT_NULL_PTR) {
                alloc_failed = alloc_info->m_ret == 0;
            } else if(ft == RM_FT_NORMAL) {
                alloc_failed = (alloc_info->m_ret >> (sizeof(size_t)*8 - 1) & 1);
                if(!alloc_failed && (alloc_info->m_ret != 0)) {
                    fprintf(stderr, "[CRETE WARNING] Unexpected return: "
                            "alloc from '%s' with ret = %zu, alloc_value = %p!\n",
                            alloc_info->m_target_func, alloc_info->m_ret,
                            (void *)alloc_info->m_value);
                }
            }

            if(alloc_failed)
            {
                fprintf(stderr, "[CRETE WARNING] alloc failure from '%s' with ret = %zu, skipping alloc_value = %p!\n",
                        alloc_info->m_target_func, alloc_info->m_ret, (void *)alloc_info->m_value);

                continue;
            }
        } catch (...) {
            cerr << boost::current_exception_diagnostic_information() << endl;
            fprintf(stderr, "[CRETE ERROR RC] Unkown  alloc function: %s .\n", alloc_func.c_str());
            BOOST_THROW_EXCEPTION(std::runtime_error("[CRETE ERROR RC]!\n"));
        }

        // 2.2 check with de-alloc
        pair<alloc_dealloc_pair_ty::const_iterator, alloc_dealloc_pair_ty::const_iterator> found_pairs = m_pairs.equal_range(alloc_func);
        if(found_pairs.first == m_pairs.end())
        {
            fprintf(stderr, "[CRETE ERROR RC] No pair information found for function: %s .\n", alloc_func.c_str());
            BOOST_THROW_EXCEPTION(std::runtime_error("[CRETE ERROR RC]\n"));
        }

        for(alloc_dealloc_pair_ty::const_iterator r_it = found_pairs.first, r_ite = found_pairs.second;
                r_it != r_ite; ++r_it) {
            const string &free_func = r_it->second;

            pair<checkee_ty::const_iterator, checkee_ty::const_iterator> found_frees = de_allocs.equal_range(free_func);

            for(checkee_ty::const_iterator f_it = found_frees.first, f_ite = found_frees.second;
                    f_it != f_ite; ++f_it) {
                const CRETE_RM_INFO *free_info = f_it->second;
                if(free_info->m_value == alloc_info->m_value)
                {
                    CRETE_DBG_RC(
                    fprintf(stderr, "[CRETE DBG] Match found: alloc/de-alloc = %p, %s @ %p (%s), %s @ %p (%s)\n",
                            (void *)free_info->m_value,
                            alloc_info->m_target_func, (void *)alloc_info->m_call_site, alloc_info->m_call_site_module,
                            free_info->m_target_func, (void *)free_info->m_call_site, free_info->m_call_site_module);
                    );
                    freed = true;
                    de_allocs.erase(f_it);
                    break;
                }
            }

            if(freed) break;
        }

        if(!freed)
        {
            CRETE_DBG_RC(
            fprintf(stderr, "[CRETE RC][Potential Bug] Resource leak:  alloc = %p, %s @ %p (%s)\n",
                            (void *)alloc_info->m_value, alloc_info->m_target_func,
                            (void *)alloc_info->m_call_site, alloc_info->m_call_site_module);
            );
            snprintf((char *)info_buf, CRETE_RESOUCE_MONITOR_NAME_SIZE*8,
                    "[CRETE RC][Potential Bug] Resource leak:  alloc = %p, %s @ %p (%s)\n",
                    (void *)alloc_info->m_value, alloc_info->m_target_func,
                    (void *)alloc_info->m_call_site, alloc_info->m_call_site_module);
            bug_info.push_back(string((char *)info_buf));
        }
    }

    for(checkee_ty::const_iterator it = de_allocs.begin(), ite = de_allocs.end(); it != ite; ++it) {
        CRETE_DBG_RC(
        fprintf(stderr, "[CRETE RC][Potential Bug] Double Free:  free = %p, %s @ %p (%s)\n",
                        (void *)it->second->m_value, it->second->m_target_func,
                        (void *)it->second->m_call_site, it->second->m_call_site_module);
        );
        snprintf((char *)info_buf, CRETE_RESOUCE_MONITOR_NAME_SIZE*8,
                "[CRETE RC][Potential Bug] Double Free:  free = %p, %s @ %p (%s)\n",
                (void *)it->second->m_value, it->second->m_target_func,
                (void *)it->second->m_call_site, it->second->m_call_site_module);
        warning_info.push_back(string((char *)info_buf));
    }
}

CreteKernalApiChecker::CreteKernalApiChecker():m_rm_array_size(0),m_rm_array(NULL)
{
    CRETE_DBG_RC(
    fprintf(stderr, "[CRETE DEBUG RC] "
            "sizeof(struct CRETE_RM_INFO) = %u, CRETE_RESOUCE_MONITOR_NAME_SIZE = %d, "
            "CRETE_RESOURCE_MONITOR_ARRAY_SIZE = %u\n",
            sizeof(CRETE_RM_INFO), CRETE_RESOUCE_MONITOR_NAME_SIZE,
            CRETE_RESOURCE_MONITOR_ARRAY_SIZE);
    );

    try {
        m_buf_size = CRETE_RESOURCE_MONITOR_ARRAY_SIZE * (sizeof(CRETE_RM_INFO) + CRETE_RESOUCE_MONITOR_NAME_SIZE*2);
        m_buffer = new char[m_buf_size];
    } catch (...) {
        cerr << boost::current_exception_diagnostic_information() << endl;
        BOOST_THROW_EXCEPTION(std::runtime_error("[CRETE ERROR RC] new memory failed in CreteKernalApiChecker()!\n"));
    }
}

CreteKernalApiChecker::~CreteKernalApiChecker()
{
    delete[] m_buffer;
}

void CreteKernalApiChecker::perform_check()
{
    read_from_procfs();

    CRETE_DBG_RC(
    print_rm_array();
    );

    m_bug_info.clear();
    m_warning_info.clear();
    m_checker_rl.check_rm_array(m_rm_array, m_rm_array_size, m_bug_info, m_warning_info);
}

void CreteKernalApiChecker::read_from_procfs()
{
    memset(m_buffer, 0, m_buf_size);

    // 1. read all information to m_buffer
    int c = crete_raw_read_file((fs::path("/proc") / CRETE_RESOURCE_MONITOR_PROCFS).string().c_str(),
            (char *)m_buffer, m_buf_size);
    if(c < 0)
    {
        BOOST_THROW_EXCEPTION(std::runtime_error("[CRETE ERROR RC] read_from_procfs failed!\n"));
    }

    // 2. Parse m_buffer: mainly setting the valid pointer values (m_target_func, and m_call_site_module)
    CRETE_RM_INFO *rm_array = (CRETE_RM_INFO *)m_buffer;
    const char *tmp_ptr = m_buffer;

    uint32_t offset_target_func = CRETE_RESOURCE_MONITOR_ARRAY_SIZE*sizeof(CRETE_RM_INFO);
    uint32_t offset_call_site_module = CRETE_RESOURCE_MONITOR_ARRAY_SIZE * (sizeof(CRETE_RM_INFO) + CRETE_RESOUCE_MONITOR_NAME_SIZE);
    for(int i = 0; i < c; ++i)
    {
        rm_array[i].m_target_func = &tmp_ptr[offset_target_func];
        rm_array[i].m_call_site_module = &tmp_ptr[offset_call_site_module];

        offset_target_func += CRETE_RESOUCE_MONITOR_NAME_SIZE;
        offset_call_site_module += CRETE_RESOUCE_MONITOR_NAME_SIZE;
    }

    // 3. Set 'm_rm_array_size' and 'm_rm_array'
    m_rm_array_size = c;
    m_rm_array = (const CRETE_RM_INFO *)m_buffer;
}

void CreteKernalApiChecker::print_rm_array()
{
    fprintf(stderr, "----------------------print_rm_array()---------------\n");
    for(int i = 0; i < m_rm_array_size; ++i)
    {
        fprintf(stderr, "[%d] %s, value = %zu, ret= %zu, call_site = %zu (%s) \n",
                i, m_rm_array[i].m_target_func,
                m_rm_array[i].m_value,  m_rm_array[i].m_ret,
                m_rm_array[i].m_call_site, m_rm_array[i].m_call_site_module);
    }
    fprintf(stderr, "-----------------------------------------------------\n");
}

} // namespace crete
