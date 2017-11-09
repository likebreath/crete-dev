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

// ------------------------------------------------
static inline
bool __CTCEM_alloc(const vector<uint8_t> &data)
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

    if(name.find("alloc") != string::npos)
    {
        ret = __CTCEM_alloc(data);
    }

    return ret;
}

// ------------------------------------------------

#endif /* LIB_TEST_CASE_TC_ELEM_CHECKER_HPP_ */
