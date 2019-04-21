#ifndef CRETE_TEST_POOL_H_
#define CRETE_TEST_POOL_H_

#include <set>
#include <string>
#include <vector>
#include <queue>
#include <stdint.h>
#include <random>

#include <boost/filesystem/path.hpp>
#include <boost/optional.hpp>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>

#include <crete/test_case.h>

namespace fs = boost::filesystem;

namespace crete
{
namespace cluster
{

enum TestSchedStrat {FIFO, BFS, COV_NEW_BFS};

class TestPriority
{
private:
    TestSchedStrat m_tc_sched_strat;

public:
    TestPriority(const TestSchedStrat& strat) {m_tc_sched_strat = strat;}
    bool operator() (const TestCase& lhs, const TestCase& rhs) const;
};

class TestPool
{
public:
    using TestQueue = std::priority_queue<TestCase, vector<TestCase>, TestPriority>;
    // Needs to be a map b/c the tc issued first is not necessary going to finish symbolic replay first
    using BaseTestCache_ty = boost::unordered_map<TestCaseIssueIndex, TestCase>;
    using UniqueTestIdentifier = TestCaseElements;

private:
    fs::path root_;

    uint64_t tc_count_;

    TestQueue next_;
    boost::unordered_set<UniqueTestIdentifier> issued_tc_hash_pool_;
    BaseTestCache_ty base_tc_cache_;

    // <br_tb_pc, count>
    boost::unordered_map<uint64_t, uint64_t> m_covered_br_tb_pc;

    // debug
    uint64_t m_duplicated_tc_count;
    uint64_t m_meaningless_tc_count;

public:
    TestPool(const fs::path& root);

    auto next() -> boost::optional<TestCase>;

    auto insert_initial_tc_from_config(const TestCase& tc) -> bool;
    auto insert_initial_tcs(const std::vector<TestCase>& tcs) -> void;

    auto insert(const std::vector<TestCase>& tcs) -> void;

    auto count_all() const -> size_t;
    auto count_next() const -> size_t;

    auto write_log(std::ostream& os) -> void;

private:
    auto insert_internal(const TestCase& tc) -> bool;

    auto set_tc_covNew_dist(const TestCase& tc) -> void;

    auto insert_base_tc(const TestCase& tc) -> BaseTestCache_ty::const_iterator;
    auto get_base_tc(const TestCase& tc) -> BaseTestCache_ty::const_iterator;
    auto get_complete_tc(const TestCase& patch_tc) -> boost::optional<TestCase> const;
    auto write_test_case(const TestCase& tc, const fs::path out_path) -> void;
};

} // namespace cluster
} // namespace crete

#endif // CRETE_TEST_POOL_H_
