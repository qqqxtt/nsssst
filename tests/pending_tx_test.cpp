#include "dpdk/pending_tx.hpp"
#include <memory>
#include <stdexcept>
#include <source_location>
#include <string>
#include <vector>
void check(bool ok, std::source_location where = std::source_location::current()) {
    if (!ok)
        throw std::runtime_error("TX ownership test line " + std::to_string(where.line()));
}
struct Item {
    int id;
    static inline int alive{};
    Item(int n) : id(n) { ++alive; }
    ~Item() { --alive; }
};
int main() {
    using Owned = std::unique_ptr<Item>;
    {
        dpdk::PendingTx<Owned, 3> q;
        for (int i = 1; i <= 3; ++i)
            check(q.push(std::make_unique<Item>(i)));
        check(!q.push(std::make_unique<Item>(4)));
        check(Item::alive == 3); // Parameter temporaries have left the full expression.
        check(q.flush([](auto p) {
            check(p.size() == 3 && p[0]->id == 1);
            return 0;
        }) == 0);
        check(q.size() == 3 && Item::alive == 3);
        std::vector<Owned> driver;
        check(q.flush([&](auto p) {
            driver.emplace_back(p[0]);
            return 1;
        }) == 1);
        check(q.size() == 2 && Item::alive == 3);
        driver.clear();
        check(Item::alive == 2);
        check(q.push(std::make_unique<Item>(5)));
        q.flush([&](auto p) {
            check(p[0]->id == 2 && p[1]->id == 3 && p[2]->id == 5);
            for (auto *item : p)
                driver.emplace_back(item);
            return p.size();
        });
        check(q.size() == 0);
        bool called = false;
        q.flush([&](auto) {
            called = true;
            return 0;
        });
        check(!called);
        driver.clear();
        check(Item::alive == 0);
        check(q.push(std::make_unique<Item>(6))); // Destructor releases an unsent suffix.
    }
    check(Item::alive == 0);
}
