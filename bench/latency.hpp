#pragma once
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <time.h>
#include <vector>

namespace bench {
inline std::uint64_t now_ns() {
    timespec ts{};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        throw std::runtime_error("clock_gettime failed");
    return std::uint64_t(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}
inline void summarize(char const *name, std::vector<std::uint64_t> values) {
    if (values.empty()) {
        std::printf("%s: n=0\n", name);
        return;
    }
    long double sum{};
    for (auto n : values)
        sum += n;
    std::sort(values.begin(), values.end());
    auto q = [&](double p) { return values[std::size_t(std::ceil(p * values.size())) - 1]; };
    std::printf("%s: n=%zu mean=%.2Lf p50=%llu p99=%llu p99.9=%llu max=%llu ns\n", name,
                values.size(), sum / values.size(), (unsigned long long)q(.5),
                (unsigned long long)q(.99), (unsigned long long)q(.999),
                (unsigned long long)values.back());
}
} // namespace bench
