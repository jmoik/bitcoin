// Copyright (c) 2026
// Distributed under the MIT software license.
/*
 * Measure the families in dev/varops/primitive-calibration/varops-primitives.md.
 * Production helpers supply internal measurements; F uses the real interpreter.
 * Setup is untimed, destructive probes receive fresh states, and raw epochs are
 * saved beside the summary CSV. No current varops rate sets repetition counts.
 *
 * The existing percentile/covering estimates are provisional diagnostics, not
 * the final fitting methodology or a validated schedule. Whole-script checks
 * belong in bench_varops. Existing result files are not rewritten.
 *
 * Build: cmake --build build --target bench_varops_primitives -j
 * Run:   build/bin/bench_varops_primitives --reference-csv old_bench_varops.csv
 *        (or --pre-v2-seconds with a same-machine script-evaluation reference).
 *
 * Standalone estimator tests:
 *   c++ -std=c++20 -O2 -DVAROPS_PRIMITIVES_ESTIMATOR_TEST \
 *       bench_varops_primitives.cpp -o primitive_estimator_test
 */

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace primitive_bench {

constexpr double BLOCK_VAROPS{40'000'000'000.0};
// Candidate schedules retain sub-varop primitive rates here.  Consensus code
// must instead sum these scaled integer terms and round the complete opcode
// charge up once.
constexpr uint64_t VAROPS_RATE_SCALE{1'000'000};
using Clock = std::chrono::steady_clock;

void Require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

uint64_t CheckedAdd(uint64_t a, uint64_t b)
{
    Require(a <= std::numeric_limits<uint64_t>::max() - b, "integer addition overflow");
    return a + b;
}

uint64_t CheckedMultiply(uint64_t a, uint64_t b)
{
    Require(a == 0 || b <= std::numeric_limits<uint64_t>::max() / a, "integer multiplication overflow");
    return a * b;
}

uint64_t FixedPointRate(double varops_per_unit)
{
    Require(varops_per_unit >= 0 && std::isfinite(varops_per_unit), "invalid fixed-point rate");
    const double scaled = std::ceil(varops_per_unit * VAROPS_RATE_SCALE);
    Require(scaled <= static_cast<double>(std::numeric_limits<uint64_t>::max()), "fixed-point rate overflow");
    return static_cast<uint64_t>(scaled);
}

/** Sum q * units / VAROPS_RATE_SCALE and round the complete charge up once. */
uint64_t FixedPointCharge(std::span<const std::pair<uint64_t, uint64_t>> terms)
{
    uint64_t whole{0};
    uint64_t fractional{0};
    for (const auto& [q, units] : terms) {
        whole = CheckedAdd(whole, CheckedMultiply(q / VAROPS_RATE_SCALE, units));
        whole = CheckedAdd(whole, CheckedMultiply(units / VAROPS_RATE_SCALE, q % VAROPS_RATE_SCALE));
        fractional = CheckedAdd(fractional, CheckedMultiply(q % VAROPS_RATE_SCALE, units % VAROPS_RATE_SCALE));
        whole = CheckedAdd(whole, fractional / VAROPS_RATE_SCALE);
        fractional %= VAROPS_RATE_SCALE;
    }
    return CheckedAdd(whole, fractional != 0);
}

// An observation barrier, not a call/clock around each primitive.
// The memory clobber prevents repeated fills/copies from being deleted.
template <typename T> inline void Observe(const T& value)
{
#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "g"(&value) : "memory");
#else
    static const void* volatile sink;
    sink = &value;
    std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
}

double Quantile(std::vector<double> values, double p)
{
    Require(!values.empty() && p >= 0 && p <= 1, "invalid quantile");
    for (double v : values) Require(std::isfinite(v) && v >= 0, "invalid timing");
    std::sort(values.begin(), values.end());
    const double index = p * static_cast<double>(values.size() - 1);
    const size_t lo = static_cast<size_t>(index);
    const size_t hi = std::min(lo + 1, values.size() - 1);
    return values[lo] + (values[hi] - values[lo]) * (index - lo);
}

std::vector<std::string> SplitCSV(const std::string& line)
{
    std::vector<std::string> result;
    std::string field;
    bool quoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '"') {
            if (quoted && i + 1 < line.size() && line[i + 1] == '"') {
                field += '"';
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (c == ',' && !quoted) {
            result.push_back(std::move(field));
            field.clear();
        } else if (c != '\r') {
            field += c;
        }
    }
    Require(!quoted, "unterminated CSV quote");
    result.push_back(std::move(field));
    return result;
}

std::string CSV(const std::string& s)
{
    std::string out{"\""};
    for (char c : s) {
        if (c == '"') out += '"';
        out += c;
    }
    return out + '"';
}

double Number(const std::string& s)
{
    size_t end = 0;
    double x = std::stod(s, &end);
    Require(end == s.size() && std::isfinite(x), "invalid number: " + s);
    return x;
}

// Reads the existing bench_varops v3 CSV; never uses v2 or extrapolated rows.
double ReadReference(std::istream& in)
{
    std::vector<std::string> header;
    double worst = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line.front() == '#') continue;
        auto fields = SplitCSV(line);
        if (header.empty()) { header = std::move(fields); continue; }
        Require(fields.size() == header.size(), "malformed reference CSV row");
        const auto get = [&](const std::string& key) -> const std::string& {
            const auto it = std::find(header.begin(), header.end(), key);
            Require(it != header.end(), "reference CSV missing column: " + key);
            return fields[static_cast<size_t>(it - header.begin())];
        };
        if (get("Record_Type") != "summary" || get("Domain") != "pre-gsr-tapscript-v1") continue;
        const auto& error = get("Actual_Termination");
        if (error != "OK" && error != "SCRIPT_ERR_OK" && error != "No error") continue;
        const double t = Number(get("Wall_Seconds"));
        if (t > worst) worst = t;
    }
    Require(worst > 0, "no successful pre-v2 Script-evaluation summary in reference CSV");
    return worst;
}

struct Options {
    size_t epochs{7};
    double epoch_ms{10.0};
    double copy_epoch_ms{100.0};
    double percentile{0.5};
    double margin{1.0};
    size_t max_bytes{4'000'000};
    size_t fixture_bytes{64U * 1024U * 1024U};
    double reference_sec{0};
    std::string reference_csv;
    std::string output{"dev/varops/primitive_costs.csv"};
    bool portable_math{false};
    bool offset_spans{false};
    bool prep_audit{false};
    bool prep_only{false};
    bool arith_only{false};
    bool div_only{false};
    bool mul_only{false};
    bool div_batch_diagnostic{false};
    std::string div_batch_case;
    bool hash_only{false};
    bool fixed_only{false};
    bool items_only{false};
    bool copy_only{false};
    bool storage_only{false};
    bool produce_only{false};
    bool growth_only{false};
    size_t growth_seed{1};
    bool calibration_candidate{false};
    bool max_diagnostic{false};
    bool self_test{false};
};

struct Sample {
    std::string label;
    size_t repetitions{0};
    double median{0};
    double tail{0};
};

struct Point { double count; double units; Sample sample; };
struct Line { double fixed{0}; double slope{0}; };

// Minimum sum of relative predicted times, subject to a+b*x >= every observed
// percentile and a,b >= 0. In two dimensions the optimum is at a vertex.
// This is a tiny covering fit, NOT ordinary least squares followed by hoping.
Line Cover(const std::vector<Point>& points, bool tail)
{
    Require(!points.empty(), "empty covering fit");
    std::vector<std::pair<double, double>> xy;
    for (const auto& p : points) {
        Require(p.count > 0 && p.units >= 0, "invalid fit feature");
        const double y = (tail ? p.sample.tail : p.sample.median) / p.count;
        Require(y > 0 && std::isfinite(y), "nonpositive fit timing");
        xy.emplace_back(p.units / p.count, y);
    }
    double best = std::numeric_limits<double>::infinity();
    Line answer;
    const auto consider = [&](double a, double b) {
        if (!std::isfinite(a) || !std::isfinite(b) || a < -1e-9 || b < -1e-12) return;
        a = std::max(0.0, a); b = std::max(0.0, b);
        double objective = 0;
        for (const auto& [x,y] : xy) {
            const double predicted = a + b*x;
            if (predicted + std::max(1.0, y)*1e-10 < y) return;
            objective += predicted / y;
        }
        if (objective < best) { best = objective; answer = {a,b}; }
    };
    double fixed_axis = 0, slope_axis = 0;
    bool slope_possible = true;
    for (const auto& [x,y] : xy) {
        fixed_axis = std::max(fixed_axis, y);
        if (x == 0) slope_possible = false;
        else slope_axis = std::max(slope_axis, y/x);
    }
    consider(fixed_axis, 0);
    if (slope_possible) consider(0, slope_axis);
    for (size_t i=0; i<xy.size(); ++i) {
        for (size_t j=i+1; j<xy.size(); ++j) {
            const auto [x1,y1] = xy[i]; const auto [x2,y2] = xy[j];
            if (x1 == x2) continue;
            const double b = (y1-y2)/(x1-x2);
            consider(y1-b*x1, b);
        }
    }
    Require(std::isfinite(best), "covering fit failed");
    // Preserve all constraints against floating-point rounding.
    double repair = 1;
    for (const auto& [x,y] : xy) repair = std::max(repair, y/(answer.fixed+answer.slope*x));
    answer.fixed *= repair; answer.slope *= repair;
    return answer;
}

struct Rate {
    std::string name, unit, method;
    double median{0}, tail{0};
    std::string status{"estimated"};
    std::optional<double> fit_multiplicative_deviation{};
};

double FitMultiplicativeDeviation(const std::vector<Point>& points, const Line& fit)
{
    double absolute_log_ratio_sum{0};
    for (const auto& point : points) {
        const double observed{point.sample.tail / point.count};
        const double predicted{fit.fixed + fit.slope * point.units / point.count};
        Require(observed > 0 && predicted > 0, "multiplicative fit quality requires positive values");
        absolute_log_ratio_sum += std::abs(std::log(predicted / observed));
    }
    return std::exp(absolute_log_ratio_sum / points.size());
}

class Runner {
    const Clock::time_point m_started{Clock::now()};
    Clock::time_point m_last_progress{m_started};
    size_t m_completed_fixtures{0};

public:
    Options options;
    std::vector<Rate> rates;
    std::ofstream raw;

    explicit Runner(Options o) : options(std::move(o))
    {
        raw.open(options.output + ".samples.csv");
        Require(raw.good(), "cannot open raw sample output");
        raw << "probe,repetitions,epoch,ns_per_execution\n" << std::setprecision(17);
    }

    size_t PoolLimit(size_t bytes_per_state) const
    {
        Require(bytes_per_state <= options.fixture_bytes, "one fixture exceeds --fixture-mib");
        return std::max<size_t>(1, std::min<size_t>(1'000'000, options.fixture_bytes / std::max<size_t>(bytes_per_state, 1)));
    }

    template <typename Make, typename Run>
    Sample Measure(const std::string& name, size_t max_repetitions, Make make, Run run)
    {
        Require(max_repetitions > 0, "empty repetition limit");
        const auto now{Clock::now()};
        if (m_completed_fixtures == 0 || now - m_last_progress >= std::chrono::seconds{5}) {
            const auto seconds{std::chrono::duration_cast<std::chrono::seconds>(now - m_started).count()};
            std::cerr << "  Progress: " << m_completed_fixtures << " fixtures complete; "
                      << seconds << " s elapsed; measuring " << name << '\n';
            m_last_progress = now;
        }
        const auto epoch = [&](size_t n) {
            auto state = make(n);  // Untimed, independent state for every epoch.
            Observe(state);
            const auto start = Clock::now();
            run(state, n);
            const auto end = Clock::now();
            Observe(state);        // Keep produced state alive until after timing.
            const double elapsed = std::chrono::duration<double, std::nano>(end-start).count();
            return elapsed;
        };
        size_t n = 1;
        for (;;) {
            const double elapsed = epoch(n); // Pilot/warmup; not included in tail.
            if (elapsed >= options.epoch_ms*1e6 || n >= max_repetitions) break;
            const double factor = std::clamp(options.epoch_ms*1e6/std::max(1.0, elapsed), 2.0, 8.0);
            const size_t next = static_cast<size_t>(std::ceil(n*factor));
            n = std::min(max_repetitions, std::max(n+1, next));
        }
        std::vector<double> observations;
        observations.reserve(options.epochs);
        for (size_t e=0; e<options.epochs; ++e) {
            const double elapsed = epoch(n);
            const double ns = elapsed/n;
            observations.push_back(ns);
            raw << CSV(name) << ',' << n << ',' << e << ',' << ns << '\n';
        }
        Require(raw.good(), "raw sample write failed");
        ++m_completed_fixtures;
        return {name, n, Quantile(observations,0.5), Quantile(observations,options.percentile)};
    }

    template <typename Make, typename Run>
    Sample Repeated(const std::string& name, Make make, Run one)
    {
        return Measure(name, 1'000'000, [&](size_t) { return make(); },
            [&](auto& state, size_t n) {
                for (size_t i=0; i<n; ++i) { one(state, i); Observe(state); }
            });
    }

    void Add(Rate rate)
    {
        std::cerr << "  " << rate.name << ": " << rate.status;
        if (rate.tail > 0) std::cerr << " (" << std::setprecision(6) << rate.tail << " ns/" << rate.unit << ')';
        std::cerr << '\n';
        rates.push_back(std::move(rate));
    }

    Rate LinearRate(const std::string& name, const std::string& unit,
                    const std::vector<Point>& p, const std::string& method)
    {
        Rate rate{name,unit,method};
        const Point* tail_driver{nullptr};
        for (const auto& point : p) {
            Require(point.units > 0, "zero units in proportional estimate");
            rate.median = std::max(rate.median, point.sample.median / point.units);
            const double tail=point.sample.tail / point.units;
            if (tail > rate.tail) {
                rate.tail=tail;
                tail_driver=&point;
            }
        }
        Require(rate.tail > 0, "empty primitive estimate: " + name);
        rate.fit_multiplicative_deviation = FitMultiplicativeDeviation(p, {0, rate.tail});
        Add(rate);
        std::cerr << "    driver: " << tail_driver->sample.label << " ("
                  << tail_driver->sample.tail << " ns / " << tail_driver->units
                  << " " << unit << ")\n";
        return rate;
    }

    Line Pair(const std::string& fixed_name, const std::string& slope_name,
              const std::string& slope_unit, const std::vector<Point>& p,
              const std::string& method)
    {
        const Line med=Cover(p,false), tail=Cover(p,true);
        const auto status=[&](double v) {
            return v == 0 ? "boundary_fit_not_free" : "estimated";
        };
        Add({fixed_name,"call",method,med.fixed,tail.fixed,status(tail.fixed)});
        Add({slope_name,slope_unit,method,med.slope,tail.slope,status(tail.slope)});
        const double fit_multiplicative_deviation{FitMultiplicativeDeviation(p, tail)};
        rates[rates.size() - 2].fit_multiplicative_deviation = fit_multiplicative_deviation;
        rates.back().fit_multiplicative_deviation = fit_multiplicative_deviation;
        std::vector<const Point*> constraints;
        constraints.reserve(p.size());
        for (const auto& point : p) constraints.push_back(&point);
        std::sort(constraints.begin(), constraints.end(), [&](const Point* a, const Point* b) {
            const double a_slack=tail.fixed*a->count+tail.slope*a->units-a->sample.tail;
            const double b_slack=tail.fixed*b->count+tail.slope*b->units-b->sample.tail;
            return a_slack < b_slack;
        });
        std::cerr << "    binding constraints for " << fixed_name << ":\n";
        for (size_t i=0; i<std::min<size_t>(2,constraints.size()); ++i) {
            const Point& point=*constraints[i];
            const double predicted=tail.fixed*point.count+tail.slope*point.units;
            std::cerr << "      " << point.sample.label << ": observed " << point.sample.tail
                      << " ns, predicted " << predicted << " ns, slack "
                      << predicted-point.sample.tail << " ns\n";
        }
        return tail;
    }

    double Get(const std::string& name) const
    {
        for (const auto& r:rates) if (r.name==name) return r.tail;
        throw std::runtime_error("missing prerequisite: " + name);
    }

    void Save()
    {
        const double reference_ns=options.reference_sec*1e9;
        Require(reference_ns > 0, "missing positive reference time");
        std::ofstream out(options.output);
        Require(out.good(), "cannot open output: " + options.output);
        out << std::setprecision(17)
            << "# Reference_Script_Evaluation_Seconds: " << options.reference_sec << '\n'
            << "# Primitive_Model: " << (options.calibration_candidate ? "producer-normalize-v1" : "legacy-primitives") << '\n'
            << "# Reference_Source: " << (options.reference_csv.empty() ? "--pre-v2-seconds" : options.reference_csv) << '\n'
            << "# Empirical_Percentile: " << options.percentile << '\n'
            << "# Safety_Multiplier: " << options.margin << '\n'
            << "# Max_Probe_Bytes: " << options.max_bytes << '\n'
            << "# Copy_Target_Batch_MS: " << options.copy_epoch_ms << '\n'
            << "# Epochs: " << options.epochs << '\n'
            << "# Forced_Portable_Val64: " << options.portable_math << '\n'
            << "# Forced_Offset_Spans: " << options.offset_spans << '\n'
            << "# Legacy covering estimates are diagnostic, not the final fit or a consensus schedule.\n"
            << "# Quantiles are over batch-mean timings, not per-invocation tail latencies.\n"
            << "# boundary_fit_not_free / covered_by_other_rates are NOT evidence of free work.\n"
            << "# varops_q is ceil(varops_float * fixed_point_scale). Candidate opcode charges sum q*units and round up once.\n"
            << "# varops_individual_ceil is diagnostic only; it MUST NOT be summed across primitive terms.\n"
            << "primitive,unit,median_curve_ns,tail_curve_ns,safe_ns,block_share,varops_float,varops_q,fixed_point_scale,varops_individual_ceil,fit_multiplicative_deviation,status,method\n";
        std::cout << std::left << std::setw(20) << "Primitive" << std::setw(14) << "Unit"
                  << std::right << std::setw(15) << "Tail ns/unit" << std::setw(15) << "Safe ns/unit"
                  << std::setw(16) << "Block share" << std::setw(14) << "Standalone ceil" << "  Status\n";
        for (const auto& r:rates) {
            const bool available=r.tail > 0;
            const double safe=r.tail*options.margin, share=safe/reference_ns, cost=share*BLOCK_VAROPS;
            Require(!available || (std::isfinite(cost) && cost < static_cast<double>(UINT64_MAX)), "cost overflow");
            std::cout << std::left << std::setw(20) << r.name << std::setw(14) << r.unit << std::right;
            out << CSV(r.name) << ',' << CSV(r.unit) << ',';
            if (available) {
                const uint64_t q=FixedPointRate(cost);
                const uint64_t integer=static_cast<uint64_t>(std::ceil(cost));
                out << r.median << ',' << r.tail << ',' << safe << ',' << share << ',' << cost << ',' << q << ','
                    << VAROPS_RATE_SCALE << ',' << integer;
                std::cout << std::fixed << std::setprecision(4) << std::setw(15) << r.tail
                          << std::setw(15) << safe << std::scientific << std::setprecision(5)
                          << std::setw(16) << share << std::setw(14) << integer;
            } else {
                out << ",,,,,,,";
                std::cout << std::setw(15) << "-" << std::setw(15) << "-" << std::setw(16) << "-" << std::setw(14) << "-";
            }
            out << ',';
            if (r.fit_multiplicative_deviation) out << *r.fit_multiplicative_deviation;
            out << ',' << CSV(r.status) << ',' << CSV(r.method) << '\n';
            std::cout << "  " << r.status << '\n';
        }
        out.flush(); raw.flush();
        Require(out.good() && raw.good(), "output write failed");
    }
};

void EstimatorSelfTests()
{
    Require(Quantile({1,2,3,4,5},0.5)==3, "median test");
    Require(std::abs(Quantile({1,2,3,4,5},0.95)-4.8)<1e-12, "percentile test");
    Require(SplitCSV("a,\"b,c\",\"d\"\"e\",").size()==4, "CSV field count");
    Require(SplitCSV("a,\"b,c\",\"d\"\"e\",")[2]=="d\"e", "CSV escaping");
    std::vector<Point> p;
    for (double x : {0.0,1.0,8.0,64.0,1024.0}) p.push_back({1,x,{"",1,12+0.25*x,12+0.25*x}});
    const auto fit=Cover(p,true);
    Require(std::abs(fit.fixed-12)<1e-8 && std::abs(fit.slope-0.25)<1e-8, "affine fit");
    Require(std::abs(FitMultiplicativeDeviation(p, fit)-1)<1e-12, "exact multiplicative fit quality");
    Require(FitMultiplicativeDeviation(p, {268, 0}) > 4, "poor multiplicative fit quality");
    const uint64_t fractional=FixedPointRate(0.000107676);
    Require(fractional == 108, "fractional fixed-point rate");
    const std::array<std::pair<uint64_t, uint64_t>, 2> terms{{{fractional,4'000'000}, {FixedPointRate(0.107676),4'000'000}}};
    Require(FixedPointCharge(terms)==431'136, "complete fixed-point charge rounding");
    // A shared hash example: one pass and two-pass probes share coefficients.
    p.push_back({2,2048,{"",1,24+0.25*2048,24+0.25*2048}});
    auto mixed=Cover(p,true);
    for (auto& point:p) Require(point.count*mixed.fixed+point.units*mixed.slope+1e-8>=point.sample.tail,"covering constraint");
    std::mt19937_64 rng(1234);
    for (size_t trial=0;trial<100;++trial) {
        std::vector<Point> cases;
        for (size_t j=0;j<20;++j) {
            double n=double(rng()%10000), t=10+n*0.2+double(rng()%100);
            cases.push_back({1,n,{"",1,t,t}});
        }
        auto cover=Cover(cases,true);
        Require(cover.fixed>=0 && cover.slope>=0,"nonnegative fit");
        for(auto& point:cases) Require(cover.fixed+cover.slope*point.units+1e-7>=point.sample.tail,"random covering constraint");
    }
    std::istringstream csv("Record_Type,Domain,Actual_Termination,Wall_Seconds\n"
        "summary,pre-gsr-tapscript-v1,OK,2.5\n"
        "summary,gsr-tapscript-v2,OK,99\n"
        "summary,raw-schnorr,OK,100\n"
        "summary,pre-gsr-tapscript-v1,No error,3\n"
        "sample,pre-gsr-tapscript-v1,OK,1000\n");
    Require(ReadReference(csv)==3,"reference selection");
}

} // namespace primitive_bench

#ifdef VAROPS_PRIMITIVES_ESTIMATOR_TEST
int main()
{
    try { primitive_bench::EstimatorSelfTests(); std::cout << "Estimator self-tests passed.\n"; return 0; }
    catch(const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
#else

#include <consensus/amount.h>
#include <crypto/ripemd160.h>
#include <crypto/sha1.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/op_tx.h>
#include <script/script.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#include <uint256.h>
#include <util/translation.h>
#include <util/string.h>

#ifdef _WIN32
#include <compat/compat.h>
#include <windows.h>
#else
#include <sys/mman.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace primitive_bench {

constexpr uint64_t DIAGNOSTIC_BUDGET{UINT64_MAX/4};
constexpr script_verify_flags FLAGS{SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};

size_t W(size_t n) { return (n+7)/8*8; }
using Bytes=std::vector<unsigned char>;
using Words=std::vector<uint64_t>;

// Several hashing APIs require a nonnull pointer even for a zero-length input.
const unsigned char* Data(const Bytes& b)
{
    static const unsigned char empty{0};
    return b.empty() ? &empty : b.data();
}
std::span<const unsigned char> Message(const Bytes& b) { return {Data(b),b.size()}; }

// Only access to EXISTING code. No copied arithmetic implementation.
struct ProbeVal64 : Val64 {
    using Val64::Val64;
    using Val64::AddSpans;
    using Val64::SubtractSpans;
    using Val64::MultiplySpan;
    using Val64::SpanIsAllZero;
    using Val64::CompareSpans;
    using Val64::ShiftDown;
    using Val64::ShiftLeftLessThanWord;
    static void Configure(bool portable, bool offset)
    {
        m_force_portable_math=portable;
        m_force_offset_span=offset;
    }
};

std::vector<size_t> Sizes(const Options& options, size_t minimum=0, size_t limit=4'000'000)
{
    const size_t cap=std::min(options.max_bytes,limit);
    std::vector<size_t> result;
    for (size_t n : std::initializer_list<size_t>{0,1,7,8,9,15,16,17,32,55,56,63,64,65,127,128,129,256,519,520,521,
                     1024,4096,16384,65536,262144,1048576,4000000}) {
        if (n>=minimum && n<=cap) result.push_back(n);
    }
    for (size_t n = minimum; n <= std::min<size_t>(cap, 64); ++n) result.push_back(n);
    for (size_t n = 72; n <= std::min<size_t>(cap, 520); n += 8) {
        if (n >= minimum) result.push_back(n);
    }
    for (size_t n = 640; n < cap; n += std::max<size_t>(1, n / 4)) {
        if (n >= minimum) result.push_back(n);
    }
    for (size_t n : {2'000'000U, 3'000'000U, 3'500'000U}) {
        if (n >= minimum && n <= cap) result.push_back(n);
    }
    // Portable allocation-size boundaries plus previously observed allocator
    // transitions. These are fixture sizes, never consensus charge features.
    std::vector<size_t> boundaries{65536, 86658, 135402, 169252, 211565, 330570};
    for (size_t n = 8; n <= cap; n *= 2) boundaries.push_back(n);
    for (size_t boundary : boundaries) {
        for (int delta : {-1, 0, 1}) {
            const size_t n{static_cast<size_t>(static_cast<int64_t>(boundary) + delta)};
            if (n >= minimum && n <= cap) result.push_back(n);
        }
    }
    if (cap>=minimum) result.push_back(cap);
    std::sort(result.begin(),result.end());
    result.erase(std::unique(result.begin(),result.end()),result.end());
    return result;
}

Bytes Pattern(size_t size, uint64_t seed=1)
{
    Bytes out(size);
    for(auto& byte:out) { seed^=seed<<13; seed^=seed>>7; seed^=seed<<17; byte=static_cast<unsigned char>(seed); }
    if (!out.empty()) out.back()|=0x80; // A normalized nonzero high byte.
    return out;
}

struct Crypto {
    std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> ctx{
        secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),secp256k1_context_destroy};
    secp256k1_keypair keypair{};
    XOnlyPubKey pubkey;
    std::array<unsigned char,32> tweak{};
    Crypto()
    {
        Require(ctx!=nullptr,"secp context creation");
        std::array<unsigned char,32> secret{}; secret.back()=1;
        Require(secp256k1_keypair_create(ctx.get(),&keypair,secret.data())==1,"keypair creation");
        secp256k1_xonly_pubkey key{};
        Require(secp256k1_keypair_xonly_pub(ctx.get(),&key,nullptr,&keypair)==1,"xonly key conversion");
        std::array<unsigned char,32> bytes{};
        Require(secp256k1_xonly_pubkey_serialize(ctx.get(),bytes.data(),&key)==1,"xonly serialize");
        pubkey=XOnlyPubKey{std::span<const unsigned char>{bytes}};
        tweak.back()=1;
    }
    std::array<unsigned char,64> Sign(const Bytes& message) const
    {
        std::array<unsigned char,64> sig{};
        Require(secp256k1_schnorrsig_sign_custom(ctx.get(),sig.data(),Data(message),message.size(),&keypair,nullptr)==1,"Schnorr sign");
        Require(pubkey.VerifySchnorr(Message(message),sig),"Schnorr fixture verification");
        return sig;
    }
};

struct TransactionFixture {
    CMutableTransaction tx;
    PrecomputedTransactionData precomputed;
    Bytes control=Bytes(33,0);
    ScriptExecutionData context;

    explicit TransactionFixture(size_t witnesses=0)
    {
        tx.version=2; tx.nLockTime=500000;
        tx.vin.resize(1); tx.vin[0].nSequence=144;
        tx.vin[0].prevout.n=0;
        tx.vin[0].scriptWitness.stack.resize(witnesses); // All empty: item work, no payload copying.
        CScript p2tr; p2tr<<OP_1<<Bytes(32,1);
        tx.vout.emplace_back(1000,p2tr);
        std::vector<CTxOut> spent; spent.emplace_back(2000,p2tr);
        precomputed.Init(tx,std::move(spent),true);
        context.m_annex_init=true; context.m_annex_present=false;
        context.m_tapleaf_hash_init=true; context.m_taptree_root_init=true;
        context.m_tapscript_init=true; context.m_control_block_init=true;
        context.m_codeseparator_pos_init=true; context.m_codeseparator_pos=0xffffffff;
        control[0]=0xc2; context.m_control_block=control;
    }
    MutableTransactionSignatureChecker Checker() const
    {
        return MutableTransactionSignatureChecker{&tx,0,2000,precomputed,MissingDataBehavior::FAIL};
    }
};

// A prepared frame owns a separate mutable stack and finite metering state.
struct Frame {
    ValtypeStack stack;
    ScriptExecutionData context;
    varops::Budget budget{DIAGNOSTIC_BUDGET};
    explicit Frame(const std::vector<Bytes>& initial, const ScriptExecutionData& data={})
        : stack(std::span<const Bytes>{initial}),context(data) {}
};

Sample ScriptSample(Runner& runner,const std::string& label,const CScript& script,
                    const std::vector<Bytes>& initial,const BaseSignatureChecker& checker)
{
    size_t bytes=sizeof(Frame)+256;
    for(const auto& v:initial) bytes+=2*v.size()+64;
    return runner.Measure(label,runner.PoolLimit(bytes),[&](size_t n) {
        std::vector<std::unique_ptr<Frame>> frames;
        frames.reserve(n);
        for(size_t i=0;i<n;++i) frames.push_back(std::make_unique<Frame>(initial));
        return frames;
    },[&](auto& frames,size_t n) {
        for(size_t i=0;i<n;++i) {
            ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR}; bool immediate=false;
            bool ok=EvalTapscriptV2(frames[i]->stack,script,FLAGS,checker,frames[i]->context,frames[i]->budget,&error,&immediate);
            if (ok && !immediate) ok=CheckTapscriptV2ScriptResult(frames[i]->stack,frames[i]->budget,&error);
            if (!ok || immediate || error!=SCRIPT_ERR_OK) throw std::runtime_error(strprintf("interpreter fixture failed: %s (error %d)", label, static_cast<int>(error)));
            Observe(ok);
        }
    });
}

// F: common evaluator overhead of instructions that pay only F, including
// parsing/prescan. Entry/finalization is amortized by long scripts, not priced
// again per opcode. Each F/<group>/<n> script executes n charged instructions
// before its final OP_1; F/skipped/<n> skips n uncharged NOPs as a diagnostic.
void EstimateFixed(Runner& r)
{
    BaseSignatureChecker checker;
    std::vector<Point> observations;
    const auto repeat = [](CScript& script, std::initializer_list<opcodetype> unit, size_t count) {
        for (size_t i = 0; i < count; ++i) {
            for (const opcodetype opcode : unit) script << opcode;
        }
    };
    const std::array<opcodetype, 8> upgradable{OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10};
    for (size_t n : {256U, 1024U, 4096U, 16384U}) {
        std::vector<std::pair<std::string, CScript>> scripts;
        CScript nop, nops, separator, toggle, pairs, nested;
        repeat(nop, {OP_NOP}, n);
        for (size_t i = 0; i < n; ++i) nops << upgradable[i % upgradable.size()];
        repeat(separator, {OP_CODESEPARATOR}, n);
        // Condition push, IF and ENDIF are three of the n charged instructions.
        toggle << OP_1 << OP_IF;
        repeat(toggle, {OP_ELSE}, n - 3);
        toggle << OP_ENDIF;
        // Inactive IF/ENDIF pay F without popping; the trailing active NOP completes n.
        pairs << OP_0 << OP_IF;
        repeat(pairs, {OP_IF, OP_ENDIF}, (n - 4) / 2);
        pairs << OP_ENDIF << OP_NOP;
        nested << OP_0 << OP_IF;
        repeat(nested, {OP_IF}, (n - 4) / 2);
        repeat(nested, {OP_ENDIF}, (n - 4) / 2 + 1);
        nested << OP_NOP;
        for (auto& [group, script] : std::initializer_list<std::pair<std::string, CScript*>>{
                 {"nop", &nop}, {"upgradable-nop", &nops}, {"codeseparator", &separator},
                 {"else", &toggle}, {"inactive-if-pairs", &pairs}, {"inactive-if-nested", &nested}}) {
            *script << OP_1;
            auto sample = ScriptSample(r, "F/" + group + "/" + std::to_string(n), *script, {}, checker);
            observations.push_back({1, double(n + 1), std::move(sample)});
        }
        CScript skipped;
        skipped << OP_0 << OP_IF;
        repeat(skipped, {OP_NOP}, n);
        skipped << OP_ENDIF << OP_1;
        ScriptSample(r, "F/skipped/" + std::to_string(n), skipped, {}, checker);
    }
    r.LinearRate("F", "execution", observations,
                 "metered F-only scripts (NOP, upgradable NOPs, CODESEPARATOR, ELSE, inactive IF/ENDIF); "
                 "parsing/prescan included, entry/finalization amortized");
}

// COPY times copied-value creation; RELEASE times buffer destruction separately.
// The churn path recreates the large-source/result lifetimes of OP_SUBSTR.
void MeasureCopyChurn(Runner& r, size_t result_size,
                      std::vector<Point>& copies, std::vector<Point>& releases)
{
    constexpr size_t source_size{3'998'900};
    struct State {
        ValtypeStack stack;
    };
    const auto make = [] {
        auto state = std::make_unique<State>();
        state->stack.reserve(6);
        state->stack.push_back(Pattern(source_size));
        state->stack.push_back(Bytes(8, 1));
        state->stack.push_back(Bytes(8, 2));
        return state;
    };
    struct Timing { double create_ns{0}; double source_release_ns{0}; double result_release_ns{0}; double cycle_ns{0}; };
    const auto epoch = [&](size_t repetitions) {
        auto state = make();
        Timing timing;
        const auto cycle_start{Clock::now()};
        for (size_t i{0}; i < repetitions; ++i) {
            state->stack.push_back(state->stack.at(0));
            Clock::time_point source_release_start;
            {
                Bytes source{state->stack.PopBackValue()};
                const auto start{Clock::now()};
                Bytes result;
                constexpr size_t WORD_BYTES{sizeof(uint64_t)};
                result.reserve(result_size + (WORD_BYTES - result_size % WORD_BYTES) % WORD_BYTES);
                result.insert(result.end(), source.begin() + 1,
                              source.begin() + 1 + result_size);
                state->stack.push_back(std::move(result));
                timing.create_ns += std::chrono::duration<double, std::nano>(Clock::now() - start).count();
                Observe(source);
                source_release_start = Clock::now();
            }
            timing.source_release_ns += std::chrono::duration<double, std::nano>(Clock::now() - source_release_start).count();
            const auto start{Clock::now()};
            state->stack.pop_back();
            timing.result_release_ns += std::chrono::duration<double, std::nano>(Clock::now() - start).count();
            Observe(state->stack);
        }
        timing.cycle_ns = std::chrono::duration<double, std::nano>(Clock::now() - cycle_start).count();
        Require(state->stack.size() == 3 && state->stack.GetTotalSize() == source_size + 16,
                "COPY churn fixture did not restore its initial stack");
        return timing;
    };
    size_t repetitions{1};
    for (;;) {
        const Timing timing{epoch(repetitions)};
        if (timing.cycle_ns >= r.options.epoch_ms * 1e6 || repetitions >= 1'000'000) break;
        const double factor{std::clamp(r.options.epoch_ms * 1e6 / std::max(1.0, timing.cycle_ns), 2.0, 8.0)};
        repetitions = std::min<size_t>(1'000'000,
                                       std::max(repetitions + 1, static_cast<size_t>(std::ceil(repetitions * factor))));
    }
    std::vector<double> copy_observations, source_observations, result_observations;
    const std::string copy_label{"COPY/churn/" + std::to_string(result_size)};
    const std::string source_label{"RELEASE/source/" + std::to_string(source_size) + "/after/" + std::to_string(result_size)};
    const std::string result_label{"RELEASE/churn/" + std::to_string(result_size)};
    for (size_t i{0}; i < r.options.epochs; ++i) {
        const Timing timing{epoch(repetitions)};
        const double create_ns{timing.create_ns / repetitions};
        const double source_ns{timing.source_release_ns / repetitions};
        const double result_ns{timing.result_release_ns / repetitions};
        copy_observations.push_back(create_ns);
        source_observations.push_back(source_ns);
        result_observations.push_back(result_ns);
        r.raw << CSV("COPY_CONTROL/cycle/" + std::to_string(result_size)) << ',' << repetitions << ',' << i << ',' << timing.cycle_ns / repetitions << '\n';
        r.raw << CSV(copy_label) << ',' << repetitions << ',' << i << ',' << create_ns << '\n';
        r.raw << CSV(source_label) << ',' << repetitions << ',' << i << ',' << source_ns << '\n';
        r.raw << CSV(result_label) << ',' << repetitions << ',' << i << ',' << result_ns << '\n';
    }
    const auto sample = [&](const std::string& label, const std::vector<double>& observations) {
        return Sample{label, repetitions, Quantile(observations, 0.5), Quantile(observations, r.options.percentile)};
    };
    copies.push_back({1, double(result_size), sample(copy_label, copy_observations)});
    releases.push_back({1, double(source_size), sample(source_label, source_observations)});
    releases.push_back({1, double(result_size), sample(result_label, result_observations)});
}

void MeasureCopyIsolated(Runner& r, size_t size,
                         std::vector<Point>& copies, std::vector<Point>& releases)
{
    const auto epoch = [&](size_t repetitions) {
        ValtypeStack stack;
        stack.reserve(2);
        stack.push_back(Pattern(size));
        double copy_ns{0}, release_ns{0};
        const auto cycle_start{Clock::now()};
        for (size_t i{0}; i < repetitions; ++i) {
            const auto copy_start{Clock::now()};
            stack.push_back(stack.at(0));
            copy_ns += std::chrono::duration<double, std::nano>(Clock::now() - copy_start).count();
            const auto release_start{Clock::now()};
            stack.pop_back();
            release_ns += std::chrono::duration<double, std::nano>(Clock::now() - release_start).count();
            Observe(stack);
        }
        Require(stack.size() == 1 && stack.GetTotalSize() == size, "COPY isolated fixture did not restore its stack");
        return std::array<double, 3>{copy_ns, release_ns,
            std::chrono::duration<double, std::nano>(Clock::now() - cycle_start).count()};
    };
    size_t repetitions{1};
    for (;;) {
        const auto timing{epoch(repetitions)};
        if (timing[2] >= r.options.epoch_ms * 1e6 || repetitions >= 1'000'000) break;
        const double factor{std::clamp(r.options.epoch_ms * 1e6 / std::max(1.0, timing[2]), 2.0, 8.0)};
        repetitions = std::min<size_t>(1'000'000,
                                       std::max(repetitions + 1, static_cast<size_t>(std::ceil(repetitions * factor))));
    }
    std::vector<double> copy_observations, release_observations;
    const std::string copy_label{"COPY/isolated/" + std::to_string(size)};
    const std::string release_label{"RELEASE/isolated/" + std::to_string(size)};
    for (size_t i{0}; i < r.options.epochs; ++i) {
        const auto timing{epoch(repetitions)};
        const double copy_ns{timing[0] / repetitions};
        const double release_ns{timing[1] / repetitions};
        copy_observations.push_back(copy_ns);
        release_observations.push_back(release_ns);
        r.raw << CSV(copy_label) << ',' << repetitions << ',' << i << ',' << copy_ns << '\n';
        r.raw << CSV(release_label) << ',' << repetitions << ',' << i << ',' << release_ns << '\n';
        r.raw << CSV("COPY_CONTROL/cycle/isolated/" + std::to_string(size)) << ',' << repetitions << ',' << i << ',' << timing[2] / repetitions << '\n';
    }
    const auto sample = [&](const std::string& label, const std::vector<double>& observations) {
        return Sample{label, repetitions, Quantile(observations, 0.5), Quantile(observations, r.options.percentile)};
    };
    copies.push_back({1, double(size), sample(copy_label, copy_observations)});
    releases.push_back({1, double(size), sample(release_label, release_observations)});
}

Sample MeasureReleasePreallocated(Runner& r, size_t logical_size, size_t capacity_size)
{
    const auto epoch = [&](size_t repetitions) {
        double release_ns{0};
        const auto cycle_start{Clock::now()};
        for (size_t i{0}; i < repetitions; ++i) {
            Bytes value{Pattern(capacity_size)};
            value.resize(logical_size);
            Require(value.capacity() >= capacity_size, "preallocated release lost capacity");
            ValtypeStack stack;
            stack.reserve(1);
            stack.push_back(std::move(value));
            const auto start{Clock::now()};
            stack.pop_back();
            release_ns += std::chrono::duration<double, std::nano>(Clock::now() - start).count();
            Observe(stack);
        }
        return std::array<double, 2>{release_ns,
            std::chrono::duration<double, std::nano>(Clock::now() - cycle_start).count()};
    };
    size_t repetitions{1};
    for (;;) {
        const auto timing{epoch(repetitions)};
        if (timing[1] >= r.options.epoch_ms * 1e6 || repetitions >= 128) break;
        repetitions = std::min<size_t>(128, repetitions * 2);
    }
    std::vector<double> observations;
    const std::string label{"RELEASE/preallocated/" + std::to_string(logical_size) + "/" + std::to_string(capacity_size)};
    for (size_t i{0}; i < r.options.epochs; ++i) {
        const auto timing{epoch(repetitions)};
        const double release_ns{timing[0] / repetitions};
        observations.push_back(release_ns);
        r.raw << CSV(label) << ',' << repetitions << ',' << i << ',' << release_ns << '\n';
        r.raw << CSV("COPY_CONTROL/cycle/preallocated/" + std::to_string(logical_size)) << ',' << repetitions << ',' << i << ',' << timing[1] / repetitions << '\n';
    }
    return {label, repetitions, Quantile(observations, 0.5), Quantile(observations, r.options.percentile)};
}

void EstimateCopy(Runner& r)
{
    const double previous_epoch_ms{std::exchange(r.options.epoch_ms, r.options.copy_epoch_ms)};
    std::vector<Point> copies, releases;
    for(size_t n:Sizes(r.options)) {
        MeasureCopyIsolated(r, n, copies, releases);
    }
    std::vector<size_t> churn_sizes{Sizes(r.options)};
    for (size_t n : {65'536U, 131'072U, 262'144U, 524'288U, 1'048'576U,
                     1'500'000U, 1'999'450U, 2'500'000U, 3'000'000U, 3'998'000U}) {
        if (n <= r.options.max_bytes) churn_sizes.push_back(n);
    }
    std::sort(churn_sizes.begin(), churn_sizes.end());
    churn_sizes.erase(std::unique(churn_sizes.begin(), churn_sizes.end()), churn_sizes.end());
    for (size_t n : churn_sizes) {
        if (n < 3'998'900) MeasureCopyChurn(r, n, copies, releases);
    }
    for (size_t size : {0U, 1U, 8U, 520U, 4096U, 65536U, 1048576U, 3000000U}) {
        releases.push_back({1, 3'998'900.0, MeasureReleasePreallocated(r, size, 3'998'900)});
    }
    for (size_t capacity : {65536U, 262144U, 1048576U, 2000000U, 3000000U, 3950000U}) {
        releases.push_back({1, double(capacity), MeasureReleasePreallocated(r, 0, capacity)});
    }
    r.options.epoch_ms = previous_epoch_ms;
    r.Pair("COPY.fixed","COPY.byte","byte",copies,"copied-value creation, without release");
    r.Pair("RELEASE.fixed","RELEASE.byte","byte",releases,"value release, including large-capacity diagnostics");
}

// PREP/OUTPUT: directly call the production ownership/conversion paths. OUTPUT
// measures MoveToValtype followed by rvalue stack insertion as one operation.
// Tight PREP samples are growth checks, not a separately exported primitive.
void EstimateRepresentation(Runner& r, bool include_output = true)
{
    std::vector<Point> prep,output;
    struct CompositionCheck { size_t bytes; double tight; double spare; };
    std::vector<CompositionCheck> composition;
    auto sizes=Sizes(r.options);
    if (r.options.prep_audit) {
        for (size_t n : {511U,512U,513U,518U,519U,520U,521U,522U,3'999'999U}) {
            if (n <= r.options.max_bytes) sizes.push_back(n);
        }
        std::sort(sizes.begin(), sizes.end());
        sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    }
    for(size_t n:sizes) {
        const Bytes source=Pattern(n);
        Sample prep_tight,prep_spare;
        for(bool spare:{false,true}) {
            const auto name=std::to_string(n)+(spare?"/spare":"/tight");
            const size_t cap=r.PoolLimit(2*W(n)+256);
            struct State { std::vector<Bytes> bytes; std::vector<Val64> numbers; };
            auto make=[&](size_t count) {
                State s; s.bytes.resize(count); s.numbers.resize(count);
                for(size_t i=0;i<count;++i) {
                    Bytes b=source;
                    if(spare) b.reserve(W(n)+16);
                    s.bytes[i]=std::move(b);
                }
                return s;
            };
            auto prep_sample=r.Measure("PREP/"+name,cap,make,[](auto& s,size_t c){
                for(size_t i=0;i<c;++i) s.numbers[i].MoveFromValtype(std::move(s.bytes[i]));
            });
            if (spare) prep_spare=prep_sample;
            else prep_tight=prep_sample;
        }
        prep.push_back({1,double(W(n)),std::move(prep_spare)});
        composition.push_back({n,prep_tight.tail,prep.back().sample.tail});

        if (!include_output) continue;

        struct OutputState {
            std::vector<Val64> numbers;
            std::vector<std::unique_ptr<ValtypeStack>> stacks;
        };
        const size_t cap=r.PoolLimit(2*W(n)+512);
        output.push_back({1,double(W(n)),r.Measure("OUTPUT/"+std::to_string(n),cap,[&](size_t count) {
            OutputState state;
            state.numbers.resize(count);
            state.stacks.reserve(count);
            for(size_t i=0;i<count;++i) {
                Bytes bytes=source;
                state.numbers[i].MoveFromValtype(std::move(bytes));
                state.stacks.push_back(std::make_unique<ValtypeStack>());
                state.stacks.back()->reserve(1);
            }
            return state;
        },[](auto& state,size_t count) {
            for(size_t i=0;i<count;++i) {
                state.stacks[i]->push_back(state.numbers[i].MoveToValtype());
                Observe(state.stacks[i]->back());
                state.stacks[i]->pop_back();
            }
        })});
    }
    if (r.options.prep_audit) {
        std::sort(composition.begin(), composition.end(), [](const auto& a, const auto& b) {
            return a.tight / std::max(a.spare, 1e-9) > b.tight / std::max(b.spare, 1e-9);
        });
        std::cerr << "  Largest tight-versus-spare PREP composition gaps:\n";
        for (size_t i=0; i<std::min<size_t>(8,composition.size()); ++i) {
            const auto& check=composition[i];
            std::cerr << "    " << check.bytes << " bytes: tight " << check.tight << " ns, spare "
                      << check.spare << " ns\n";
        }
    }
    r.Pair("PREP.fixed","PREP.byte","rounded_byte",prep,"fresh Val64::MoveFromValtype with pre-reserved rounded capacity");
    if (!include_output) return;
    // Small scalar construction is part of the same result-production family.
    for (uint64_t value : std::array<uint64_t, 7>{0, 1, 255, 256, 65536, 0x80000000ULL, UINT64_MAX}) {
        Val64 fixture(value);
        const size_t bytes = fixture.MoveToValtype().size();
        auto sample = r.Repeated("OUTPUT/scalar/" + std::to_string(value), [] {
            auto stack = std::make_unique<ValtypeStack>();
            stack->reserve(1);
            return stack;
        }, [&](auto& stack, size_t) {
            Val64 number(value);
            stack->push_back(number.MoveToValtype());
            Observe(stack->back());
            stack->pop_back();
        });
        output.push_back({1, double(W(bytes)), std::move(sample)});
    }
    r.Pair("OUTPUT.fixed","OUTPUT.byte","rounded_byte",output,
           "numeric result production/insertion/release, including scalar construction");
}

// Producer lifetime model: complete creation/use/destruction is timed together.
// NORMALIZE isolates numeric materialization; no insertion or destruction occurs
// inside its timer. Sizes/counts describe semantic values, never capacity.
void EstimateProducer(Runner& r)
{
    std::ofstream manifest(r.options.output + ".produce.csv");
    Require(manifest.good(), "cannot open producer manifest");
    manifest << "probe,kind,items,bytes,normalize_bytes\n";
    const auto cycle = [&](const std::string& label, const std::string& kind,
                           size_t items, size_t bytes, size_t numeric_bytes, auto work) {
        work();
        const double old_ms{r.options.epoch_ms};
        r.options.epoch_ms = r.options.copy_epoch_ms;
        r.Repeated(label, [] { return 0; }, [&](auto&, size_t) { work(); });
        r.options.epoch_ms = old_ms;
        manifest << CSV(label) << ',' << kind << ',' << items << ',' << bytes << ',' << numeric_bytes << '\n';
    };
    auto sizes = Sizes(r.options);
    for (size_t boundary : {65536U, 86658U, 135402U, 169252U, 211565U, 330570U}) {
        for (int delta : {-16, -8, -1, 0, 1, 8, 16}) {
            const size_t n{static_cast<size_t>(static_cast<int64_t>(boundary) + delta)};
            if (n <= r.options.max_bytes) sizes.push_back(n);
        }
    }
    std::sort(sizes.begin(), sizes.end());
    sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    if (r.options.growth_only) {
        sizes = {65520, 65528, 65535, 65536, 65537, 65538, 65543, 65544, 65545, 65552,
                 86650, 86657, 86658, 86659, 86666, 135386, 135394, 135401, 135402,
                 135403, 135410, 135418, 169244, 169251, 169252, 169260};
        std::erase_if(sizes, [&](size_t n) { return n > r.options.max_bytes; });
        std::mt19937_64 rng{r.options.growth_seed};
        std::shuffle(sizes.begin(), sizes.end(), rng);
    }
    for (const size_t n : sizes) {
        const Bytes source{Pattern(n)};
        ValtypeStack stack;
        stack.reserve(8);
        for (const std::string mode : {"stack", "vector", "zero", "shrink-empty", "shrink-one", "grow"}) {
            if (r.options.growth_only && mode != "grow") continue;
            // Growth funds both the original value and its enlarged replacement.
            cycle("PRODUCE/" + mode + "/" + std::to_string(n), "produce",
                  mode == "grow" ? 2 : 1, mode == "grow" ? n + n / 2 : n, 0, [&] {
                if (mode == "stack") {
                    stack.push_back(source);
                    Observe(stack.back());
                    stack.pop_back();
                } else {
                    Bytes value;
                    if (mode == "zero") {
                        value.resize(n);
                    } else if (mode == "grow") {
                        value.assign(source.begin(), source.begin() + n / 2);
                        value.insert(value.end(), source.begin() + n / 2, source.end());
                    } else {
                        value = source;
                    }
                    Observe(value);
                    if (mode == "shrink-empty") value.resize(0);
                    if (mode == "shrink-one") value.resize(std::min<size_t>(n, 1));
                    stack.push_back(std::move(value));
                    Observe(stack.back());
                    stack.pop_back();
                }
            });
        }
        if (r.options.growth_only) continue;
        // Worst-case allocator: every value lands on freshly mapped pages, so each
        // lifetime pays the page faults, kernel zeroing and unmapping. Warm reuse is
        // the stack mode above; this bounds allocators that return large blocks to the OS.
        if (n >= 16384) {
            cycle("PRODUCE/fresh-pages/" + std::to_string(n), "produce", 1, n, 0, [&] {
#ifdef _WIN32
                void* pages{VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)};
                Require(pages != nullptr, "fresh-page allocation failed");
                std::memcpy(pages, source.data(), n);
                Observe(pages);
                VirtualFree(pages, 0, MEM_RELEASE);
#else
                void* pages{mmap(nullptr, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)};
                Require(pages != MAP_FAILED, "fresh-page allocation failed");
                std::memcpy(pages, source.data(), n);
                Observe(pages);
                munmap(pages, n);
#endif
            });
        }
        // Source and result are both funded: never attribute freeing a 4 MB
        // source to the size of a one-byte result.
        const size_t source_size{std::min<size_t>(3'998'900, r.options.max_bytes)};
        const Bytes large_source{Pattern(source_size)};
        const size_t result_size{std::min(n, source_size)};
        cycle("PRODUCE/churn/" + std::to_string(n), "produce", 2, source_size + result_size, 0, [&] {
            Bytes temporary{large_source};
            Bytes result(temporary.begin(), temporary.begin() + result_size);
            Observe(temporary);
            stack.push_back(std::move(result));
            stack.pop_back();
        });
        for (const bool offset : {false, true}) {
            struct State { std::vector<Val64> numbers; std::vector<Bytes> results; };
            const std::string label{"NORMALIZE/" + std::string(offset ? "offset-span/" : "aligned/") + std::to_string(n)};
            r.Measure(label, r.PoolLimit(2 * W(n + 8) + 256), [&](size_t count) {
                State state;
                state.numbers.resize(count);
                state.results.resize(count);
                for (size_t i = 0; i < count; ++i) {
                    Bytes bytes{Pattern(n)};
                    ProbeVal64::Configure(r.options.portable_math, offset);
                    state.numbers[i].MoveFromValtype(std::move(bytes));
                    ProbeVal64::Configure(r.options.portable_math, r.options.offset_spans);
                }
                return state;
            }, [](auto& state, size_t count) {
                for (size_t i = 0; i < count; ++i) {
                    state.results[i] = state.numbers[i].MoveToValtype();
                    Observe(state.results[i]);
                }
            });
            manifest << CSV(label) << ",normalize,1,0," << n << '\n';
        }
        // These are held-out composition checks, not more fit constraints.
        for (const bool spare : {false, true}) {
            cycle("PRODUCER_CHECK/numeric/" + std::string(spare ? "spare/" : "tight/") + std::to_string(n),
                  "numeric", 1, n, n, [&] {
                Bytes bytes;
                if (spare) bytes.reserve(W(n) + 16);
                bytes.insert(bytes.end(), source.begin(), source.end());
                Val64 number{std::move(bytes)};
                stack.push_back(number.MoveToValtype());
                Observe(stack.back());
                stack.pop_back();
            });
        }
    }
    if (r.options.growth_only) return;
    for (uint64_t value : {uint64_t{0}, uint64_t{1}, uint64_t{255}, uint64_t{256}, uint64_t{65536}, UINT64_MAX}) {
        Val64 fixture(value);
        const size_t n{fixture.MoveToValtype().size()};
        const std::string label{"NORMALIZE/scalar/" + std::to_string(value)};
        struct State { std::vector<Val64> numbers; std::vector<Bytes> results; };
        r.Measure(label, r.PoolLimit(512), [&](size_t count) {
            State state;
            state.results.resize(count);
            state.numbers.reserve(count);
            for (size_t i = 0; i < count; ++i) state.numbers.emplace_back(value);
            return state;
        }, [](auto& state, size_t count) {
            for (size_t i = 0; i < count; ++i) {
                state.results[i] = state.numbers[i].MoveToValtype();
                Observe(state.results[i]);
            }
        });
        manifest << CSV(label) << ",normalize,1,0," << n << '\n';
    }
    for (size_t n : {0U, 1U, 8U, 521U, 4096U, 65536U, 1048576U}) {
        if (n > r.options.max_bytes) continue;
        const Bytes source{Pattern(n)};
        for (size_t count : {1U, 8U, 64U, 1024U, 32768U}) {
            if (count * (n + 32) > r.options.fixture_bytes / 2) continue;
            cycle("PRODUCER_CHECK/retained/" + std::to_string(n) + "/" + std::to_string(count),
                  "retained", count, n * count, 0, [&] {
                ValtypeStack stack;
                for (size_t i = 0; i < count; ++i) {
                    Bytes value{source};
                    value.resize(std::min<size_t>(n, 1));
                    stack.push_back(std::move(value));
                }
                Observe(stack);
            });
        }
    }
}

// Complete finite lifetimes: unlike Measure's prepared-state probes, every
// mutable buffer (including its final destruction) is inside the timed loop.
// Immutable source bytes are fixtures, not free mutable allocation history.
// These are composite diagnostics, not additional independent opcode charges.
void EstimateStorage(Runner& r)
{
    std::ofstream manifest(r.options.output + ".storage.csv");
    Require(manifest.good(), "cannot open storage fixture manifest");
    manifest << "probe,bytes,items,current_varops,kind\n";
    const auto cycle = [&](const std::string& name, size_t bytes, size_t items, auto work) {
        work(); // Validate the path before collecting measurements.
        r.Repeated(name, [] { return 0; }, [&](auto&, size_t) { work(); });
        manifest << CSV(name) << ',' << bytes << ',' << items << ",0,lifetime\n";
    };
    for (size_t n : Sizes(r.options)) {
        const Bytes source{Pattern(n)};
        for (const std::string mode : {"stack", "vector", "shrink-empty", "shrink-one", "shrink-half"}) {
            cycle("STORAGE/copy/" + mode + "/" + std::to_string(n), n, 1, [&] {
                if (mode == "stack") {
                    ValtypeStack stack;
                    stack.push_back(source);
                    Observe(stack.back());
                } else {
                    Bytes value{source};
                    Observe(value);
                    if (mode == "shrink-empty") value.resize(0);
                    if (mode == "shrink-one") value.resize(std::min<size_t>(n, 1));
                    if (mode == "shrink-half") value.resize(n / 2);
                    Observe(value);
                }
            });
        }
        for (bool spare : {false, true}) {
            cycle("STORAGE/numeric/" + std::string(spare ? "spare/" : "tight/") + std::to_string(n), n, 1, [&] {
                Bytes bytes;
                if (spare) bytes.reserve(W(n) + 16);
                bytes.insert(bytes.end(), source.begin(), source.end());
                Val64 number{std::move(bytes)};
                ValtypeStack stack;
                stack.push_back(number.MoveToValtype());
                Observe(stack.back());
            });
        }
    }

    // Retain small logical values backed by larger buffers; creation, shrinking,
    // accumulated storage and final reclamation all occur within this sample.
    for (size_t n : {0U, 1U, 8U, 521U, 4096U, 65536U, 1048576U}) {
        if (n > r.options.max_bytes) continue;
        const Bytes source{Pattern(n)};
        for (size_t count : {1U, 8U, 64U, 1024U, 32768U}) {
            if (count * (n + 32) > r.options.fixture_bytes / 2) continue;
            for (bool shrink : {false, true}) {
                cycle("STORAGE/retained/" + std::string(shrink ? "shrunk/" : "whole/") +
                          std::to_string(n) + "/" + std::to_string(count), n, count, [&] {
                    ValtypeStack stack;
                    for (size_t i = 0; i < count; ++i) {
                        Bytes value{source};
                        if (shrink) value.resize(std::min<size_t>(n, 1));
                        stack.push_back(std::move(value));
                    }
                    Observe(stack);
                });
            }
        }
    }

    BaseSignatureChecker checker;
    const auto script_sample = [&](const std::string& name, size_t size, const CScript& script,
                                   const std::vector<Bytes>& initial) {
        uint64_t charged{0};
        const auto execute = [&] {
            Frame frame{initial}; // Witness-stack copy and eventual cleanup are timed.
            ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
            bool immediate{false};
            const bool ok{EvalTapscriptV2(frame.stack, script, FLAGS, checker, frame.context,
                                         frame.budget, &error, &immediate)};
            if (!ok || immediate || !CheckTapscriptV2ScriptResult(frame.stack, frame.budget, &error)) {
                throw std::runtime_error(strprintf("storage fixture %s failed: %d", name, int(error)));
            }
            charged = DIAGNOSTIC_BUDGET - *frame.budget.Remaining();
            Observe(frame);
        };
        execute();
        r.Repeated(name, [] { return 0; }, [&](auto&, size_t) { execute(); });
        manifest << CSV(name) << ',' << size << ',' << initial.size() << ',' << charged << ",script\n";
    };
    for (size_t n : {0U, 1U, 7U, 8U, 9U, 63U, 64U, 65U, 119U, 120U, 121U,
                     127U, 128U, 129U, 519U, 520U, 521U, 4096U, 65536U, 1048576U, 1999000U, 3998900U}) {
        if (n > r.options.max_bytes) continue;
        const Bytes source{Pattern(n)};
        const Bytes index{Val64{uint64_t(n / 2)}.MoveToValtype()};
        const auto run = [&](const std::string& mode, const CScript& script, const std::vector<Bytes>& initial) {
            script_sample("STORAGE/script/" + mode + "/" + std::to_string(n), n, script, initial);
        };
        run("witness-drop", CScript{} << OP_DROP << OP_1, {source});
        run("literal", CScript{} << source << OP_DROP << OP_1, {});
        run("dup-altstack", CScript{} << OP_DUP << OP_TOALTSTACK << OP_FROMALTSTACK << OP_2DROP << OP_1, {source});
        if (n <= 2'000'000) run("cat", CScript{} << OP_CAT << OP_DROP << OP_1, {source, source});
        run("cat-grow-one", CScript{} << OP_CAT << OP_DROP << OP_1, {source, Bytes{1}});
        run("substr", CScript{} << OP_SUBSTR << OP_DROP << OP_1, {source, index, Bytes{1}});
        run("left", CScript{} << OP_LEFT << OP_DROP << OP_1, {source, index});
        run("right", CScript{} << OP_RIGHT << OP_DROP << OP_1, {source, index});
        run("carry", CScript{} << OP_1ADD << OP_DROP << OP_1, {Bytes(n, 0xff)});
        run("cancel", CScript{} << OP_SUB << OP_DROP << OP_1, {source, source});
        run("min", CScript{} << OP_MIN << OP_DROP << OP_1, {source, source});
        run("max", CScript{} << OP_MAX << OP_DROP << OP_1, {source, source});
        run("numequalverify", CScript{} << OP_NUMEQUALVERIFY << OP_1, {source, source});
        run("normalize", CScript{} << OP_0NOTEQUAL << OP_DROP << OP_1, {Bytes(n, 0)});
        run("shift-grow", CScript{} << OP_LSHIFT << OP_DROP << OP_1, {source, Bytes{65}});
        run("shift-shrink", CScript{} << OP_RSHIFT << OP_DROP << OP_1, {source, Bytes{65}});
        run("mul", CScript{} << OP_MUL << OP_DROP << OP_1, {source, Pattern(16)});
        run("div", CScript{} << OP_DIV << OP_DROP << OP_1, {source, Bytes(16, 1)});
        run("mod", CScript{} << OP_MOD << OP_DROP << OP_1, {source, Bytes(16, 1)});
        if (n <= 4096) {
            for (size_t divisor_size : {8U, 64U, 128U}) {
                for (bool normalized : {false, true}) {
                    Bytes divisor{Pattern(divisor_size)};
                    if (!normalized) divisor.back() = 1;
                    const auto suffix{std::to_string(divisor_size) + (normalized ? "-normalized" : "-grow")};
                    run("div-" + suffix, CScript{} << OP_DIV << OP_DROP << OP_1, {source, divisor});
                    run("mod-" + suffix, CScript{} << OP_MOD << OP_DROP << OP_1, {source, divisor});
                }
            }
        }
        run("sha256", CScript{} << OP_SHA256 << OP_DROP << OP_1, {source});
        // Both source duplication and result destruction are now timed. Unlike
        // the old scoped churn timer, this does not attribute source work to n.
        run("substr-churn", CScript{} << OP_3DUP << OP_SUBSTR << OP_DROP << OP_2DROP << OP_DROP << OP_1,
            {source, index, index});
        CScript repeated;
        for (size_t i = 0; i < 64; ++i) repeated << OP_3DUP << OP_SUBSTR << OP_DROP;
        repeated << OP_2DROP << OP_DROP << OP_1;
        run("substr-repeat", repeated, {source, index, index});
        if (n != 0) run("final", CScript{} << OP_NOP, {source});
    }

    // Macro declarations and call frames are different allocations from value
    // buffers; retain them as complete-script controls.
    for (size_t definitions : {1U, 8U, 128U}) {
        const CScript body{CScript{} << OP_0 << OP_IF << OP_1 << OP_ENDIF};
        CScript script;
        for (size_t i = 0; i < definitions; ++i) {
            script << OP_MACRO;
            script.push_back(body.size()); // Canonical one-byte CompactSize.
            script.insert(script.end(), body.begin(), body.end());
        }
        for (size_t i = 0; i < definitions; ++i) {
            script << OP_CALLMACRO;
            script.push_back(i);
        }
        script << OP_1;
        script_sample("STORAGE/script/macros/" + std::to_string(definitions), definitions, script, {});
    }

    // OP_TX owns result vectors and planning arrays; context preparation remains
    // outside this evaluator-only boundary, exactly as in EstimateItems.
    for (bool collate : {false, true}) {
        for (size_t n : {0U, 1U, 8U, 128U, 4096U}) {
            TransactionFixture fixture(n);
            for (size_t bytes : {0U, 32U, 520U}) {
                for (auto& item : fixture.tx.vin[0].scriptWitness.stack) item = Pattern(bytes);
                auto tx_checker{fixture.Checker()};
                const Bytes selector{0, static_cast<unsigned char>(collate), 0, 0x20, 0x80, 0};
                cycle("STORAGE/select/" + std::string(collate ? "collated/" : "items/") +
                          std::to_string(bytes) + "/" + std::to_string(n), bytes, n, [&] {
                    Frame frame{{selector}, fixture.context};
                    ValtypeStack alt;
                    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
                    const auto status{EvalOpTx(frame.stack, alt, tx_checker, frame.context, frame.budget, &error)};
                    Require(status == OpTxResult::NORMAL && frame.stack.size() == (collate ? 1 : n),
                            "storage OP_TX fixture failed");
                    Observe(frame.stack);
                });
            }
        }
    }
    Require(manifest.good(), "storage manifest write failed");
}

// READ: Val64 zero/comparison helpers. Full scans are forced by equal/all-zero
// operands. Normalization uses
// independent padded-zero values because repeating TrimTail would time empties.
void EstimateTraversal(Runner& r)
{
    std::vector<Point> reads;
    for(size_t n:Sizes(r.options,1)) {
        const size_t words=(n+7)/8, bytes=words*8;
        auto test=r.Repeated("READ/zero/"+std::to_string(bytes),[&]{return Words(words,0);},[](auto& a,size_t){
            const bool v=ProbeVal64::SpanIsAllZero(std::span<const uint64_t>{a}); Observe(v);
        });
        reads.push_back({1,double(bytes),std::move(test)});
        auto compare=r.Repeated("READ/compare/"+std::to_string(bytes),[&]{return std::pair{Words(words,1),Words(words,1)};},[](auto& a,size_t){
            const int v=ProbeVal64::CompareSpans(std::span<const uint64_t>{a.first},std::span<const uint64_t>{a.second}); Observe(v);
        });
        reads.push_back({1,double(bytes),std::move(compare)});
        auto trim=r.Measure("READ/trim/"+std::to_string(n),r.PoolLimit(2*W(n)+128),[&](size_t count){
            std::vector<Val64> v; v.reserve(count);
            for(size_t i=0;i<count;++i) v.emplace_back(Bytes(n,0));
            return v;
        },[](auto& v,size_t count){for(size_t i=0;i<count;++i) v[i].TrimTrailingZeros();});
        reads.push_back({1,double(bytes),std::move(trim)});
    }
    r.LinearRate("READ","rounded_byte",reads,"max full-scan zero/compare/TrimTrailingZeros time per modeled byte");
}

// ARITH: AddSpans/SubtractSpans are timed separately on fresh prepared input.
// A shared affine envelope exposes the kernel's fixed call/loop work instead
// of folding it into a small-operand per-byte rate.
void EstimateArithmetic(Runner& r)
{
    std::vector<Point> p;
    for(size_t n:Sizes(r.options,1)) {
        const size_t words=(n+7)/8;
        for(bool unequal:{false,true}) {
          for (bool borrow_chain : {false, true}) {
            struct State { Words a,b; };
            const auto make=[&](size_t count) {
                std::vector<State> states;
                states.reserve(count);
                for(size_t i=0;i<count;++i) {
                    states.push_back({Words(words,UINT64_MAX),Words(unequal?1:words,0)});
                    states.back().a.back()=0x7fffffffffffffffULL;
                    states.back().b.front()=1;
                    if (borrow_chain) {
                        std::fill(states.back().a.begin(), states.back().a.end(), 0);
                        states.back().a.back() = 1;
                    }
                }
                return states;
            };
            const auto suffix=std::to_string(words)+(unequal?"/one-word":"/equal")+
                              (borrow_chain ? "/borrow-chain" : "/carry-chain");
            const size_t capacity=r.PoolLimit(16*words+128);
            auto add=r.Measure("ARITH/add/"+suffix,capacity,make,[](auto& states,size_t count) {
                for(size_t i=0;i<count;++i) {
                    size_t nonzero=0;
                    const bool carry=ProbeVal64::AddSpans(states[i].a,states[i].b,nonzero);
                    Observe(carry); Observe(nonzero);
                }
            });
            auto sub=r.Measure("ARITH/sub/"+suffix,capacity,make,[](auto& states,size_t count) {
                for(size_t i=0;i<count;++i) {
                    size_t nonzero=0;
                    const bool borrow=ProbeVal64::SubtractSpans(states[i].a,states[i].b,nonzero);
                    Observe(borrow); Observe(nonzero);
                }
            });
            p.push_back({1,double(8*words),std::move(add)});
            p.push_back({1,double(8*words),std::move(sub)});
          }
        }
    }
    r.Pair("ARITH.fixed","ARITH.byte","rounded_byte",p,
           "shared covering line for separately measured AddSpans and SubtractSpans on fresh inputs");
}

// BIT: no conversions in the timed region. Exercise actual Val64 inversion and
// XOR plus the same std::reverse byte kernel used by OP_BYTEREV. Repetition is
// value-preserving or toggles bits; no decreasing-size steady-state shortcut.
void EstimateBit(Runner& r)
{
    std::vector<Point> p;
    for(size_t n:Sizes(r.options,1)) {
        auto invert=r.Repeated("BIT/invert/"+std::to_string(n),[&]{return std::make_unique<Val64>(Pattern(n));},[](auto& v,size_t){
            Val64::OpInvert(*v); Observe(*v);
        });
        p.push_back({1,double(W(n)),std::move(invert)});
        auto reverse=r.Repeated("BIT/reverse/"+std::to_string(n),[&]{return Pattern(n);},[](auto& v,size_t){std::reverse(v.begin(),v.end());});
        p.push_back({1,double(n),std::move(reverse)});
        struct State { Val64 a,b; explicit State(size_t n):a(Pattern(n,1)),b(Pattern(n,2)){} };
        auto xor_sample=r.Repeated("BIT/xor/"+std::to_string(n),[&]{return std::make_unique<State>(n);},[](auto& s,size_t){
            Val64::OpXor(s->a,s->b); Observe(s->a);
        });
        p.push_back({1,double(W(n)),std::move(xor_sample)});
        for(size_t shift:std::array<size_t,3>{1,7,63}) {
            // Whole-word-sized values avoid introducing representation padding.
            // The raw shift helpers preserve the view size even after bits vanish.
            auto down=r.Repeated("BIT/down/"+std::to_string(n)+"/"+std::to_string(shift),
                [&]{return std::make_unique<ProbeVal64>(Pattern(W(n)));},
                [&](auto& v,size_t){v->ShiftDown(0,shift);});
            p.push_back({1,double(W(n)),std::move(down)});
            auto up=r.Repeated("BIT/up/"+std::to_string(n)+"/"+std::to_string(shift),
                [&]{return std::make_unique<ProbeVal64>(Pattern(W(n)));},
                [&](auto& v,size_t){const bool carry=v->ShiftLeftLessThanWord(shift);Observe(carry);});
            p.push_back({1,double(W(n)),std::move(up)});
        }
    }
    r.LinearRate("BIT","byte",p,"max tail ns/unit of OpInvert, OpXor, ShiftDown, ShiftLeftLessThanWord and byte reversal");
}

// MOVE: real stack.Roll(depth), with payloads held constant. This moves owning
// headers, not payload bytes. Test empty and one-byte elements.
void EstimateMove(Runner& r)
{
    std::vector<Point> p;
    for(size_t d:std::initializer_list<size_t>{1,2,8,32,128,1024,8192,32767}) for(bool nonempty:{false,true}) {
        auto sample=r.Repeated("MOVE/"+std::to_string(d)+(nonempty?"/nonempty":"/empty"),[&]{
            auto stack=std::make_unique<ValtypeStack>(); stack->reserve(d+1);
            for(size_t i=0;i<=d;++i) stack->push_back(nonempty?Bytes{1}:Bytes{});
            return stack;
        },[&](auto& stack,size_t){stack->Roll(d);});
        p.push_back({1,double(d),std::move(sample)});
    }
    r.LinearRate("MOVE","entry",p,"max tail time per header moved by ValtypeStack::Roll");
}

// DIVCORE includes normalization and temporary storage in the prepared DIV/MOD
// call. Fresh operands prevent repetition from measuring an already divided value.
void DivisionBatchDiagnostic(const Options& options)
{
    std::ofstream out(options.output);
    Require(out.good(), "cannot open batch diagnostic output");
    out << "operation,batch,state,epoch,wall_ns,cpu_ns\n" << std::setprecision(17);
    const Bytes a{Pattern(65 * 8, 17)};
    Bytes b{Pattern(64 * 8, 22)};
    b.back() = 0x40;
    struct CapacityProbe : Val64 {
        using Val64::Val64;
        size_t Capacity() const { return m_bytes.capacity(); }
    };
    Bytes expected;
    for (bool spare : {false, true}) {
        Bytes bytes{a};
        if (spare) bytes.reserve(bytes.size() + 8);
        CapacityProbe dividend{std::move(bytes)};
        Val64 divisor{Bytes{b}};
        const size_t before{dividend.Capacity()};
        Require(Val64::OpDiv(dividend, divisor), "capacity control failed");
        std::cerr << "  Dividend capacity: " << (spare ? "spare" : "tight")
                  << ' ' << before << " -> " << dividend.Capacity() << " bytes\n";
        auto result = dividend.MoveToValtype();
        if (!spare) expected = result;
        else Require(result == expected, "capacity changed division result");
    }
    struct State {
        Val64 a, b;
        State(Bytes x, Bytes y, bool spare) : b(std::move(y))
        {
            if (spare) x.reserve(x.size() + 8);
            a = Val64(std::move(x));
        }
    };
    Bytes disturbance(64 * 1024 * 1024, 1);
    for (const std::string op : {"DIV", "MUL"}) {
        for (size_t count : {1U, 64U, 256U, 1024U, 4096U, 16384U, 21977U}) {
            for (const std::string mode : {"forward", "reverse", "disturbed", "spare-forward", "spare-disturbed", "spare-reverse"}) {
                if (!options.div_batch_case.empty() && (op != "DIV" || count != 4096 || mode != options.div_batch_case)) continue;
                std::cerr << "  Batch diagnostic: " << op << '/' << count << '/' << mode << '\n';
                for (size_t epoch = 0; epoch < options.epochs; ++epoch) {
                    std::vector<std::unique_ptr<State>> states;
                    states.reserve(count);
                    for (size_t i = 0; i < count; ++i) states.push_back(std::make_unique<State>(a, b, mode.starts_with("spare-")));
                    if (mode == "disturbed" || mode == "spare-disturbed") {
                        for (size_t i = 0; i < disturbance.size(); i += 64) ++disturbance[i];
                        Observe(disturbance);
                    }
                    const auto cpu_start = std::clock();
                    const auto start = Clock::now();
                    for (size_t i = 0; i < count; ++i) {
                        auto& state = *states[mode.ends_with("reverse") ? count - 1 - i : i];
                        if (op == "DIV") {
                            if (!Val64::OpDiv(state.a, state.b)) throw std::runtime_error("diagnostic division failed");
                        } else {
                            auto result = Val64::OpMul(state.a, state.b);
                            Observe(result);
                        }
                        Observe(state.a);
                    }
                    const auto end = Clock::now();
                    const auto cpu_end = std::clock();
                    out << op << ',' << count << ',' << mode << ',' << epoch << ','
                        << std::chrono::duration<double, std::nano>(end - start).count() / count << ','
                        << (cpu_end - cpu_start) * (1e9 / CLOCKS_PER_SEC) / count << '\n';
                }
            }
        }
    }
    Require(out.good(), "batch diagnostic write failed");
}

void EstimateDivision(Runner& r)
{
    size_t fixtures{0};
    for (size_t bw : {1U, 2U, 3U, 4U, 8U, 16U, 32U, 64U, 128U, 256U, 1024U}) {
        // bw + 1024 gives many quotient rows at every divisor width, which identifies the per-row term.
        std::vector<size_t> dividends{std::max(size_t{1}, bw - 1), bw, bw + 1, 2 * bw, 4 * bw, bw + 32, bw + 1024};
        std::sort(dividends.begin(), dividends.end());
        dividends.erase(std::unique(dividends.begin(), dividends.end()), dividends.end());
        for (size_t aw : dividends) {
            if (std::max(aw, bw) * 8 > r.options.max_bytes) continue;
            for (uint64_t seed : {17U, 127U}) {
                for (const std::string pattern : {"normalized", "top-clear", "top-one", "padded"}) {
                    Bytes a{Pattern(aw * 8, seed)}, b{Pattern(bw * 8, seed + 5)};
                    if (pattern == "normalized") {
                        b.back() |= 0x80;
                    } else if (pattern == "top-clear") {
                        b.back() = 0x40;
                    } else if (pattern == "top-one") {
                        std::fill(b.end() - 8, b.end(), 0);
                        b[b.size() - 8] = 1;
                    } else {
                        // Names and DIVCORE features use the trimmed divisor width.
                        b.back() |= 0x80;
                        b.resize(std::max(aw, bw) * 8, 0);
                    }
                    for (bool modulo : {false, true}) {
                        struct State { Val64 a, b; State(Bytes x, Bytes y) : a(std::move(x)), b(std::move(y)) {} };
                        const std::string name{"DIVCORE/" + std::to_string(aw) + "/" + std::to_string(bw) +
                            "/" + std::to_string(seed) + (modulo ? "/MOD/" : "/DIV/") + pattern};
                        r.Measure(name, r.PoolLimit(2 * (aw + bw) * 8 + 256), [&](size_t count) {
                            std::vector<std::unique_ptr<State>> states;
                            states.reserve(count);
                            for (size_t i{0}; i < count; ++i) states.push_back(std::make_unique<State>(a, b));
                            return states;
                        }, [&](auto& states, size_t count) {
                            for (size_t i{0}; i < count; ++i) {
                                const bool ok{modulo ? Val64::OpMod(states[i]->a, states[i]->b)
                                                     : Val64::OpDiv(states[i]->a, states[i]->b)};
                                if (!ok) throw std::runtime_error("division fixture failed");
                            }
                        });
                        if (++fixtures % 100 == 0) std::cerr << "  DIVCORE: " << fixtures << " fixtures measured\n";
                    }
                }
            }
        }
    }
    r.Add({"DIVCORE", "trial", "prepared DIV/MOD across divisor widths, shape and normalization paths",
           0, 0, "diagnostic_no_fit"});
}

// MULCORE times the complete prepared OP_MUL call, like DIVCORE for division:
// schoolbook rows over u longer-operand limbs and v shorter-operand limbs,
// including the result and scratch allocation. Operand preparation happens
// before timing; the product is kept alive until after timing, so its release
// and final byte conversion stay with PRODUCE and NORMALIZE.
void EstimateMultiplication(Runner& r)
{
    const size_t max_limbs{r.options.max_bytes / 8};
    // Cap single products so the largest fixtures stay near the full-budget scale.
    constexpr size_t MAX_CELLS{size_t{1} << 28};
    size_t fixtures{0};
    for (size_t v : {1U, 2U, 3U, 4U, 8U, 16U, 32U, 64U, 128U, 256U, 1024U, 4096U, 16384U}) {
        std::vector<size_t> rows;
        for (size_t factor : {1U, 2U, 4U, 16U, 128U, 1024U, 8192U, 65536U}) rows.push_back(v * factor);
        rows.push_back(v + 1);
        rows.push_back(max_limbs);
        std::sort(rows.begin(), rows.end());
        rows.erase(std::unique(rows.begin(), rows.end()), rows.end());
        for (size_t u : rows) {
            if (u < v || u > max_limbs || u * v > MAX_CELLS) continue;
            for (const std::string pattern : {"ones", "random"}) {
                Bytes a, b;
                if (pattern == "ones") {
                    // All-ones limbs maximize every carry chain.
                    a.assign(u * 8, 0xff);
                    b.assign(v * 8, 0xff);
                } else {
                    a = Pattern(u * 8, 17 + u);
                    b = Pattern(v * 8, 29 + v);
                }
                struct State {
                    Val64 a, b, product;
                    State(const Bytes& x, const Bytes& y) : a(Bytes{x}), b(Bytes{y}) {}
                };
                const std::string name{"MULCORE/" + std::to_string(u) + "/" + std::to_string(v) + "/" + pattern};
                r.Measure(name, r.PoolLimit(2 * (u + v) * 8 + (v + 1) * 8 + 256), [&](size_t count) {
                    std::vector<std::unique_ptr<State>> states;
                    states.reserve(count);
                    for (size_t i{0}; i < count; ++i) states.push_back(std::make_unique<State>(a, b));
                    return states;
                }, [&](auto& states, size_t count) {
                    for (size_t i{0}; i < count; ++i) states[i]->product = Val64::OpMul(states[i]->a, states[i]->b);
                });
                if (++fixtures % 25 == 0) std::cerr << "  MULCORE: " << fixtures << " fixtures measured\n";
            }
        }
    }
    r.Add({"MULCORE", "trial", "prepared complete OP_MUL across longer and shorter limb counts",
           0, 0, "diagnostic_no_fit"});
}

// Legacy primitives: MUL measures production MultiplySpan rows; DIVCORE bundles
// the complete prepared DIV/MOD call. The candidate schedule uses MULCORE instead.
void EstimateMulDiv(Runner& r)
{
    std::vector<Point> mul;
    for(size_t words:std::initializer_list<size_t>{1,2,4,8,32,128,1024,8192}) {
        if(words*8>r.options.max_bytes) continue;
        auto sample=r.Repeated("MUL/row/"+std::to_string(words),[&]{return std::pair{Words(words,UINT64_MAX),Words(words+1,0)};},[](auto& s,size_t i){
            ProbeVal64::MultiplySpan(s.second,s.first,UINT64_MAX-static_cast<uint64_t>(i)); Observe(s.second);
        });
        mul.push_back({1,double(words),std::move(sample)});
    }
    r.LinearRate("MUL", "limb_cell", mul, "MultiplySpan time per source limb; coefficient for u*v cells");
    EstimateDivision(r);
}

// H_*: initialized/finalized production hash passes. The shared SHA256 fit also
// covers libsecp's tagged hashing backend: tagged_sha256 performs one tag hash
// and then a hash of taghash||taghash||message (2 fixed passes, 2*32+taglen+n bytes).
// Outputs are observed. No use of an existing opcode hash price.
template <typename Hash> Sample HashSample(Runner& r,const std::string& name,size_t n)
{
    struct State { Bytes data; std::array<unsigned char,32> digest{}; explicit State(size_t n):data(Pattern(n)){} };
    return r.Repeated(name+"/"+std::to_string(n),[&]{return State{n};},[](auto& s,size_t){
        Hash().Write(Data(s.data),s.data.size()).Finalize(s.digest.data()); Observe(s.digest);
    });
}

void EstimateHashes(Runner& r,const Crypto& crypto)
{
    std::vector<Point> sha,ripemd,sha1;
    for(size_t n:Sizes(r.options)) sha.push_back({1,double(n),HashSample<CSHA256>(r,"H256/core",n)});
    const Bytes tag{'v','a','r','o','p','s'};
    for(size_t n:Sizes(r.options)) {
        struct State {Bytes data; std::array<unsigned char,32> out{}; explicit State(size_t n):data(Pattern(n)){} };
        auto sample=r.Repeated("H256/secp_tagged/"+std::to_string(n),[&]{return State{n};},[&](auto& s,size_t){
            int ok=secp256k1_tagged_sha256(crypto.ctx.get(),s.out.data(),tag.data(),tag.size(),Data(s.data),s.data.size());
            if(ok!=1) throw std::runtime_error("tagged hash failed");
            Observe(s.out);
        });
        sha.push_back({2,double(n+64+tag.size()),std::move(sample)});
    }
    for(size_t n:Sizes(r.options,0,520)) {
        ripemd.push_back({1,double(n),HashSample<CRIPEMD160>(r,"H160",n)});
        sha1.push_back({1,double(n),HashSample<CSHA1>(r,"H1",n)});
    }
    r.Pair("H256.fixed","H256.byte","byte",sha,"shared covering fit: Core SHA256 and libsecp tagged-SHA256; actual pass/byte counts");
    r.Pair("H160.fixed","H160.byte","byte",ripemd,"CRIPEMD160 init/write/finalize; operand domain <=520 bytes");
    r.Pair("H1.fixed","H1.byte","byte",sha1,"CSHA1 init/write/finalize; operand domain <=520 bytes");
}

// SIG: subtract the already estimated ONE challenge hash from actual Schnorr
// verification. The message-size sweep challenges the shared libsecp SHA rate.
// A negative residual is 'covered', not evidence that curve verification is free.
void EstimateSignatures(Runner& r,const Crypto& crypto)
{
    Rate sigma{"SIG","verification","max residual VerifySchnorr(msg)-H256(64+msglen); no signature cache"};
    bool positive=false;
    for(size_t n:std::array<size_t,7>{0,32,64,128,1024,8192,65536}) {
        if(n>r.options.max_bytes) continue;
        Bytes msg=Pattern(n); auto signature=crypto.Sign(msg);
        auto sample=r.Repeated("SIG/"+std::to_string(n),[]{return uint64_t{0};},[&](auto& good,size_t){
            bool valid=crypto.pubkey.VerifySchnorr(Message(msg),signature); good+=valid; Observe(valid);
            if(!valid) throw std::runtime_error("verification failed");
        });
        const double background=r.Get("H256.fixed")+r.Get("H256.byte")*(64+n);
        sigma.median=std::max(sigma.median,sample.median-background);
        sigma.tail=std::max(sigma.tail,sample.tail-background);
        positive|=sample.tail>background;
    }
    if(!positive) sigma.status="covered_by_other_rates";
    r.Add(sigma);
    auto tweak=r.Repeated("TWEAK",[]{return uint64_t{0};},[&](auto& good,size_t){
        auto result=crypto.pubkey.AddTweak(crypto.tweak); if(!result) throw std::runtime_error("tweak failed");
        good+=result->data()[0]; Observe(result);
    });
    r.LinearRate("TWEAK","operation",{{1,1,std::move(tweak)}},"XOnlyPubKey::AddTweak: parse, group operation, x-only serialization");
}

// SELECT: EvalOpTx over one input and N empty witness items, in both formats.
// k = 1 selected input + N witness items, not implementation traversal counts.
// Includes planning, empty-result production and cleanup. Collated framing is
// included in this diagnostic too; it must not also receive a copying allowance.
void EstimateItems(Runner& r)
{
    std::vector<Point> p;
    for (bool collate : {false, true}) {
        for (size_t n : std::array<size_t,14>{0, 1, 2, 8, 32, 128, 512, 2048, 4096,
                                               8192, 12288, 16384, 24576, 30000}) {
            const Bytes selector{0, static_cast<unsigned char>(collate ? 1 : 0), 0, 0x20, 0x80, 0};
            TransactionFixture fixture(n); auto checker=fixture.Checker();
            const std::vector<Bytes> initial{selector};
            const size_t output_entries{collate ? 1U : n};
            const size_t selected_items{1 + n};
            auto sample=r.Measure("SELECT/empty_items/" + std::string(collate ? "collated/" : "noncollated/") +
                                      std::to_string(n),
                                  r.PoolLimit(1024 + n * 96),
                                  [&](size_t count){
                                      std::vector<std::unique_ptr<Frame>> v; v.reserve(count);
                                      for (size_t i{0}; i < count; ++i) {
                                          v.push_back(std::make_unique<Frame>(initial, fixture.context));
                                      }
                                      return v;
                                  },
                                  [&](auto& v, size_t count){
                                      ValtypeStack alt;
                                      for (size_t i{0}; i < count; ++i) {
                                          ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
                                          auto status=EvalOpTx(v[i]->stack, alt, checker, v[i]->context,
                                                               v[i]->budget, &error);
                                          if (status != OpTxResult::NORMAL || v[i]->stack.size() != output_entries) {
                                              throw std::runtime_error("OP_TX item fixture failed");
                                          }
                                          while (v[i]->stack.size() != 0) v[i]->stack.pop_back();
                                      }
                                  });
            p.push_back({1, static_cast<double>(selected_items), std::move(sample)});
        }
    }
    r.Pair("SELECT.fixed", "SELECT.item", "selected_item", p,
           "EvalOpTx lifetime for one selected input plus N empty witness items; both output formats");
}

// DECODE: real GetOp without payload materialization, as used for a scan. Dense
// one-byte bodies are the linear-byte envelope; data pushes also exercise length
// decoding. Never time a copied/reimplemented decoder.
void EstimateDecode(Runner& r)
{
    std::vector<Point> p;
    for(size_t length:std::initializer_list<size_t>{64,256,1024,4096,65536}) {
        CScript script; for(size_t i=0;i<length;++i) script<<OP_NOP;
        auto sample=r.Repeated("DECODE/dense/"+std::to_string(length),[]{return uint64_t{0};},[&](auto& sum,size_t){
            CScript::const_iterator pc=script.begin(); opcodetype op;
            while(pc!=script.end()) {if(!script.GetOp(pc,op)) throw std::runtime_error("decode failed"); sum+=static_cast<unsigned int>(op);}
            Observe(sum);
        });
        p.push_back({1,double(script.size()),std::move(sample)});
    }
    r.LinearRate("DECODE","body_byte",p,"max ns/body-byte of actual GetOp prescan on dense instruction streams");
}

// FINAL: production epilogue, minus its already estimated preparation and scan.
// Final stack payload is nonzero at the high end to require a full truth scan.
void EstimateFinal(Runner& r)
{
    Rate final{"FINAL","evaluation","CheckTapscriptV2ScriptResult residual after PREP(n)+READ(W(n))"};
    for(size_t n:std::array<size_t,5>{1,8,64,1024,65536}) {
        if(n>r.options.max_bytes) continue;
        Bytes value(n,0); value.back()=1;
        const std::vector<Bytes> initial{value};
        auto sample=r.Measure("FINAL/"+std::to_string(n),r.PoolLimit(2*n+512),[&](size_t count){
            std::vector<std::unique_ptr<Frame>> v; v.reserve(count);
            for(size_t i=0;i<count;++i) v.push_back(std::make_unique<Frame>(initial));
            return v;
        },[](auto& v,size_t count){
            for(size_t i=0;i<count;++i) {
                ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
                if(!CheckTapscriptV2ScriptResult(v[i]->stack,v[i]->budget,&error)) throw std::runtime_error("final check fixture failed");
            }
        });
        const double background=r.Get("PREP.fixed")+(r.Get("PREP.byte")+r.Get("READ"))*W(n);
        final.median=std::max(final.median,sample.median-background);
        final.tail=std::max(final.tail,sample.tail-background);
    }
    if(final.tail==0) final.status="covered_by_other_rates";
    r.Add(final);
}

void Help()
{
    std::cout << "Usage: bench_varops_primitives (--reference-csv FILE | --pre-v2-seconds SECONDS | --max-diagnostic) [options]\n"
        "  --out FILE          Summary CSV (default dev/varops/primitive_costs.csv); raw epochs use FILE.samples.csv\n"
        "  --epochs N          Measured epochs per fixture (default 7)\n"
        "  --div-batch-diagnostic Fixed-batch DIV and full-MUL memory-state controls; raw timings only\n"
        "  --div-batch-case MODE Focus diagnostic on DIV/4096 with forward, reverse or spare-reverse traversal\n"
        "  --sample-ms MS      Target timed duration per epoch (default 10)\n"
        "  --copy-sample-ms MS Target duration for COPY/producer lifetime fixtures (default 100)\n"
        "  --calibration-candidate Collect the frozen PRODUCE/NORMALIZE model only\n"
        "  --percentile P      Empirical quantile, 0..1 (default .5; NOT a confidence interval)\n"
        "  --margin M          Multiplicative margin >=1 (default 1)\n"
        "  --max-bytes N       Maximum linear-probe payload (default 4000000)\n"
        "  --fixture-mib N     Maximum estimated prepared-state pool (default 64)\n"
        "  --portable-math     Exercise the existing Val64 portable-math test path\n"
        "  --offset-spans      Exercise the existing Val64 offset-alignment test path\n"
        "  --prep-audit        Include neighbours of the PREP binding-size candidates\n"
    "  --prep-only         Run only the PREP/OUTPUT ownership-conversion probes\n"
    "  --copy-only         Run only the COPY/RELEASE isolated/churn probes\n"
    "  --storage-only      Complete storage lifetimes and allocating-opcode checks\n"
    "  --produce-only      Producer lifetimes and isolated numeric materialization\n"
    "  --growth-only       Complete producer growth lifetimes near observed allocation boundaries\n"
    "  --growth-seed N     Shuffle growth-only fixture order reproducibly (default 1)\n"
    "  --arith-only        Run only the separately measured ADD/SUB kernel audit\n"
    "  --div-only          Run only the prepared DIV/MOD size and normalization sweep\n"
    "  --mul-only          Run only the prepared complete OP_MUL sweep (MULCORE)\n"
    "  --hash-only         Run only the hash primitive probes\n"
    "  --fixed-only        Run only the F probes (F-only instruction groups and skipped NOPs)\n"
    "  --items-only        Run only the OP_TX SELECT probes\n"
    "  --max-diagnostic    Time OP_MAX's copy, compare, trim, and buffer lifetimes\n"
    "  --self-test         Check estimator and production helper fixtures, then exit\n";
}

Options Parse(int argc,char** argv)
{
    Options o;
    for(int i=1;i<argc;++i) {
        const std::string arg=argv[i];
        auto value=[&]() {Require(i+1<argc,"missing value for "+arg);return std::string(argv[++i]);};
        auto integer=[&]() {const double x=Number(value());Require(x>=0&&x<=double(UINT32_MAX)&&x==std::floor(x),"invalid integer for "+arg);return static_cast<size_t>(x);};
        if(arg=="--help" || arg=="-h") {Help();std::exit(0);}
        else if(arg=="--reference-csv") o.reference_csv=value();
        else if(arg=="--pre-v2-seconds") o.reference_sec=Number(value());
        else if(arg=="--out") o.output=value();
        else if(arg=="--epochs") o.epochs=integer();
        else if(arg=="--sample-ms") o.epoch_ms=Number(value());
        else if(arg=="--copy-sample-ms") o.copy_epoch_ms=Number(value());
        else if(arg=="--percentile") o.percentile=Number(value());
        else if(arg=="--margin") o.margin=Number(value());
        else if(arg=="--max-bytes") o.max_bytes=integer();
        else if(arg=="--fixture-mib") {const size_t n=integer();Require(n>=1&&n<=4096,"fixture MiB out of range");o.fixture_bytes=n*size_t{1024}*1024;}
        else if(arg=="--portable-math") o.portable_math=true;
        else if(arg=="--offset-spans") o.offset_spans=true;
        else if(arg=="--prep-audit") o.prep_audit=true;
        else if(arg=="--prep-only") o.prep_only=true;
        else if(arg=="--copy-only") o.copy_only=true;
        else if(arg=="--storage-only") o.storage_only=true;
        else if(arg=="--produce-only") o.produce_only=true;
        else if(arg=="--growth-only") { o.produce_only=true; o.growth_only=true; }
        else if(arg=="--growth-seed") o.growth_seed=integer();
        else if(arg=="--max-diagnostic") o.max_diagnostic=true;
        else if(arg=="--arith-only") o.arith_only=true;
        else if(arg=="--calibration-candidate") o.calibration_candidate=true;
        else if(arg=="--div-only") o.div_only=true;
        else if(arg=="--mul-only") o.mul_only=true;
        else if(arg=="--div-batch-diagnostic") o.div_batch_diagnostic=true;
        else if(arg=="--div-batch-case") { o.div_batch_diagnostic=true; o.div_batch_case=value(); }
        else if(arg=="--hash-only") o.hash_only=true;
        else if(arg=="--fixed-only") o.fixed_only=true;
        else if(arg=="--items-only") o.items_only=true;
        else if(arg=="--self-test") o.self_test=true;
        else throw std::runtime_error("unknown option: "+arg);
    }
    Require(int(o.prep_only) + int(o.copy_only) + int(o.storage_only) + int(o.produce_only) + int(o.arith_only) + int(o.div_only) + int(o.mul_only) + int(o.hash_only) + int(o.fixed_only) + int(o.items_only) + int(o.max_diagnostic) + int(o.div_batch_diagnostic) <= 1,
            "choose only one focused probe group");
    Require(!o.calibration_candidate || !(o.prep_only || o.copy_only || o.storage_only || o.produce_only ||
            o.arith_only || o.div_only || o.mul_only || o.hash_only || o.fixed_only || o.items_only || o.max_diagnostic || o.div_batch_diagnostic),
            "candidate collection cannot be combined with a focused probe");
    Require(o.epochs>=1 && o.epochs<=1000,"epochs must be 1..1000");
    Require(o.div_batch_case.empty() || o.div_batch_case == "forward" || o.div_batch_case == "reverse" || o.div_batch_case == "spare-reverse", "unknown division batch case");
    Require(o.epoch_ms>0 && o.epoch_ms<=1000,"sample-ms must be >0 and <=1000");
    if (o.copy_epoch_ms == 0) o.copy_epoch_ms = o.epoch_ms;
    Require(o.copy_epoch_ms>0 && o.copy_epoch_ms<=1000,"copy-sample-ms must be >0 and <=1000");
    Require(o.percentile>=0.5 && o.percentile<=1,"percentile must be .5..1");
    Require(o.margin>=1 && o.margin<=100,"margin must be 1..100");
    Require(o.max_bytes>=64 && o.max_bytes<=4'000'000,"max-bytes must be 64..4000000");
    if(!o.reference_csv.empty()) {
        Require(o.reference_sec==0,"choose only one reference source");
        std::ifstream in(o.reference_csv);Require(in.good(),"cannot open reference CSV");
        o.reference_sec=ReadReference(in);
    }
    if(!o.self_test && !o.max_diagnostic && !o.div_batch_diagnostic) Require(o.reference_sec>0,"supply --reference-csv or --pre-v2-seconds from same-machine bench_varops");
    return o;
}

void MeasureMaxDiagnostic(const Options& options)
{
    // Recreate OP_2DUP, OP_MAX, OP_DROP with persistent source values. The
    // split path exposes phases; the native path checks its timing against OpMax.
    std::ofstream out(options.output);
    Require(out.good(), "cannot open OP_MAX diagnostic output");
    out << "bytes,pattern,epoch,mode,repetitions,copy_ns,prep_ns,opmax_or_compare_ns,trim_ns,output_ns,drop_ns,operand_destroy_ns,total_ns\n";
    for (const size_t size : {size_t{520}, size_t{65'536}, size_t{1'950'000}, size_t{2'000'000}}) {
        for (const bool padded : {false, true}) {
            Bytes value{Pattern(size)};
            if (padded) {
                std::fill(value.begin(), value.end(), 0);
                value.front() = 1;
            } else {
                value.back() = 0x7f;
            }
            const size_t repetitions{size >= 1'000'000 ? 500U : size >= 65'536 ? 5'000U : 50'000U};
            for (size_t epoch{0}; epoch < options.epochs; ++epoch) {
                for (const bool split : {epoch % 2 == 0, epoch % 2 != 0}) {
                    ValtypeStack stack;
                    stack.reserve(4);
                    stack.push_back(value);
                    stack.push_back(value);
                    std::array<double, 7> phases{};
                    const auto batch_start{Clock::now()};
                    for (size_t i{0}; i < repetitions; ++i) {
                        const auto t0{Clock::now()};
                        stack.push_back(stack.at(0));
                        stack.push_back(stack.at(1));
                        const auto t1{Clock::now()};
                        Clock::time_point after_drop;
                        {
                            Val64 right, left;
                            Require(stack.PopVal64(right) && stack.PopVal64(left), "OP_MAX diagnostic stack underflow");
                            const auto t2{Clock::now()};
                            if (split) {
                                const int comparison{left.Compare(right)};
                                const auto t3{Clock::now()};
                                if (comparison < 0) left = std::move(right);
                                left.TrimTrailingZeros();
                                const auto t4{Clock::now()};
                                phases[2] += std::chrono::duration<double, std::nano>(t3 - t2).count();
                                phases[3] += std::chrono::duration<double, std::nano>(t4 - t3).count();
                            } else {
                                Val64::OpMax(left, right);
                                phases[2] += std::chrono::duration<double, std::nano>(Clock::now() - t2).count();
                            }
                            const auto t4{Clock::now()};
                            stack.push_back(left.MoveToValtype());
                            const auto t5{Clock::now()};
                            stack.pop_back();
                            const auto t6{Clock::now()};
                            after_drop = t6;
                            phases[0] += std::chrono::duration<double, std::nano>(t1 - t0).count();
                            phases[1] += std::chrono::duration<double, std::nano>(t2 - t1).count();
                            phases[4] += std::chrono::duration<double, std::nano>(t5 - t4).count();
                            phases[5] += std::chrono::duration<double, std::nano>(t6 - t5).count();
                        }
                        const auto t7{Clock::now()};
                        phases[6] += std::chrono::duration<double, std::nano>(t7 - after_drop).count();
                    }
                    Require(stack.size() == 2 && stack.GetTotalSize() == 2 * size,
                            "OP_MAX diagnostic did not restore its stack");
                    const double total_ns{std::chrono::duration<double, std::nano>(Clock::now() - batch_start).count() / repetitions};
                    out << size << ',' << (padded ? "padded" : "dense") << ',' << epoch << ','
                        << (split ? "split" : "native") << ',' << repetitions;
                    for (size_t phase{0}; phase < 6; ++phase) {
                        out << ',';
                        if (split || phase != 3) out << phases[phase] / repetitions;
                    }
                    out << ',' << phases[6] / repetitions;
                    out << ',' << total_ns << '\n';
                }
            }
        }
    }
    Require(out.good(), "OP_MAX diagnostic output failed");
}

void ProductionSelfTests()
{
    EstimatorSelfTests();
    Words a{5,0},b{7,0}; size_t nonzero=0;
    Require(!ProbeVal64::AddSpans(a,b,nonzero)&&a[0]==12,"AddSpans self-test");
    Require(!ProbeVal64::SubtractSpans(a,b,nonzero)&&a[0]==5,"SubtractSpans self-test");
    for (size_t words : {1U, 2U, 8U, 65U}) {
        Words lhs(words, 0), rhs(words, 0);
        lhs.back() = 1;
        rhs.front() = 1;
        Require(!ProbeVal64::SubtractSpans(lhs, rhs, nonzero), "borrow-chain underflow");
        Require(lhs.back() == 0 && std::all_of(lhs.begin(), lhs.end() - 1,
                    [](uint64_t limb) { return limb == UINT64_MAX; }), "full borrow chain not exercised");
    }
    Words product(3);ProbeVal64::MultiplySpan(product,a,3);
    Require(product[0]==15,"MultiplySpan self-test");
    Val64 x(Bytes{100}),y(Bytes{7});Require(Val64::OpDiv(x,y),"division self-test");
    Require(x.MoveToValtype()==Bytes{14},"division result");
    Crypto crypto;auto signature=crypto.Sign(Bytes{1,2,3});
    Require(crypto.pubkey.VerifySchnorr(std::array<unsigned char,3>{1,2,3},signature),"signature self-test");
    TransactionFixture f(8);auto checker=f.Checker();
    std::vector<Bytes> initial{Bytes{0,0,0,0x20,0x80,0}};
    Frame frame(initial,f.context);ValtypeStack alt;ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    Require(EvalOpTx(frame.stack,alt,checker,frame.context,frame.budget,&error)==OpTxResult::NORMAL,"OP_TX self-test");
    Require(frame.stack.size()==8 && frame.stack.GetTotalSize()==0,"OP_TX result count");
}

} // namespace primitive_bench

int main(int argc,char** argv)
{
    using namespace primitive_bench;
    try {
        Options options=Parse(argc,argv);
        ProbeVal64::Configure(options.portable_math,options.offset_spans);
        std::cerr<<"SHA256 backend: "<<SHA256AutoDetect()<<'\n';
        ProductionSelfTests();
        if(options.self_test) {std::cout<<"Estimator and production-helper self-tests passed.\n";return 0;}
        if(options.max_diagnostic) {
            MeasureMaxDiagnostic(options);
            std::cerr << "Wrote OP_MAX diagnostic to " << options.output << '\n';
            return 0;
        }
        std::cerr<<"Reference: "<<options.reference_sec<<" s (Script evaluation only).\n"
                 <<"Empirical percentile: "<<options.percentile<<"; safety multiplier: "<<options.margin<<".\n";
        if (options.div_batch_diagnostic) { DivisionBatchDiagnostic(options); return 0; }
        Runner runner(options);Crypto crypto;
        if (options.calibration_candidate) {
            EstimateFixed(runner);
            EstimateProducer(runner);
            EstimateRepresentation(runner, false);
            EstimateTraversal(runner);
            EstimateArithmetic(runner);
            EstimateBit(runner);
            EstimateMove(runner);
            EstimateMultiplication(runner);
            EstimateDivision(runner);
            EstimateHashes(runner, crypto);
            EstimateSignatures(runner, crypto);
            runner.Save();
            return 0;
        }
        if (options.epochs == 1) std::cerr << "Single-epoch pilot: no repeatability or uncertainty estimate.\n";
        if (options.prep_only) {
            EstimateRepresentation(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.copy_only) {
            EstimateCopy(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.storage_only) {
            EstimateStorage(runner);
            runner.Save();
            std::cerr << "Wrote storage lifetimes to " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.produce_only) {
            EstimateProducer(runner);
            runner.Save();
            std::cerr << "Wrote producer lifetimes to " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.arith_only) {
            EstimateArithmetic(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.fixed_only) {
            EstimateFixed(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.hash_only) {
            EstimateHashes(runner, crypto);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.mul_only) {
            EstimateMultiplication(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.div_only) {
            EstimateDivision(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        if (options.items_only) {
            EstimateItems(runner);
            runner.Save();
            std::cerr << "Wrote " << options.output << " and " << options.output << ".samples.csv\n";
            return 0;
        }
        EstimateFixed(runner);
        EstimateCopy(runner);
        EstimateRepresentation(runner);
        EstimateTraversal(runner);
        EstimateArithmetic(runner);
        EstimateBit(runner);
        EstimateMove(runner);
        EstimateMulDiv(runner);
        EstimateHashes(runner,crypto);
        EstimateSignatures(runner,crypto);
        EstimateItems(runner);
        EstimateDecode(runner);
        EstimateFinal(runner);
        runner.Save();
        std::cerr<<"Wrote "<<options.output<<" and "<<options.output<<".samples.csv\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<"bench_varops_primitives: "<<e.what()<<'\n';return 1;}
}
#endif
