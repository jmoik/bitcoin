"""Fit raw reduced-family timings and emit a self-contained preliminary HTML."""
import argparse
import collections
import csv
import datetime
import hashlib
import html
import json
import math
import pathlib
import platform
import statistics
import subprocess

ORDER = 'F PREP OUTPUT COPY RELEASE READ ARITH BIT MOVE MUL DIVCORE H256 H160 H1 SIG TWEAK SIGHASH SELECT DECODE FINAL'.split()
DISPLAY_NAMES = {'SELECT': 'OP_TX_SELECT', 'DECODE': 'MACRO_DECODE'}
PRIMITIVE_CATEGORIES = [
    ('interpreter', 'Interpreter and context', ('F', 'SELECT', 'DECODE', 'FINAL')),
    ('stack', 'Stack and byte processing', ('COPY', 'RELEASE', 'READ', 'MOVE')),
    ('numeric', 'Numeric and bit operations', ('PREP', 'OUTPUT', 'ARITH', 'BIT', 'MUL', 'DIVCORE')),
    ('crypto', 'Hashing and signatures', ('H256', 'H160', 'H1', 'SIG', 'SIGHASH', 'TWEAK')),
]
SAMPLED_DIMENSIONS = {
    'F': 'Executed NOP count',
    'COPY': 'Copied result bytes; isolated creation fitted, churn retained as a diagnostic',
    'RELEASE': 'Allocated capacity × isolated, churn-result, churn-source or retained 4 MB preallocation',
    'MUL': 'Source limb count; other operand fixed to one limb',
    'H160': 'Message bytes, at most 520',
    'H1': 'Message bytes, at most 520',
    'SIG': 'Signature message bytes',
    'DECODE': 'Body bytes',
    'FINAL': 'Final stack-item bytes',
    'PREP': 'Input bytes × tight or spare capacity',
    'OUTPUT': 'Result bytes, plus seven scalar values',
    'READ': 'Rounded bytes × zero, compare, or trim path',
    'ARITH': 'Operand words × add/subtract × equal/one-word second operand',
    'BIT': 'Operand bytes × kernel and shift distance',
    'MOVE': 'Roll depth × empty or nonempty items',
    'H256': 'Message bytes × Core or tagged hash path',
    'SELECT': 'Empty witness-item count × collated or noncollated output',
    'DIVCORE': 'Dividend limbs × divisor limbs × three data seeds',
    'SIGHASH': 'Five sighash modes',
    'TWEAK': 'One fixed key and tweak',
}
CONSTANT = {'F', 'SIG', 'TWEAK', 'SIGHASH', 'FINAL'}
UNDER_PENALTIES = (10, 100)
COLORS = ['#2563eb', '#d97706', '#15803d', '#9333ea', '#dc2626', '#0891b2', '#64748b', '#be185d']
NOTES = {
    'F': 'NOP evaluator time divided by executed instructions. Includes parsing/prescan and amortized entry/finalization, not pure CPU dispatch.',
    'PREP': 'Fit uses pre-reserved inputs. Tight-capacity inputs remain visible as excluded growth diagnostics; their extra work still needs coverage in complete compositions.',
    'OUTPUT': 'Shared fit includes materialization/insertion/release and small scalar construction. A shared fit does not establish that these paths have equal fixed work.',
    'COPY': 'Fit uses isolated copied-value creation and insertion, excluding subsequent release. Churn points remain visible only as composition diagnostics for COPY + RELEASE. The empty-copy fast path is shown but excluded. The local candidate uses this follow-up 100× fit; it remains preliminary.',
    'RELEASE': 'Times ValtypeStack removal and buffer destruction. Churn separates release of the copied result and the 4 MB source. Preallocated fixtures include touched buffers shrunk to empty before release: logical size and capacity then differ. OP_LEFT/RIGHT also use a separate provisional 1 varop per discarded byte after target adjustment and integer rounding. Capacity is diagnostic, not a consensus charge input.',
    'BIT': 'The one-byte reversal performs no swaps and is shown but excluded from this fit.',
    'MUL': 'Only MultiplySpan rows (u=1) were measured. The u*v extension is the declared model, not a measured complete multiplication or validation of accumulation/storage work.',
    'DIVCORE': 'Diagnostic fit of complete OpDiv on prepared operands, NOT an isolated trial coefficient. Storage and normalization are included. Do not add this fitted total to overlapping MUL/storage charges.',
    'H256': 'One shared H256 fit covers Core SHA256 and libsecp tagged hashing. Tagged calls use two passes and n+70 bytes. Backend differences remain visible; this compromise is not an upper bound.',
    'H160': 'Direct RIPEMD160 domain ends at 520 bytes. Includes the 32-byte HASH160 intermediate input.',
    'H1': 'Direct SHA1 domain ends at 520 bytes.',
    'SIG': 'Plot shows complete signature verification. Fit estimates a nonnegative constant over the fitted H256(64+n) allowance; it does not independently identify curve-only work.',
    'SIGHASH': 'Measured supported modes over prepared transaction context; excludes SIGHASH_SINGLE. Construction and hashing in this call are bundled, not independently isolated.',
    'SELECT': 'One selected input plus n empty witness items, both output formats. Includes planning, output production and cleanup (also collated framing). Not a pure traversal-only rate.',
    'DECODE': 'Dense GetOp scan diagnostic for the byte-based charge on OP_MACRO declarations and OP_CALLMACRO references; not a complete OP_SUCCESS prescan measurement.',
    'FINAL': 'Plot shows complete final checks. Fit estimates a nonnegative remainder over fitted PREP(W(n))+READ(W(n)); zero remainder would mean no extra allowance identified, not free finalization.',
}


def word(n):
    return math.ceil(n / 8) * 8


def sampling_grid(family, rows, group_rows, epochs):
    count = rows[family] // epochs
    if family == 'COPY':
        return (f'{group_rows[family, "isolated"] // epochs} isolated fitted + '
                f'{group_rows[family, "churn"] // epochs} churn diagnostic')
    if family == 'RELEASE':
        return ' + '.join(f'{group_rows[family, group] // epochs} {group}'
                          for group in ('isolated', 'churn', 'source', 'preallocated'))
    if family == 'OUTPUT':
        lengths = group_rows[family, 'materialized'] // epochs
        scalars = group_rows[family, 'scalar'] // epochs
        assert lengths + scalars == count
        return f'{lengths} + {scalars} = {count}'
    if family == 'DIVCORE':
        assert count % 3 == 0
        return f'{count // 3} × 3 = {count}'
    variants = [n // epochs for (name, _), n in group_rows.items() if name == family]
    if family != 'COPY' and len(variants) > 1 and len(set(variants)) == 1:
        return f'{variants[0]} × {len(variants)} = {count:,}'
    return f'{count:,}'


def decade(x):
    return -1 if x == 0 else math.floor(math.log10(x))


def weights(points):
    counts = collections.Counter((p['group'], decade(p['x'])) for p in points)
    groups = {p['group'] for p in points}
    bins = collections.Counter(g for g, _ in counts)
    return [1 / (len(groups) * bins[p['group']] * counts[p['group'], decade(p['x'])]) for p in points]


def minimize(fn, lo, hi):
    grid = [(fn(lo + (hi-lo)*i/80), lo + (hi-lo)*i/80) for i in range(81)]
    _, center = min(grid)
    left, right = max(lo, center-(hi-lo)/80), min(hi, center+(hi-lo)/80)
    for _ in range(70):
        a, b = left+(right-left)/3, right-(right-left)/3
        if fn(a) < fn(b):
            right = b
        else:
            left = a
    return (left+right)/2


def log_loss(predictions, points, ws, under_penalty):
    if min(predictions) <= 0:
        return math.inf
    return sum(w * (under_penalty if predicted < p['y'] else 1) *
               math.log(predicted/p['y'])**2
               for w, predicted, p in zip(ws, predictions, points))


def optimal_scale(shape, points, ws, under_penalty):
    """Minimize asymmetric log error for a fixed nonnegative feature shape."""
    targets = [math.log(p['y']/feature) for p, feature in zip(points, shape)]
    lo, hi = min(targets), max(targets)
    for _ in range(60):
        mid = (lo + hi)/2
        gradient = sum(w * (under_penalty if mid < target else 1) * (mid - target)
                       for w, target in zip(ws, targets))
        if gradient < 0:
            lo = mid
        else:
            hi = mid
    return math.exp((lo + hi)/2)


def fit(points, mode, under_penalty=1):
    ws = weights(points)
    def loss(pred):
        return log_loss(pred, points, ws, under_penalty)
    if mode == 'residual':
        def objective(q):
            return loss([p['background'] + math.exp(q) for p in points])
        q = minimize(objective, -30, math.log(max(p['y'] for p in points)*10))
        a = math.exp(q)
        if loss([p['background'] for p in points]) <= objective(q):
            a = 0
        return a, 0
    if mode == 'constant':
        if under_penalty == 1:
            return math.exp(sum(w*math.log(p['y']) for w, p in zip(ws, points))), 0
        return optimal_scale([1]*len(points), points, ws, under_penalty), 0
    # Nonnegative two-feature fit: a*c + b*v. Profile out overall scale.
    scale = max(p['v']/p['c'] for p in points) or 1
    def at(q):
        r = math.exp(q)/scale
        shape = [p['c']+r*p['v'] for p in points]
        a = (math.exp(sum(w*math.log(p['y']/value) for w, p, value in zip(ws, points, shape)))
             if under_penalty == 1 else optimal_scale(shape, points, ws, under_penalty))
        return loss([a*(p['c']+r*p['v']) for p in points]), a, a*r
    q = minimize(lambda z: at(z)[0], -35, 35)
    candidates = [at(q)]
    a = (math.exp(sum(w*math.log(p['y']/p['c']) for w, p in zip(ws, points)))
         if under_penalty == 1 else optimal_scale([p['c'] for p in points], points, ws, under_penalty))
    candidates.append((loss([a*p['c'] for p in points]), a, 0))
    if all(p['v'] > 0 for p in points):
        b = (math.exp(sum(w*math.log(p['y']/p['v']) for w, p in zip(ws, points)))
             if under_penalty == 1 else optimal_scale([p['v'] for p in points], points, ws, under_penalty))
        candidates.append((loss([b*p['v'] for p in points]), 0, b))
    return min(candidates)[1:]


def fit_divcore(points, under_penalty=1):
    """Fit intercept + quotient steps + quotient steps times divisor limbs."""
    ws = weights(points)
    features = [(1, p['c'], p['v']) for p in points]

    def loss(coeff):
        predictions = [sum(a*x for a, x in zip(coeff, row)) for row in features]
        return log_loss(predictions, points, ws, under_penalty)

    constant, _ = fit(points, 'constant', under_penalty)
    step, trial = fit(points, 'affine', under_penalty)
    starts = [(constant, 0, 0), (0, step, trial), (constant/3, step/3, trial/3)]
    candidates = []
    for start in starts:
        coeff = list(start)
        for _ in range(100 if under_penalty > 10 else 20):
            previous = loss(coeff)
            for i in range(3):
                present = [row[i] for row in features if row[i] > 0]
                upper = math.log(10*max(p['y'] for p in points)/min(present))

                def objective(q):
                    trial_coeff = coeff.copy()
                    trial_coeff[i] = math.exp(q)
                    return loss(trial_coeff)

                q = minimize(objective, -35, upper)
                candidate = math.exp(q)
                trial_coeff = coeff.copy()
                trial_coeff[i] = 0
                coeff[i] = candidate if objective(q) < loss(trial_coeff) else 0
            if previous-loss(coeff) < 1e-12:
                break
        candidates.append((loss(coeff), tuple(coeff)))
    return min(candidates)[1]


def features(family, x, group):
    if family == 'DIVCORE':
        return x, x*int(group.split('=')[1])
    if family == 'H256' and group == 'secp_tagged':
        return 2, x+70
    if family in {'PREP', 'OUTPUT'}:
        return 1, word(x)
    return 1, x


def parse(row):
    label = row['probe']; parts = label.split('/'); family = parts[0]
    x, group, included = 1, 'measurement', True
    y = float(row['ns_per_execution'])
    if family == 'F':
        x = int(parts[2])+1; y /= x; group = 'nop'
    elif family == 'PREP':
        x, group = int(parts[1]), parts[2]; included = group == 'spare'
    elif family == 'OUTPUT':
        if parts[1] == 'scalar':
            x = (int(parts[2]).bit_length()+7)//8; group = 'scalar'
        else:
            x = int(parts[1]); group = 'materialized'
    elif family == 'ARITH':
        x = int(parts[2])*8; group = parts[1]+'/'+parts[3]
    elif family in {'READ', 'BIT'}:
        x = int(parts[2]); group = parts[1]
        if family == 'READ' or group != 'reverse':
            x = word(x)
        if len(parts) > 3:
            group += '/'+parts[3]
    elif family == 'MOVE':
        x = int(parts[1]); group = parts[2]
    elif family == 'MUL':
        x = int(parts[2]); group = 'u=1'
    elif family == 'DIVCORE':
        aw, bw = int(parts[1]), int(parts[2]); x = aw if bw == 1 else aw-bw; group = f'v={bw}'
    elif family == 'H256':
        x = int(parts[2]); group = parts[1]
    elif family == 'SELECT':
        x = int(parts[3])+1; group = parts[2]
    elif family == 'DECODE':
        x = int(parts[2]); group = parts[1]
    elif family == 'COPY':
        x = int(parts[2]); group = parts[1]; included = group == 'isolated'
    elif family == 'RELEASE':
        group = parts[1]
        x = int(parts[3]) if group == 'preallocated' else word(int(parts[2]))
    elif family != 'TWEAK':
        x = int(parts[1])
    if family in {'COPY', 'RELEASE'} and x == 0 and group != 'preallocated':
        group = 'empty'
        included = False
    if label == 'BIT/reverse/1':
        included = False
    c, v = features(family, x, group)
    return family, dict(label=label, x=x, y=y, c=c, v=v, group=group, included=included,
                        batch_ns=float(row['ns_per_execution'])*int(row['repetitions']), background=0)


def formula(family, coeff):
    a, b = coeff[:2]
    if family in CONSTANT:
        return f'{a:.6g}'
    if family == 'MUL':
        return f'{a:.6g} + {b:.6g} × u × v'
    if family == 'DIVCORE':
        return f'{a:.6g} + {b:.6g} × s + {coeff[2]:.6g} × s × v'
    term = 'W(n)' if family in {'PREP', 'OUTPUT'} else 'k' if family in {'MOVE', 'SELECT'} else 'n'
    return (f'{a:.6g} + ' if a else '') + f'{b:.6g} × {term}'


def background(family, x, fits):
    if family == 'SIG':
        a,b = fits['H256']; return a+b*(64+x)
    if family == 'FINAL':
        a,b = fits['PREP']; ra,rb = fits['READ']; return a+b*word(x)+ra+rb*word(x)
    return 0


def predict(family, x, group, coeff, fits):
    a,b = coeff[:2]
    if family in CONSTANT:
        return a+background(family, x, fits)
    c,v = features(family, x, group)
    if family == 'DIVCORE':
        return a+b*c+coeff[2]*v
    return a*c+b*v


def plot(family, points, models):
    groups = sorted({p['group'] for p in points})
    included = [p for p in points if p['included']]
    path_specific = family in {'H256', 'DIVCORE'}
    model_groups = sorted({p['group'] for p in included}) if path_specific else [included[0]['group']]
    xmax = max(p['x'] for p in points) or 1
    ys = [p['y'] for p in points]
    for _, model, _, _ in models:
        ys += [predict(family,p['x'],p['group'],model[family],model)
               for p in points if p['included']]
    ymin, ymax = min(ys)*.55, max(ys)*1.8
    def xy(x,y):
        return 75+700*math.log1p(x)/math.log1p(xmax), 330-285*math.log(max(y,ymin)/ymin)/math.log(ymax/ymin)
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 820 420" role="img" aria-label="'+family+' measured timings and fitted function">',
           '<rect width="820" height="420" fill="white"/>', '<g font-family="system-ui" font-size="12" fill="#334155">']
    for power in range(math.floor(math.log10(ymin)), math.ceil(math.log10(ymax))+1):
        for mul in (1, 2, 5):
            y = mul*10**power
            if ymin <= y <= ymax:
                _,py = xy(0,y)
                out.append(f'<path d="M75 {py:.2f}H775" stroke="#e2e8f0"/><text x="67" y="{py+4:.2f}" text-anchor="end">{y:g}</text>')
    for x in [0]+[10**i for i in range(8) if 10**i <= xmax]:
        px,_ = xy(x,ymin)
        out.append(f'<text x="{px:.2f}" y="350" text-anchor="middle">{x:g}</text>')
    out.append('<defs><clipPath id="clip-'+family+'"><rect x="75" y="45" width="700" height="285"/></clipPath></defs>')
    out.append(f'<g clip-path="url(#clip-{family})">')
    model_legend = []
    for label, model, model_color, dash_pattern in models:
        for i, group in enumerate(model_groups):
            ps = [p for p in included if p['group'] == group] if path_specific else included
            lo, hi = min(p['x'] for p in ps), max(p['x'] for p in ps)
            if hi == lo:
                lo, hi = 0, xmax
            curve = []
            for j in range(260):
                x = math.expm1(math.log1p(lo)+(math.log1p(hi)-math.log1p(lo))*j/259)
                px, py = xy(x, predict(family, x, group, model[family], model))
                curve.append(f'{px:.2f},{py:.2f}')
            color = COLORS[i % len(COLORS)] if path_specific else model_color
            dash = f' stroke-dasharray="{dash_pattern}"' if dash_pattern else ''
            out.append(f'<polyline points="{" ".join(curve)}" fill="none" stroke="{color}" stroke-width="3"{dash}/>')
            model_legend.append(f'<span style="color:{color}">{"┄" if dash_pattern else "━"} '
                                f'{html.escape(label)}{f" for {group}" if path_specific else ""}</span>')
    for i, group in enumerate(groups):
        color = COLORS[i%len(COLORS)]
        ps = [p for p in points if p['group'] == group]
        for p in ps:
            px,py = xy(p['x'],p['y'])
            style = f'fill="{color}" opacity=".75"' if p['included'] else f'fill="white" stroke="{color}" stroke-width="1.5"'
            excluded = '' if p['included'] else '; excluded from fit'
            out.append(f'<circle cx="{px:.2f}" cy="{py:.2f}" r="3.1" {style}><title>{html.escape(p["label"])}: {p["y"]:.6g} ns; batch {p["batch_ns"]/1000:.3g} µs{excluded}</title></circle>')
    out.append('</g>')
    axis = 'bytes n' if family not in {'F','MOVE','MUL','DIVCORE','SIGHASH','SELECT','TWEAK','RELEASE'} else {
        'F':'executed instructions', 'MOVE':'entries k', 'MUL':'source limbs v (u = 1)', 'DIVCORE':'quotient steps s',
        'SIGHASH':'sighash mode (numeric identifier)', 'SELECT':'selected input + witness items k', 'TWEAK':'fixture',
        'RELEASE':'allocated capacity (bytes) · diagnostic'}[family]
    out.append(f'<text x="425" y="381" text-anchor="middle">{axis} · log(1+x) spacing</text><text x="75" y="24">{"ns / executed instruction" if family == "F" else "ns / measured call"} · logarithmic y</text></g></svg>')
    legend = ' '.join(model_legend) + ' ' + ' '.join(f'<span style="color:{COLORS[i%len(COLORS)]}">● measured {html.escape(g)}'+(' (excluded from fit)' if not any(p['included'] for p in points if p['group']==g) else '')+'</span>' for i,g in enumerate(groups))
    if any(not p['included'] for p in points):
        legend += ' <span>○ excluded measurement</span>'
    return ''.join(out)+'<div class="legend">'+legend+'</div>'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('result_dir', type=pathlib.Path)
    parser.add_argument('--sample-ms', type=float, required=True)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--target-fraction', type=float, default=0.9,
                        help='Provisional runtime target as a fraction of the measured pre-v2 reference (default: 0.9)')
    parser.add_argument('--measurements-csv', type=pathlib.Path,
                        help='Read a focused measurement CSV while updating the existing report')
    parser.add_argument('--baseline-dir', type=pathlib.Path,
                        help='Use this complete run for families other than COPY/RELEASE when result_dir contains a focused run')
    parser.add_argument('--output-dir', type=pathlib.Path,
                        help='Write the single report here instead of creating one beside the new measurements')
    parser.add_argument('--opcode-composition', type=pathlib.Path,
                        help='Current bench_varops coverage manifest (defaults to OUTPUT_DIR/opcode-composition.csv)')
    args = parser.parse_args()
    if not 0 < args.target_fraction <= 1:
        parser.error('--target-fraction must be greater than 0 and at most 1')
    root = args.result_dir.resolve()
    output_root = args.output_dir.resolve() if args.output_dir else root
    composition_source = (args.opcode_composition.resolve() if args.opcode_composition else
                          output_root/'opcode-composition.csv')
    source = (args.measurements_csv.resolve() if args.measurements_csv else
              root/'measurements.csv.samples.csv')
    series = collections.defaultdict(list)
    repeated = collections.defaultdict(list)
    epochs = set()
    row_count = 0
    family_rows = collections.Counter()
    group_rows = collections.Counter()
    focused_families = {'COPY', 'RELEASE'}
    sample_sources = [(source, None)]
    if args.baseline_dir:
        sample_sources = [(args.baseline_dir.resolve()/'measurements.csv.samples.csv', False),
                          (source, True)]
    for sample_source, copy_only in sample_sources:
        with sample_source.open() as f:
            for row in csv.DictReader(f):
                if row['probe'].startswith('COPY_CONTROL/'):
                    continue
                name = row['probe'].split('/', 1)[0]
                if name == 'ZERO':
                    continue  # Retain historical measurements without fitting the removed primitive.
                if copy_only is not None and (name in focused_families) != copy_only:
                    continue
                name,p = parse(row)
                row_count += 1
                epochs.add(int(row['epoch']))
                assert p['y'] > 0, row['probe']
                repeated[name,p['label']].append(p)
                family_rows[name] += 1
                group_rows[name,p['group']] += 1
    assert epochs == set(range(len(epochs))), 'Missing measured epoch.'
    assert all(len(samples) % len(epochs) == 0 for samples in repeated.values()), 'Incomplete fixture epochs.'
    for (name,_), samples in repeated.items():
        p = dict(samples[0])
        p['y'] = statistics.median(s['y'] for s in samples)
        assert p['y'] > 0, p['label']
        p['batch_ns'] = min(s['batch_ns'] for s in samples)
        series[name].append(p)
    assert set(series) == set(ORDER)
    category_families = [family for _, _, families in PRIMITIVE_CATEGORIES for family in families]
    assert sorted(category_families) == sorted(ORDER)
    assert set(SAMPLED_DIMENSIONS) == set(ORDER)
    assert all(count % len(epochs) == 0 for count in family_rows.values())
    assert all(count % len(epochs) == 0 for count in group_rows.values())
    fits, penalized_fits, penalized_100_fits = {}, {}, {}
    for model, under_penalty in ((fits, 1), (penalized_fits, 10), (penalized_100_fits, 100)):
        for family in [f for f in ORDER if f not in {'SIG','FINAL'}]+['SIG','FINAL']:
            ps = [p for p in series[family] if p['included']]
            for p in ps:
                p['background'] = background(family,p['x'],model)
            mode = 'residual' if family in {'SIG','FINAL'} else 'constant' if family in CONSTANT else 'affine'
            model[family] = (fit_divcore(ps, under_penalty) if family == 'DIVCORE' else
                             fit(ps, mode, under_penalty))
    # Exact synthetic fixtures check the optimizer and declared feature shapes.
    test = [dict(x=x,y=12+.25*x,c=1,v=x,group='test') for x in [0,1,8,64,1024]]
    a,b = fit(test,'affine'); assert abs(a-12)<1e-5 and abs(b-.25)<1e-7
    for penalty in UNDER_PENALTIES:
        a,b = fit(test,'affine',penalty); assert abs(a-12)<1e-5 and abs(b-.25)<1e-7
    uneven = [dict(x=1,y=y,c=1,v=1,group='test') for y in (1,10)]
    assert fit(uneven,'constant',100)[0] > fit(uneven,'constant',10)[0] > fit(uneven,'constant')[0]
    div_test = [dict(p, y=5+2*p['c']+3*p['v']) for p in [dict(x=x, c=x, v=x*v, group=f'v={v}') for x in [1, 8, 64] for v in [1, 3, 8]]]
    da,db,dc = fit_divcore(div_test); assert abs(da-5)<1e-4 and abs(db-2)<1e-4 and abs(dc-3)<1e-4
    for penalty in UNDER_PENALTIES:
        da,db,dc = fit_divcore(div_test,penalty)
        assert abs(da-5)<5e-4 and abs(db-2)<5e-4 and abs(dc-3)<5e-4
    stamp = datetime.datetime.fromtimestamp(source.stat().st_mtime).astimezone().isoformat(timespec='seconds')
    repo = pathlib.Path(__file__).resolve().parents[3]
    binary = args.binary.resolve()
    summary = source.with_name(source.name.removesuffix('.samples.csv'))
    headers = {}
    with summary.open() as f:
        for line in f:
            if line.startswith('# ') and ': ' in line:
                key, value = line[2:].split(': ', 1)
                headers[key] = value.strip()
    cache = binary.parent.parent/'CMakeCache.txt'
    build = {}
    if cache.exists():
        for line in cache.read_text().splitlines():
            if line.startswith(('CMAKE_BUILD_TYPE:', 'GSR_PRIMITIVES_CANDIDATE_SCHEDULE:')):
                key, value = line.split('=', 1)
                build[key.split(':', 1)[0]] = value
    reference_seconds = float(headers['Reference_Script_Evaluation_Seconds'])
    target_seconds = reference_seconds * args.target_fraction
    meta = dict(collected=stamp,generated=datetime.datetime.now().astimezone().isoformat(timespec='seconds'),
                platform=platform.platform(),head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
                epochs=len(epochs),target_batch_ms=args.sample_ms,max_bytes=headers.get('Max_Probe_Bytes'),
                copy_target_batch_ms=headers.get('Copy_Target_Batch_MS'),
                reference_script_seconds=reference_seconds,target_fraction=args.target_fraction,
                target_script_seconds=target_seconds,cost_rounding='ceil each coefficient to whole varops',build=build,
                source_sha256=hashlib.sha256((repo/'src/bench/bench_varops_primitives.cpp').read_bytes()).hexdigest(),
                binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                samples_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    if args.baseline_dir:
        baseline_samples = args.baseline_dir.resolve()/'measurements.csv.samples.csv'
        meta['non_copy_samples'] = str(baseline_samples)
        meta['non_copy_samples_sha256'] = hashlib.sha256(baseline_samples.read_bytes()).hexdigest()
    composition_rows = []
    if composition_source.exists():
        with composition_source.open() as f:
            composition_rows = list(csv.DictReader(f))
        expected_columns = {'opcode', 'candidate formula', 'coefficients used', 'parity-test status'}
        if not composition_rows or set(composition_rows[0]) != expected_columns:
            raise RuntimeError(f'unexpected opcode-composition schema: {composition_source}')
        meta['opcode_composition'] = str(composition_source)
        meta['opcode_composition_sha256'] = hashlib.sha256(composition_source.read_bytes()).hexdigest()
    models = [('100× under-penalty fit', penalized_100_fits, '#7c3aed', '')]
    varops_per_ns = 40 / target_seconds
    table_rows, cards, results = {}, {}, {}
    for family in ORDER:
        ps=series[family]; selected=[p for p in ps if p['included']]; coeff=fits[family]
        errors=[math.log(predict(family,p['x'],p['group'],fits[family],fits)/p['y']) for p in selected]
        rms=math.exp(math.sqrt(sum(w*e*e for w,e in zip(weights(selected),errors))))
        worst=max(math.exp(abs(e)) for e in errors)
        under_ratios=[p['y']/predict(family,p['x'],p['group'],penalized_100_fits[family],penalized_100_fits)
                      for p in selected]
        misses=sum(ratio > 1 for ratio in under_ratios)
        max_under=max(1.0, *under_ratios)
        shortest=min(p['batch_ns'] for p in ps)/1000
        ftext=formula(family,coeff)
        penalized_text=formula(family,penalized_fits[family])
        penalized_100_text=formula(family,penalized_100_fits[family])
        rounded_cost=tuple(math.ceil(value * varops_per_ns) for value in penalized_100_fits[family])
        if family == 'SIG':
            rounded_cost = (500_000, 0)  # Sigops-parity override, not a fitted conversion.
        converted_text=formula(family, rounded_cost)
        if family == 'MUL':
            converted_text=f'u × ({rounded_cost[0]} + {rounded_cost[1]} × v)'
        note=NOTES.get(family,'')
        if family == 'SIG':
            note += ' The provisional candidate fixes SIG at 500,000 varops for sigops parity instead of using the fitted conversion.'
        if shortest < 10:
            note += f' Shortest batch is only {shortest:.2g} µs: timer/cache noise may be material.'
        if family=='TWEAK':
            note += ' One fixture only; no size dependence or repeatability test.'
        display_name = DISPLAY_NAMES.get(family, family)
        table_rows[family] = (f'<tr><td><a href="#{family}">{display_name}</a></td>'
                              f'<td>{html.escape(SAMPLED_DIMENSIONS[family])}</td>'
                              f'<td>{sampling_grid(family, family_rows, group_rows, len(epochs))}</td>'
                              f'<td>{len(selected)}/{len(ps)}</td>'
                              f'<td><code>{penalized_100_text}</code></td>'
                              f'<td><code>{converted_text}</code></td>'
                              f'<td>{misses}/{len(selected)}; {max_under:.2f}× max</td>'
                              f'<td>{rms:.3f}× / {worst:.3f}×</td></tr>')
        cards[family] = (f'<section id="{family}"><h2>{display_name}</h2>'
                         f'<p class="formula">100× under-penalty fit: {penalized_100_text} ns</p>'
                         f'<p class="formula">Provisional integer cost: {converted_text} varops</p>'
                         f'<p>{html.escape(note)}</p>'+plot(family,ps,models)+
                         f'<p class="metrics">{len(selected)} fitted / {len(ps)} measured fixtures · 100× fit below {misses} points (largest {max_under:.2f}×) · symmetric RMS error factor {rms:.3f}× · shortest batch {shortest:.3g} µs</p></section>')
        result=dict(a_ns=coeff[0],b_ns=coeff[1],formula_ns=ftext,weighted_rms_factor=rms,worst_error_factor=worst,notes=note,
                    provisional_integer_cost=rounded_cost,
                    applied_to_candidate=True,
                    under_penalty_10_fit=dict(a_ns=penalized_fits[family][0],
                                              b_ns=penalized_fits[family][1],
                                              formula_ns=penalized_text),
                    under_penalty_100_fit=dict(a_ns=penalized_100_fits[family][0],
                                               b_ns=penalized_100_fits[family][1],
                                               formula_ns=penalized_100_text))
        if family == 'DIVCORE':
            result['c_ns'] = coeff[2]
            result['under_penalty_10_fit']['c_ns'] = penalized_fits[family][2]
            result['under_penalty_100_fit']['c_ns'] = penalized_100_fits[family][2]
        results[family]=result
    doc='''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Varops primitive measurements</title>
<style>body{margin:0;background:#f4f6f8;color:#172536;font:16px/1.55 system-ui}main{max-width:1120px;margin:auto;padding:32px 20px}h1{font-size:30px;margin-bottom:8px}h2{margin:0;font-size:24px}.category-title{margin:36px 0 16px;scroll-margin-top:16px}p{margin:10px 0}a{color:#1d4ed8}header,section{background:white;padding:24px;border:1px solid #dce2e8;border-radius:10px;margin-bottom:24px}section{scroll-margin-top:16px}svg{width:100%;max-height:540px}.notice{border-left:4px solid #d97706;padding-left:16px}.formula{font:18px ui-monospace,monospace}.metrics,.legend{font-size:14px;color:#475569}.legend span{display:inline-block;margin-right:18px}.table{overflow:auto}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:9px;text-align:left;border-bottom:1px solid #e2e8f0}th{background:#f1f5f9}code{white-space:nowrap}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}details{margin-top:16px}nav{display:flex;flex-wrap:wrap;gap:8px 16px;margin:18px 0} @media(max-width:600px){main{padding:12px}header,section{padding:14px}.formula{font-size:15px}}</style><main><header><h1>Varops primitives: preliminary fits</h1>'''
    doc+=f'<p>Collected {stamp} · {len(ORDER)} families · {row_count // len(epochs)} fixture instances · {sum(map(len,series.values()))} plotted points · {len(epochs)} measured epochs per fixture</p>'
    if args.baseline_dir:
        doc+='<p>New COPY and RELEASE measurements are combined with the prior run for all other families; source files and hashes are listed below.</p>'
    doc+=f'''<p class="notice">The local candidate uses these rounded fit coefficients except SIG, which is fixed at 500,000 varops for sigops parity; OP_MULTI and discarded-byte charges are separate provisional measurements. This report does not plot the published or ordinary budget schedule, and the candidate has not passed runtime-safety validation.</p>
<p>Preliminary measurements, not calibrated costs. {args.sample_ms} ms target batches, with {html.escape(str(headers.get('Copy_Target_Batch_MS', args.sample_ms)))} ms for COPY/RELEASE; prepared-state limits can shorten them. Each dot is the median of measured epochs for that fixture. COPY is fitted only to isolated creation and insertion; churn remains a composition diagnostic for COPY + RELEASE. RELEASE measures destruction separately, and complete-cycle timings remain controls. The nanosecond fits have no safety margin; only their varops conversion uses the provisional {args.target_fraction:.0%} runtime target. No uncertainty estimates or acceptance claim. All timings are nanoseconds on this machine. Repeated fixture labels caused by word-rounded size aliases are collapsed to their median; raw records remain intact.</p>
<p>The displayed curves are the 100× underprediction-penalty fit: squared log(prediction / measurement) errors are weighted 100× when the fit falls below a measurement. Fits use equal weight per path and operand-size decade (zero separate) and nonnegative coefficients. Dots are unchanged measurements; H256 and DIVCORE show multiple lines for their specified paths or operand shapes. This exploratory fit is not an upper bound or an accepted budget.</p>
<p>Measured pre-v2 reference: {reference_seconds:.9f} seconds. Provisional target: {args.target_fraction:.0%} × reference = {target_seconds:.9f} seconds. Except for the fixed SIG override, convert each fitted coefficient using 40,000,000,000 / ({target_seconds:.9f} seconds × 1,000,000,000) ≈ {varops_per_ns:.9f} varops/ns, then round that coefficient upward to a whole varop. The reference comes from an earlier same-machine run, so these are preliminary comparisons, not consensus parameters.</p>
<p>Every nonconstant fit includes a nonnegative degree-zero term. SIG and FINAL fit a remainder against the complete measured process. DIVCORE is a bundled diagnostic, not an isolated coefficient. The old covering estimates in measurements.csv are not used here.</p>'''
    doc+=f'<p>Primitives are grouped by the work they charge. The sampling-grid column shows tested sizes, counts, and path variants; its totals count fixtures before the {len(epochs)} timing epochs. Fit points can be fewer because rounded-size aliases are combined or diagnostic fixtures are excluded.</p>'
    doc+='<nav>'+''.join(f'<a href="#category-{slug}">{html.escape(title)}</a>'
                        for slug, title, _ in PRIMITIVE_CATEGORIES)
    if composition_rows:
        doc+='<a href="#opcode-composition">Opcode composition</a>'
    doc+='</nav>'
    for slug, title, families in PRIMITIVE_CATEGORIES:
        doc+=f'<h3><a href="#category-{slug}">{html.escape(title)}</a></h3><div class="table"><table><thead><tr><th>Primitive</th><th>Varied parameters</th><th>Sampling grid</th><th>Fit / plotted</th><th>100× penalty fit (ns)</th><th>Provisional integer cost (varops)</th><th>100× fit below data</th><th>Symmetric RMS / worst</th></tr></thead><tbody>'
        doc+=''.join(table_rows[family] for family in families)+'</tbody></table></div>'
    doc+='<details><summary>Run details and source fingerprints</summary><pre>'+html.escape(json.dumps(meta,indent=2))+'</pre><p>The reference Script-evaluation time converts fitted nanoseconds to provisional varops; it is not used when fitting the timing curves.</p></details></header>'
    for slug, title, families in PRIMITIVE_CATEGORIES:
        doc+=f'<h2 class="category-title" id="category-{slug}">{html.escape(title)}</h2>'
        doc+=''.join(cards[family] for family in families)
    if composition_rows:
        rows = ''.join(
            '<tr><td><code>'+html.escape(row['opcode'])+'</code></td>'
            '<td><code>'+html.escape(row['candidate formula'].replace('SELECT(', 'OP_TX_SELECT(').replace('DECODE(', 'MACRO_DECODE('))+'</code></td>'
            '<td><code>'+html.escape(row['coefficients used'].replace('SELECT.', 'OP_TX_SELECT.').replace('DECODE', 'MACRO_DECODE'))+'</code></td>'
            '<td>'+html.escape(row['parity-test status'])+'</td></tr>'
            for row in composition_rows)
        doc += ('<section id="opcode-composition"><h2>Opcode composition</h2>'
                '<p>Current formulas exported by the compiled <code>bench_varops</code> candidate registry. '
                'They describe which primitive families each opcode charges under the provisional integer schedule.</p>'
                '<div class="table"><table><thead><tr><th>Opcode</th><th>Primitive composition</th>'
                '<th>Parameters used</th><th>Parity verification</th></tr></thead><tbody>'+rows+'</tbody></table></div></section>')
    doc+='</main></html>'
    (output_root/'primitive-fits.html').write_text(doc, encoding='utf-8')
    (output_root/'fits.json').write_text(
        json.dumps(dict(metadata=meta, fits=results), indent=2) + '\n',
        encoding='utf-8',
    )
    print(f'{output_root}/primitive-fits.html')
    for name,r in results.items():
        print(name,r['formula_ns'],f"RMS {r['weighted_rms_factor']:.3f}x")


if __name__ == '__main__':
    main()
