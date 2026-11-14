#!/usr/bin/env python3
"""Static call graph of the leaf (src/*.c), from the compiler.

    python3 tools/callgraph/callgraph.py            # writes reports/img/call-graph.svg, prints the table
    python3 tools/callgraph/callgraph.py --check    # exit 1 if the SVG is not up to date
    ZTL_CC=<arm-zephyr-eabi-gcc> python3 tools/callgraph/callgraph.py
                                                    # also: depth after inlining and worst stack on the target

Needs a GCC with -fcallgraph-info (GCC 10 or later) and Graphviz `dot`. No prover.
Each source file is compiled once with -fcallgraph-info; the edges are the direct calls
that the compiler sees. The script stops if it finds a call through a pointer or a
recursive cycle, because the drawing would then not show every call.
The output is written to a temporary file and renamed, so a stopped run leaves no
partial file.
"""
import collections
import glob
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OUT = os.path.join(ROOT, "reports", "img", "call-graph.svg")
DOORS = ["ztl_init", "ztl_pin", "ztl_input", "ztl_poll", "ztl_frame_to", "ztl_tx_first", "ztl_tx_second", "ztl_mac_of"]
# A function of depth 1 with at least this many callers is listed, not drawn with its edges.
HELPER_CALLERS = 5
COLOURS = {  # one colour for each source file (fill, border)
    "leaf.c": ("#e8f0fb", "#2a5caa"), "rx.c": ("#fdeee4", "#c0571c"), "wire.c": ("#fdeee4", "#c0571c"),
    "reasm.c": ("#fdeee4", "#c0571c"), "auth.c": ("#f3e9f9", "#7a3fa8"), "salsa.c": ("#f3e9f9", "#7a3fa8"),
    "poly.c": ("#f3e9f9", "#7a3fa8"), "lz4.c": ("#e9f6ec", "#2e7d43"), "dict.c": ("#e9f6ec", "#2e7d43"),
}


def graph(cc, flags):
    """Compile each src/*.c with -fcallgraph-info=su. Return (edges, home, stack): keys are the
    compiler's node titles (path:name for a static function, name otherwise); home[k] = defining
    file; stack[k] = frame size in bytes (None if the compiler gave no bound)."""
    edges, home, stack = collections.defaultdict(set), {}, {}
    with tempfile.TemporaryDirectory() as tmp:
        for src in sorted(glob.glob(os.path.join(ROOT, "src", "*.c"))):
            subprocess.run([cc, "-std=c11", *flags, "-fcallgraph-info=su", "-I" + os.path.join(ROOT, "include"),
                            "-I" + os.path.join(ROOT, "src"), "-c", src, "-o", os.devnull],
                           cwd=tmp, check=True)
        for ci in sorted(glob.glob(os.path.join(tmp, "*.ci"))):
            for line in open(ci):
                if "__indirect_call" in line:
                    sys.exit("call through a pointer found: the drawing would be incomplete")
                m = re.match(r'node: \{ title: "([^"]+)" label: "[\w.]+\\n[^"]*?([\w.]+):\d+:\d+(?:\\n(\d+) bytes \(([\w,]+)\))?', line)
                if m and m.group(3):  # a definition (a declaration has no frame size)
                    k = m.group(1) if not m.group(2).endswith(".h") else short(m.group(1))  # one node per header helper
                    home[k] = m.group(2)
                    stack[k] = int(m.group(3)) if m.group(4) in ("static", "dynamic,bounded") else None
                m = re.match(r'edge: \{ sourcename: "([^"]+)" targetname: "([^"]+)"', line)
                if m:
                    edges[m.group(1)].add(m.group(2))
    key = {short(k): k for k in home}  # header helpers and external names resolve by name
    edges = {(f if f in home else key.get(short(f), f)): {g if g in home else key.get(short(g), g) for g in gs}
             for f, gs in edges.items()}
    defined = set(home)
    edges = {f: {g for g in gs if g in defined} for f, gs in edges.items() if f in defined}
    return edges, home, stack


def short(k):
    return k.rsplit(":", 1)[-1]


def worst_stack(edges, stack, f, path=()):
    """Largest sum of frame sizes on any call path from f (bytes), and that path."""
    if f in path:
        sys.exit("recursion found: " + " -> ".join(map(short, path + (f,))))
    if stack.get(f) is None:
        sys.exit("no static stack size for " + short(f))
    best = (0, ())
    for g in edges.get(f, ()):
        best = max(best, worst_stack(edges, stack, g, path + (f,)))
    return stack[f] + best[0], (f,) + best[1]


def depth_of(edges):
    memo = {}

    def d(f, path):
        if f in path:
            sys.exit("recursion found: " + " -> ".join(path + (f,)))
        if f not in memo:
            memo[f] = 1 + max((d(g, path + (f,)) for g in edges.get(f, ())), default=0)
        return memo[f]
    return {f: d(f, ()) for f in set(edges) | {g for gs in edges.values() for g in gs}}


def reach(edges, f):
    seen, todo = set(), [f]
    while todo:
        for g in edges.get(todo.pop(), ()):
            if g not in seen:
                seen.add(g)
                todo.append(g)
    return seen


def names(home):
    """Display name of each node: the function name, with the file only when two files share it."""
    n = collections.Counter(short(k) for k in home)
    return {k: short(k) if n[short(k)] == 1 else home[k] + ":" + short(k) for k in home}


def dot_text(edges, home, depth):
    disp = names(home)
    callers = collections.Counter(g for gs in edges.values() for g in gs)
    helpers = sorted(k for k in home if depth.get(k, 1) == 1 and (callers[k] >= HELPER_CALLERS or home[k].endswith(".h")))
    drawn = sorted((k for k in home if k not in helpers), key=lambda k: disp[k])
    out = ['digraph leaf {', 'rankdir=LR; nodesep=0.12; ranksep=0.45; bgcolor="#fcfcfb";',
           'node [shape=box, style="rounded,filled", fontname="DejaVu Sans", fontsize=11, height=0.25, margin="0.06,0.02"];',
           'edge [color="#555555", arrowsize=0.5, penwidth=0.8];',
           'labelloc=t; fontname="DejaVu Sans"; fontsize=15;',
           'label="Static call graph of src/*.c, as written (direct calls only; no call through a pointer, no recursion)\\n'
           'Read from left to right: the entry points of include/ztl/leaf.h (bold) call to the right. Blue: protocol (leaf.c); '
           'orange: receive gate; violet: cryptography; green: decoders.\\nNot drawn: ' + str(len(helpers)) +
           ' small helpers called from many places (' + ", ".join(sorted({disp[k] for k in helpers})) + ')";']
    for k in drawn:
        fill, line = COLOURS.get(home[k], ("#eeeeee", "#666666"))
        extra = ', penwidth=2.4, fontsize=13, fontname="DejaVu Sans Bold"' if disp[k] in DOORS else ""
        out.append(f'"{disp[k]}" [fillcolor="{fill}", color="{line}"{extra}];')
    out.append("{rank=same; " + " ".join(f'"{d}";' for d in DOORS if d in {disp[k] for k in drawn}) + "}")
    for k in drawn:
        for g in sorted(edges.get(k, ()), key=lambda g: disp[g]):
            if g in drawn:
                out.append(f'"{disp[k]}" -> "{disp[g]}";')
    out.append("}")
    return "\n".join(out) + "\n"


def table(edges, home, stack, with_stack):
    by = {short(k): k for k in home if not home[k].endswith(".h") or short(k) not in {short(j) for j in home if j != k}}
    depth = depth_of(edges)
    rows = ["| Entry point | Call depth | Functions reached" + (" | Worst stack (bytes) | Deepest path by stack |\n|---|---|---|---|---|" if with_stack else " |\n|---|---|---|")]
    for d in DOORS:
        k = by.get(d)
        if k is None:
            continue
        r = f"| `{d}()` | {depth.get(k, 1)} | {len(reach(edges, k))}"
        if with_stack:
            b, path = worst_stack(edges, stack, k)
            r += f" | {b} | " + " → ".join(f"{short(f)} ({stack[f]})" for f in path)
        rows.append(r + " |")
    return "\n".join(rows)


def main():
    edges, home, stack = graph("gcc", ["-O0"])
    depth = depth_of(edges)
    svg = subprocess.run(["dot", "-Tsvg"], input=dot_text(edges, home, depth), capture_output=True, text=True,
                         check=True).stdout
    svg = re.sub(r"<!-- Generated by graphviz[^>]*-->\n", "", svg)  # no tool version in the file
    if "--check" in sys.argv:
        same = os.path.exists(OUT) and open(OUT).read() == svg
        print("call-graph.svg is " + ("up to date" if same else "NOT up to date"))
        sys.exit(0 if same else 1)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(OUT))
    with os.fdopen(fd, "w") as f:
        f.write(svg)
    os.replace(tmp, OUT)
    print(f"As written (host gcc -O0, no inlining): {len(home)} functions; wrote {os.path.relpath(OUT, ROOT)}\n")
    print(table(edges, home, stack, False))
    cc = os.environ.get("ZTL_CC")
    if cc:
        e2, h2, s2 = graph(cc, ["-Os", "-mcpu=cortex-m7", "-mthumb"])
        print(f"\nOn the target (ZTL_CC -Os -mcpu=cortex-m7 -mthumb, as proofs/run.sh step target; after inlining): "
              f"{len(h2)} functions remain\n")
        print(table(e2, h2, s2, True))


if __name__ == "__main__":
    main()
