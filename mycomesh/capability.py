"""Capability probes: tasks a tier's model answers reliably and a cheaper substitute does not.

Every Provider in a tier is paid the same network price, so serving a smaller
model than the one advertised is pure margin. Basic probes (short products,
reversing a word) catch a Provider that does not answer at all; any modern
small model passes them. These tasks need several careful steps: tracing a
loop, the Chinese remainder theorem, long multiplication, a shortest path, an
order statistic, counting letters across a paragraph, a far-off weekday. The
answers are checked exactly and every task is rebuilt from its parameters, so
anyone can re-grade a published verdict (mirrored in the Node Consumer).

A single miss proves nothing; the pass rate over many probes does. A Provider
is flagged only when the upper confidence bound of its pass rate falls below
its tier's floor (see ``flagged``).
"""
from __future__ import annotations

import datetime
import math
import re
import secrets
from dataclasses import dataclass

_random = secrets.SystemRandom()

KINDS = ("trace", "crt", "long_multiply", "path", "kth", "letters", "calendar")
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
PRIMES = (11, 13, 17, 19, 23, 29, 31, 37)
VOCABULARY = ("strawberry", "bookkeeper", "mississippi", "committee", "assessment", "balloon", "coffee", "parallel",
              "raspberry", "tennessee", "possession", "barrel", "occurrence", "accommodate", "embarrass", "success",
              "address", "letter", "banana", "cinnamon", "referral", "millennium", "harass", "necessary")
NODES = "ABCDEFGHI"


def numbers(text: str) -> list[str]:
    """Integers in a text, accepting 1,234,567 and 1 234 567 groupings."""
    return [re.sub(r"[,\s_]", "", match) for match in re.findall(r"[0-9]{1,3}(?:[,\s_][0-9]{3})+(?![0-9])|[0-9]+", text)]


def ordinal(n: int) -> str:
    suffix = "th" if 10 <= n % 100 <= 20 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _last_line(text: str) -> str:
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-1] if lines else ""


@dataclass(frozen=True)
class CapabilityTask:
    kind: str
    params: dict
    question: str
    reference: str

    def grade(self, answer: str) -> str:
        """pass | wrong. The last line that states an answer decides (a model may show its work or change its
        mind); a handful of values at most, since listing candidates is not answering. Never "unrelated":
        missing a hard task lowers a pass rate, it is not grounds for a dispute."""
        text = answer.strip()
        if self.kind == "calendar":
            pick = lambda part: [day for day in WEEKDAYS if day.lower() in part.lower()]  # noqa: E731
        else:
            pick = numbers
        final = pick(_last_line(text))
        stated = final if final else pick(text)
        return "pass" if len(stated) <= (1 if self.kind == "calendar" else 3) and self.reference in stated else "wrong"


def _trace(p: dict) -> tuple[str, str]:
    x, y, a, m, n = (int(p[k]) for k in ("x", "y", "a", "m", "n"))
    question = (f"Start with x = {x} and y = {y}. Repeat the following {n} times: first set x to (x * {a} + y) mod {m}, "
                f"then set y to (y + 2 * x) mod {m}. What is x + y at the end?")
    for _ in range(n):
        x = (x * a + y) % m
        y = (y + 2 * x) % m
    return question, str(x + y)


def _crt(p: dict) -> tuple[str, str]:
    moduli, residues = [int(v) for v in p["moduli"]], [int(v) for v in p["residues"]]
    parts = [f"remainder {r} when divided by {m}" for m, r in zip(moduli, residues)]
    question = f"What is the smallest positive integer that leaves {', '.join(parts[:-1])}, and {parts[-1]}?"
    product = math.prod(moduli)
    answer = next(x for x in range(1, product + 1) if all(x % m == r for m, r in zip(moduli, residues)))
    return question, str(answer)


def _long_multiply(p: dict) -> tuple[str, str]:
    a, b = int(p["a"]), int(p["b"])
    return f"What is {a} times {b}?", str(a * b)


def _path(p: dict) -> tuple[str, str]:
    edges = [(str(u), str(v), int(w)) for u, v, w in p["edges"]]
    start, end = str(p["start"]), str(p["end"])
    roads = ", ".join(f"{u}-{v} {w}" for u, v, w in edges)
    question = (f"In a road network the two-way roads and their lengths are: {roads}. "
                f"What is the length of the shortest route from {start} to {end}?")
    distance = {start: 0}
    done: set[str] = set()
    while True:
        open_nodes = [(d, node) for node, d in distance.items() if node not in done]
        if not open_nodes:
            break
        d, node = min(open_nodes)
        done.add(node)
        for u, v, w in edges:
            for here, there in ((u, v), (v, u)):
                if here == node and d + w < distance.get(there, math.inf):
                    distance[there] = d + w
    return question, str(distance[end])


def _kth(p: dict) -> tuple[str, str]:
    values, k = [int(v) for v in p["values"]], int(p["k"])
    question = f"What is the {ordinal(k)} smallest number in this list: {', '.join(map(str, values))}?"
    return question, str(sorted(values)[k - 1])


def _letters(p: dict) -> tuple[str, str]:
    text, letter = str(p["text"]), str(p["letter"])
    return f'How many times does the letter "{letter}" appear in the following text: "{text}"?', str(text.count(letter))


def _calendar(p: dict) -> tuple[str, str]:
    start, offset = datetime.date.fromisoformat(str(p["start"])), int(p["offset"])
    answer = WEEKDAYS[(start + datetime.timedelta(days=offset)).weekday()]
    return f"What day of the week will it be {offset} days after {start.isoformat()}?", answer


BUILDERS = {"trace": _trace, "crt": _crt, "long_multiply": _long_multiply, "path": _path, "kth": _kth,
            "letters": _letters, "calendar": _calendar}


def build_capability_task(kind: str, params: dict) -> CapabilityTask:
    question, reference = BUILDERS[kind](params)
    return CapabilityTask(kind, params, question, reference)


# ---------------- generators ----------------

def _graph() -> dict:
    """Nine towns, a random chain through all of them plus shortcuts; never a direct start-end road."""
    order = list(NODES)
    _random.shuffle(order)
    start, end = order[0], order[-1]
    pairs = {tuple(sorted(pair)) for pair in zip(order, order[1:])}
    while len(pairs) < 16:
        u, v = sorted(_random.sample(NODES, 2))
        if {u, v} != {start, end}:
            pairs.add((u, v))
    edges = [[u, v, _random.randint(2, 19)] for u, v in sorted(pairs)]
    _random.shuffle(edges)
    return {"edges": edges, "start": start, "end": end}


GENERATORS = {
    "trace": lambda: {"x": _random.randint(2, 90), "y": _random.randint(2, 90), "a": _random.randint(3, 9),
                      "m": _random.choice((97, 101, 103, 107, 109, 113)), "n": _random.randint(12, 16)},
    "crt": lambda: (lambda moduli: {"moduli": moduli, "residues": [_random.randint(1, m - 1) for m in moduli]})(
        sorted(_random.sample(PRIMES, 4))),
    "long_multiply": lambda: {"a": _random.randint(10_000_000, 99_999_999), "b": _random.randint(1_000_000, 9_999_999)},
    "path": _graph,
    "kth": lambda: {"values": _random.sample(range(100, 1000), 25), "k": _random.randint(6, 12)},
    "letters": lambda: {"text": " ".join(_random.choice(VOCABULARY) for _ in range(18)),
                        "letter": _random.choice("rsenc")},
    "calendar": lambda: {"start": (datetime.date(1990, 1, 1) + datetime.timedelta(days=_random.randint(0, 12_000))).isoformat(),
                         "offset": _random.randint(5_000, 40_000)},
}


def random_task(kind: str | None = None) -> CapabilityTask:
    kind = kind or _random.choice(KINDS)
    return build_capability_task(kind, GENERATORS[kind]())


# ---------------- scoring ----------------

# The pass rate below which a tier's Provider is flagged (see ``flagged``), from
# docs/release-evidence/capability-calibration.json: the honest models pass far more often, the
# small substitutes far less. A network manifest's tier ``capability_floor`` overrides these.
FLOORS = {1: 0.6, 2: 0.6}

def wilson_upper(passes: int, total: int, z: float = 2.326) -> float:
    """Upper bound of the pass rate at 99% one-sided confidence."""
    if total == 0:
        return 1.0
    p = passes / total
    centre = p + z * z / (2 * total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    return min(1.0, (centre + spread) / (1 + z * z / total))


def flagged(passes: int, total: int, floor: float, *, minimum: int = 10) -> bool:
    """True once the evidence says, with 99% confidence, that the pass rate is below the tier's floor."""
    return total >= minimum and wilson_upper(passes, total) < floor
