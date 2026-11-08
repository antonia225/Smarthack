"""Deterministic intent recognition for the offline Learning Mode answer.

Questions are matched after case folding and diacritic removal, so
"Care e scorul meu?" and "care e scorul meu" behave the same. Patterns are
short, explicit phrases in Romanian and English; nothing here is learned or
sent anywhere. The first matching intent wins, in the order of ``_INTENTS``.
"""
from __future__ import annotations

import re
import unicodedata

FIX = "fix"
SCORE = "score"
WORST = "worst"
START = "start"
PORTS = "ports"
SEVERITY = "severity"
EXPLAIN = "explain"


def normalize(text: str) -> str:
    """Lowercase, strip diacritics and punctuation, collapse whitespace."""

    folded = "".join(
        char for char in unicodedata.normalize("NFKD", text.casefold())
        if not unicodedata.combining(char)
    )
    return " ".join(re.findall(r"[^\W_]+", folded))


def _any(*patterns: str) -> re.Pattern[str]:
    return re.compile("|".join(f"(?:{pattern})" for pattern in patterns))


# Order matters: "Cum repar cea mai gravă problemă?" is a fix question, and
# "Care dispozitiv e cel mai periculos?" must not be read as "is it dangerous?".
_INTENTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (FIX, _any(
        r"\b(repar|rezolv|remedi|imbunatat|corectez|securizez|dezactivez)\w*",
        r"\bpasii\b", r"\bpasi\b", r"\bce pot face\b",
        r"\b(fix|repair|solve|resolv|remediat|mitigat|improv)\w*",
        r"\bsteps\b", r"\bturn (it |this |that )?off\b",
        r"\b(secure|protect) (it|this|that|them|my)\b",
    )),
    (SCORE, _any(r"\bscor\w*", r"\bpunctaj\w*", r"\bscor(e|es|ed|ing)\b", r"\brating\b")),
    (WORST, _any(
        r"\bcel mai (periculos|expus|vulnerabil|riscant|grav|nesigur|problematic|afectat)\b",
        r"\bcea mai (periculoasa|expusa|vulnerabila|grava|serioasa|mare problema)\b",
        r"\bcele mai (periculoase|grave|expuse)\b", r"\bcel mai mare risc\b",
        r"\bmost (dangerous|exposed|vulnerable|at risk|risky|critical|serious|urgent|affected)\b",
        r"\b(riskiest|worst)\b", r"\bbiggest (risk|problem|issue|threat)\b",
    )),
    (START, _any(
        r"\b(cu|de) ce (sa )?incep\b", r"\bde unde (sa )?incep\b",
        r"\bce (sa )?fac (mai )?(intai|intii|prima data|primul|primul lucru)\b",
        r"\bprimul pas\b", r"\bprioritat\w*", r"\bce (trebuie|ar trebui) sa fac\b", r"\bce sa fac\b",
        r"\bwhere (do|should|can) i (start|begin)\b", r"\bwhere to (start|begin)\b",
        r"\bwhat (should|do|must) i do\b", r"\bfirst step\b", r"\bprioriti\w*", r"\bpriority\b",
        r"\bstart with\b",
    )),
    (PORTS, _any(
        r"\b(ce|care) port\w*", r"\bport\w* (sunt |e |este )?deschis\w*", r"\blista porturilor\b",
        r"\b(which|what) ports?\b", r"\bopen ports?\b", r"\bports? (are |is )?open\b",
    )),
    (SEVERITY, _any(
        r"\bgrav\w*", r"\bserio\w*", r"\bpericulo\w*", r"\bingrijor\w*", r"\burgent\w*",
        r"\bseveritat\w*", r"\bris(c|cul|curi|curile)\b", r"\brisks?\b", r"\bcat de (rau|expus|sigur)\w*", r"\b(e|este|sunt) (rau|in regula|ok)\b",
        r"\b(bad|serious|dangerous|severe|severity|critical|worr(y|ied))\b",
        r"\bhow (bad|risky|safe|secure)\b",
    )),
    (EXPLAIN, _any(
        r"\bce inseamna( (asta|aceasta|acest|acestea|rezultat\w*|problem\w*|constatar\w*|finding\w*))?$",
        r"\bce inseamna (asta|aceasta|acest|acestea|rezultat\w*|problem\w*|constatar\w*|finding\w*)\b",
        r"\bce (e|este) (asta|aceasta|acest)\b", r"\bce inseamna \d+( \d+){3}\b", r"\bwhat does \d+( \d+){3} mean\b", r"\bce (a|s a) gasit\b",
        r"\bexplic\w*( mi)? (asta|aceasta|acest|rezultat\w*|problem\w*|scan\w*|ce a gasit)\b",
        r"\bwhat does (this|it|that|the scan|the result|this finding) mean\b",
        r"\bwhat do (the|these|my) (results|findings) mean\b",
        r"\bwhat is (this|that|wrong)\b", r"\bwhat did (the scan|it) find\b",
        r"\bexplain (this|it|that|the (results?|scan|problem|finding))\b",
    )),
)


def detect(question: str) -> str | None:
    """Return the first matching intent name, or ``None``."""

    text = normalize(question)
    for name, pattern in _INTENTS:
        if pattern.search(text):
            return name
    return None
