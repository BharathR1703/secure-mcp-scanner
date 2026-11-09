"""The context-gated detection engine shared by the PHI and PCI rules.

Presidio's ``PatternRecognizer`` matches the whole regex hit, so a rule
for ``MRN: 4471`` would report the span ``MRN: 4471`` rather than the
number itself. The rules here use exactly one capture group and report
only that group's span.

A rule is *context-gated*: the value only counts when the text around it
-- or the column and relation it was found in -- carries a word that
places it in the right domain. That is what separates ``diagnosis:
carcinoma of the lung`` (a diagnosis) from ``Cancer Research Institute,
Bengaluru`` (an organisation name).

Two things follow from the design:

* The window checked is 48 characters before the match and 24 after it.
* A match with context scores 0.85; a match without context scores 0.05,
  which the global score threshold discards. The low-scoring finding is
  still emitted so that the behaviour is visible in the overlap resolver
  rather than being a special case buried in a rule.

The engine has no dependency on Presidio or spaCy. Presidio is the
scanner's main detector, but it can be unavailable -- and when it is, the
scanner falls back to a regex-only mode. Cardholder data must not become
invisible in that mode, so the domain rules run in both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

CONTEXT_WINDOW_BEFORE = 48
CONTEXT_WINDOW_AFTER = 24

#: Score for a match whose surrounding context supports the rule.
CONTEXT_SCORE = 0.85

#: Score for a match whose context does not support the rule. Below the
#: scanner's minimum score, so it is discarded.
NO_CONTEXT_SCORE = 0.05

#: Signature of a value guard: ``(value, whole_text) -> bool``. Returning
#: False drops the match. Used to require, say, that a medical record
#: number contain a digit.
ValueValidator = Callable[[str, str], bool]

_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9]+")


def tokenize(text: str) -> Set[str]:
    """Split ``text`` into lowercase alphanumeric tokens.

    Both separators and camelCase boundaries split, so ``cardNumber``,
    ``card_number`` and ``card-number`` all yield ``{"card", "number"}``.
    """
    if not text:
        return set()
    spaced = _CAMEL_BOUNDARY_RE.sub(" ", text)
    return {token for token in _NON_ALNUM_RE.split(spaced.lower()) if token}


def _contains_phrase(haystack: str, phrase: str) -> bool:
    """Return True if ``phrase`` appears in ``haystack`` on word boundaries."""
    if not phrase:
        return False
    pattern = r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])"
    return re.search(pattern, haystack) is not None


@dataclass(frozen=True)
class Rule:
    """One detection rule.

    ``pattern`` must contain exactly one capture group; that group's span
    is what gets reported.
    """

    entity_type: str
    pattern: re.Pattern
    context_words: Tuple[str, ...] = ()
    score: float = CONTEXT_SCORE
    requires_context: bool = True
    value_validator: Optional[ValueValidator] = None
    label: str = ""

    def __post_init__(self) -> None:
        if self.pattern.groups != 1:
            raise ValueError(
                f"rule '{self.label or self.entity_type}' must use exactly one "
                f"capture group, found {self.pattern.groups}"
            )


class ContextGatedRecognizer:
    """Applies a set of :class:`Rule` objects to a piece of text."""

    def __init__(
        self,
        entity_type: str,
        rules: Sequence[Rule],
        context_words: Sequence[str] = (),
        score: float = CONTEXT_SCORE,
        name: Optional[str] = None,
    ) -> None:
        self.entity_type = entity_type
        self.rules = list(rules)
        self.context_words = tuple(word.lower() for word in context_words)
        self.score = score
        self.name = name or entity_type

    def analyze(
        self, text: str, extra_context: str = ""
    ) -> List[Dict[str, object]]:
        """Return the findings for ``text``.

        ``extra_context`` is free text supplied by the caller -- normally
        the column name and the relation name the value was found in. Its
        tokens satisfy the context gate exactly like words in the text
        itself, which is how a cell that reads only ``Type 2 Diabetes
        Mellitus`` is still recognised as a diagnosis because it sits in a
        column called ``diagnosis``.
        """
        if not isinstance(text, str) or not text:
            return []

        context_tokens = tokenize(extra_context)
        findings: List[Dict[str, object]] = []

        for rule in self.rules:
            for match in rule.pattern.finditer(text):
                start, end = match.span(1)
                if start < 0 or end <= start:
                    continue
                value = text[start:end]
                if rule.value_validator is not None:
                    try:
                        if not rule.value_validator(value, text):
                            continue
                    except Exception:
                        continue

                score = rule.score
                if rule.requires_context:
                    if not self._is_contexted(
                        text, start, end, rule.context_words, context_tokens
                    ):
                        score = NO_CONTEXT_SCORE

                findings.append(
                    {
                        "type": rule.entity_type,
                        "value": value,
                        "start": start,
                        "end": end,
                        "score": score,
                    }
                )
        return findings

    def _is_contexted(
        self,
        text: str,
        start: int,
        end: int,
        rule_context_words: Sequence[str],
        context_tokens: Set[str],
    ) -> bool:
        window = text[
            max(0, start - CONTEXT_WINDOW_BEFORE) : end + CONTEXT_WINDOW_AFTER
        ].lower()
        for word in tuple(self.context_words) + tuple(rule_context_words):
            if not word:
                continue
            if _contains_phrase(window, word):
                return True
            if tokenize(word) and tokenize(word) <= context_tokens:
                return True
        return False


def whole_value_is_valid(value: str, text: str) -> bool:
    """Guard for rules that only make sense on a cell's entire content.

    A bare three-digit number is not a card verification value, but a
    cell whose entire content is ``123`` in a column called ``cvv`` is.
    """
    return value.strip() == text.strip()
