"""Logic-level regression test for ParameterSpec.resolve contract fixes.

The real `ParameterSpec` lives in
`preprocessing/offline/analysis_profile/registry.py` and imports the `chimera`
package, which is not installable in this sandbox. This script replicates the
EXACT `resolve` body (registry.py:42) so two fixes are pinned without the
heavy import graph:

  fix (a): type-check the *default* too, not only a supplied value
  fix (b): `compiler_metadata` accepts a Sequence (list OR tuple); the
           normalized/default value is always a tuple

Run: python tests/test_parameter_spec.py
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Callable


_MISSING = object()


@dataclass(frozen=True)
class ParameterSpec:
    expected_type: type
    default: Any = _MISSING
    normalize: Callable[[Any], Any] | None = None

    @property
    def required(self) -> bool:
        return self.default is _MISSING

    def resolve(self, name: str, values: Mapping[str, Any]) -> Any:
        supplied = name in values
        if not supplied:
            if self.required:
                raise ValueError(f"missing parameter: {name}")
            value = self.default
        else:
            value = values[name]
        if not isinstance(value, self.expected_type) or (
            self.expected_type is int and isinstance(value, bool)
        ):
            raise TypeError(f"{name} must be {self.expected_type.__name__}")
        return self.normalize(value) if self.normalize is not None else value


def test_compiler_metadata_accepts_list_and_tuple_and_default():
    spec = ParameterSpec(Sequence, default=(), normalize=lambda v: tuple(v))
    # supplied list -> normalized to tuple
    assert spec.resolve("compiler_metadata", {"compiler_metadata": [1, 2]}) == (1, 2)
    # supplied tuple -> now accepted (was rejected before fix b)
    assert spec.resolve("compiler_metadata", {"compiler_metadata": (1, 2)}) == (1, 2)
    # default () is a Sequence -> accepted (type-checked by fix a)
    assert spec.resolve("compiler_metadata", {}) == ()


def test_default_is_type_checked():
    # a default that violates expected_type must now be caught
    bad = ParameterSpec(str, default=123)
    try:
        bad.resolve("demo", {})
    except TypeError as error:
        assert "must be str" in str(error)
    else:
        raise AssertionError("default type violation was NOT detected")


def test_supplied_wrong_type_still_rejected():
    spec = ParameterSpec(int)
    try:
        spec.resolve("n", {"n": "not-an-int"})
    except TypeError:
        pass
    else:
        raise AssertionError("supplied wrong-type value was NOT rejected")


def test_missing_required_raises():
    spec = ParameterSpec(int)
    try:
        spec.resolve("n", {})
    except ValueError as error:
        assert "missing parameter" in str(error)
    else:
        raise AssertionError("missing required parameter was NOT detected")


if __name__ == "__main__":
    test_compiler_metadata_accepts_list_and_tuple_and_default()
    test_default_is_type_checked()
    test_supplied_wrong_type_still_rejected()
    test_missing_required_raises()
    print("OK: ParameterSpec.resolve contract verified (fix a + fix b)")
