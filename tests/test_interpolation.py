"""Tests for ${ENV} interpolation in matrix files."""
import pytest

from overstep.interpolation import InterpolationError, interpolate
from overstep.matrix import load_matrix


def test_basic_substitution():
    out = interpolate({"token": "${TOK}"}, {"TOK": "secret"})
    assert out["token"] == "secret"


def test_default_value_when_missing():
    out = interpolate({"url": "${HOST:-http://localhost}"}, {})
    assert out["url"] == "http://localhost"


def test_missing_without_default_raises_listing_the_var():
    with pytest.raises(InterpolationError) as err:
        interpolate({"a": "${MISSING_ONE}", "b": "${MISSING_TWO}"}, {})
    assert "MISSING_ONE" in str(err.value) and "MISSING_TWO" in str(err.value)


def test_recurses_dicts_and_lists():
    data = {"subjects": [{"token": "${T}"}], "nested": {"k": "${T}"}}
    out = interpolate(data, {"T": "x"})
    assert out["subjects"][0]["token"] == "x"
    assert out["nested"]["k"] == "x"


def test_leaves_subject_placeholders_untouched():
    # {{...}} is the per-subject auth syntax, not env interpolation.
    out = interpolate({"user": "{{U}}"}, {"U": "should-not-be-used"})
    assert out["user"] == "{{U}}"


def test_non_strings_pass_through():
    out = interpolate({"n": 5, "b": True, "z": None}, {})
    assert out == {"n": 5, "b": True, "z": None}


def test_load_matrix_interpolates_from_env(tmp_path):
    f = tmp_path / "m.yaml"
    f.write_text(
        "base_url: ${BASE}\n"
        "subjects:\n"
        "  - name: alice\n"
        "    role: user\n"
        "    token: ${ALICE_TOKEN}\n"
        "resources: []\n"
    )
    matrix = load_matrix(str(f), env={"BASE": "http://x", "ALICE_TOKEN": "jwt-123"})
    assert matrix.base_url == "http://x"
    assert matrix.subjects[0].token == "jwt-123"
