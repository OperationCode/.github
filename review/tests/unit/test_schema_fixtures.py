import pytest

from oc_review.envelope import EnvelopeError, validate_envelope, validate_findings

from .conftest import fixture_names, load_fixture


@pytest.mark.parametrize("name", fixture_names("findings", "good"))
def test_findings_good(name):
    validate_findings(load_fixture("findings", name))


@pytest.mark.parametrize("name", fixture_names("findings", "bad"))
def test_findings_bad(name):
    with pytest.raises(EnvelopeError):
        validate_findings(load_fixture("findings", name))


@pytest.mark.parametrize("name", fixture_names("envelope", "good"))
def test_envelope_good(name):
    validate_envelope(load_fixture("envelope", name))


@pytest.mark.parametrize("name", fixture_names("envelope", "bad"))
def test_envelope_bad(name):
    with pytest.raises(EnvelopeError):
        validate_envelope(load_fixture("envelope", name))


def test_fixture_sets_not_empty():
    for kind in ("findings", "envelope"):
        assert fixture_names(kind, "good") and fixture_names(kind, "bad")
