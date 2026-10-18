from app.detectors.other import SSTIDetector
from app.detectors.base import Validator


def test_ssti_payloads_cover_expected_template_engines():
    expected_engines = {
        "jinja2", "twig", "freemarker", "velocity",
        "smarty", "erb", "thymeleaf", "express",
    }

    assert set(SSTIDetector.PAYLOADS) == expected_engines

    for engine, payloads in SSTIDetector.PAYLOADS.items():
        assert payloads, f"No SSTI payloads defined for {engine}"
        assert any("7*7" in payload for payload in payloads)


def test_generic_ssti_payloads_include_multiple_expression_syntaxes():
    payloads = SSTIDetector.GENERIC_PAYLOADS

    assert "{{7*7}}" in payloads
    assert "${7*7}" in payloads
    assert "<%= 7*7 %>" in payloads
    assert "#{7*7}" in payloads
    assert "{7*7}" in payloads


def test_ssti_validation_confirms_evaluated_expression():
    result = Validator.ssti_evaluated("The result is 49", "49")

    assert result.confirmed is True
    assert result.evidence["expected"] == "49"


def test_ssti_validation_rejects_unevaluated_expression():
    result = Validator.ssti_evaluated("The result is {{7*7}}", "49")

    assert result.confirmed is False
