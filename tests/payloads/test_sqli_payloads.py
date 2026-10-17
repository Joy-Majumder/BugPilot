from app.detectors.sqli import SQLIDetector
from app.detectors.base import Validator


def test_boolean_sqli_payloads_are_true_false_pairs():
    payloads = SQLIDetector.GENERIC_PAYLOADS["boolean"]

    assert payloads

    for pair in payloads:
        assert isinstance(pair, tuple)
        assert len(pair) == 2
        true_payload, false_payload = pair
        assert isinstance(true_payload, str) and true_payload
        assert isinstance(false_payload, str) and false_payload
        assert true_payload != false_payload


def test_time_sqli_payloads_have_positive_expected_delays():
    payloads = SQLIDetector.GENERIC_PAYLOADS["time"]

    assert payloads

    for payload, expected_delay in payloads:
        assert isinstance(payload, str) and payload
        assert isinstance(expected_delay, (int, float))
        assert expected_delay > 0


def test_boolean_sqli_validator_confirms_expected_response_difference():
    control = {"body": "A" * 100}
    true_response = {"body": "A" * 99}
    false_response = {"body": "B" * 50}

    result = Validator.boolean_based_sqli(
        control, true_response, false_response
    )

    assert result.confirmed is True


def test_boolean_sqli_validator_rejects_missing_response_difference():
    control = {"body": "A" * 100}
    true_response = {"body": "B" * 50}
    false_response = {"body": "C" * 49}

    result = Validator.boolean_based_sqli(
        control, true_response, false_response
    )

    assert result.confirmed is False


def test_time_sqli_validator_confirms_sufficient_delay():
    result = Validator.timing_based_sqli(
        control_time=1.0,
        sleep_time=4.0,
        threshold=2.0,
    )

    assert result.confirmed is True
    assert result.evidence["delta"] == 3.0


def test_time_sqli_validator_rejects_insufficient_delay():
    result = Validator.timing_based_sqli(
        control_time=1.0,
        sleep_time=2.0,
        threshold=2.0,
    )

    assert result.confirmed is False
