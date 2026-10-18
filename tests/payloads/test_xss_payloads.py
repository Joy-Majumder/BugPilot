from app.detectors.xss import ReflectedXSSDetector


def test_xss_payloads_cover_all_expected_contexts():
    expected_contexts = {"html", "attribute", "javascript", "url"}

    assert set(ReflectedXSSDetector.CONTEXT_PAYLOADS) == expected_contexts

    for context, techniques in ReflectedXSSDetector.CONTEXT_PAYLOADS.items():
        assert "basic" in techniques
        assert techniques["basic"]
        assert "filter_bypass" in techniques
        assert techniques["filter_bypass"]

        if context != "url":
            assert "encoding" in techniques
            assert techniques["encoding"]


def test_xss_payloads_include_execution_marker():
    for techniques in ReflectedXSSDetector.CONTEXT_PAYLOADS.values():
        for payloads in techniques.values():
            assert any("xssPoC12345" in payload for payload in payloads)


def test_unknown_xss_context_falls_back_to_html():
    detector = ReflectedXSSDetector(http_client=None)

    assert detector._get_payloads_for_context("unknown") == (
        ReflectedXSSDetector.CONTEXT_PAYLOADS["html"]
    )
