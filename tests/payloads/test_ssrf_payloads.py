from app.detectors.ssrf import SSRFDetector


def test_ssrf_payloads_cover_expected_cloud_providers():
    expected_providers = {
        "aws", "gcp", "azure", "digitalocean", "alibaba", "oracle",
    }

    assert set(SSRFDetector.CLOUD_METADATA) == expected_providers

    for provider, urls in SSRFDetector.CLOUD_METADATA.items():
        assert urls, f"No metadata URLs defined for {provider}"
        assert all(url.startswith(("http://", "https://")) for url in urls)


def test_ssrf_internal_address_list_contains_private_targets():
    expected_addresses = {
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "localhost",
        "[::1]",
    }

    assert expected_addresses.issubset(set(SSRFDetector.INTERNAL_IPS))


def test_ssrf_bypasses_include_expected_ip_representations():
    detector = SSRFDetector(http_client=None)
    bypasses = detector.apply_bypasses("127.0.0.1")

    assert "2130706433" in bypasses
    assert "0x7f000001" in bypasses
    assert "[::ffff:127.0.0.1]" in bypasses
    assert "127.0.0.1.nip.io" in bypasses
    assert "localtest.me" in bypasses


def test_ssrf_bypass_results_are_unique():
    detector = SSRFDetector(http_client=None)
    bypasses = detector.apply_bypasses("127.0.0.1")

    assert len(bypasses) == len(set(bypasses))
