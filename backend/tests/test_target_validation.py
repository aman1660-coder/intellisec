import pytest

from app.utils.target_validator import TargetValidationError, validate_target


def test_blocks_loopback_ip():
    with pytest.raises(TargetValidationError):
        validate_target("http://127.0.0.1:8000")


def test_blocks_metadata_endpoint():
    with pytest.raises(TargetValidationError):
        validate_target("http://169.254.169.254/latest/meta-data")


def test_accepts_public_ip_and_normalizes_scheme():
    target = validate_target("https://93.184.216.34")
    assert target.scheme == "https"
    assert target.port == 443
    assert target.resolved_ips == ["93.184.216.34"]

