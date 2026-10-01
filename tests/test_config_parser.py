"""
Unit Tests – Config Parser
============================
Tests for the FortiGate configuration parser module.
"""

import pytest
import os
import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cis_benchmark.config_parser import FortiGateConfigParser, FortiGateConfig


@pytest.fixture
def parser():
    return FortiGateConfigParser()


@pytest.fixture
def sample_config_path():
    return str(Path(__file__).parent / "test_sample_config.conf")


@pytest.fixture
def sample_config(parser, sample_config_path):
    return parser.parse_file(sample_config_path)


class TestConfigParser:
    """Test config file parsing."""

    def test_parse_file_exists(self, parser, sample_config_path):
        config = parser.parse_file(sample_config_path)
        assert isinstance(config, FortiGateConfig)

    def test_parse_file_not_found(self, parser):
        with pytest.raises(FileNotFoundError):
            parser.parse_file("nonexistent.conf")

    def test_version_detection(self, sample_config):
        assert sample_config.model == "FG200F"
        assert sample_config.version == "7.2.8"
        assert sample_config.build == "1639"

    def test_hostname_extraction(self, sample_config):
        assert sample_config.hostname == "FG-CIS-TEST"

    def test_global_settings(self, sample_config):
        assert sample_config.get_global_setting("strong-crypto") == "enable"
        assert sample_config.get_global_setting("admintimeout") == "10"
        assert sample_config.get_global_setting("intra-zone-deny") == "enable"

    def test_global_setting_default(self, sample_config):
        assert sample_config.get_global_setting("nonexistent", "default") == "default"

    def test_has_global_setting(self, sample_config):
        assert sample_config.has_global_setting("hostname")
        assert not sample_config.has_global_setting("nonexistent")

    def test_interface_blocks(self, sample_config):
        interfaces = sample_config.get_interface_blocks()
        assert len(interfaces) > 0

    def test_policy_blocks(self, sample_config):
        policies = sample_config.get_policy_blocks()
        assert len(policies) > 0

    def test_admin_blocks(self, sample_config):
        admins = sample_config.get_admin_blocks()
        assert len(admins) > 0

    def test_search_pattern(self, sample_config):
        assert sample_config.search(r'config system global')
        assert not sample_config.search(r'nonexistent_pattern_xyz')

    def test_search_value(self, sample_config):
        val = sample_config.search_value(r'set hostname\s+"?([^"\n]+)"?')
        assert val is not None
        assert "FG-CIS-TEST" in val

    def test_get_blocks(self, sample_config):
        dns = sample_config.get_blocks("system dns")
        assert len(dns) > 0

    def test_get_block_single(self, sample_config):
        block = sample_config.get_block("system dns")
        assert block is not None

    def test_validate_config_valid(self, parser, sample_config_path):
        content = Path(sample_config_path).read_text()
        assert parser.validate_config(content)

    def test_validate_config_invalid(self, parser):
        assert not parser.validate_config("this is not a fortigate config")

    def test_parse_content_direct(self, parser):
        content = """
config system global
    set hostname "TEST"
    set timezone 5
end
"""
        config = parser.parse_content(content)
        assert config.hostname == "TEST"
        assert config.get_global_setting("timezone") == "5"

    def test_nested_blocks(self, sample_config):
        ha = sample_config.get_block("system ha")
        assert ha is not None
        assert ha.get("mode") == "a-p"

    def test_empty_content(self, parser):
        config = parser.parse_content("")
        assert config.hostname == ""


class TestConfigSecurity:
    """Test security features of the parser."""

    def test_null_byte_removal(self, parser):
        content = "config system global\x00\n    set hostname \"test\"\nend\n"
        config = parser.parse_content(content)
        assert '\x00' not in config.raw_content

    def test_empty_file_error(self, parser, tmp_path):
        empty_file = tmp_path / "empty.conf"
        empty_file.write_text("")
        with pytest.raises(ValueError, match="empty"):
            parser.parse_file(str(empty_file))
