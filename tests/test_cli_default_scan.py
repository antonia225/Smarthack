import json
from pathlib import Path
from unittest.mock import patch

from netcheck.cli import main
from netcheck.scanner import NetworkInfo, ScanResult


def test_scan_without_target_uses_persisted_subnet(tmp_path):
    config = tmp_path / "network.json"
    network = NetworkInfo("en0", "172.20.10.2", 28, "172.20.10.0/28", "172.20.10.1")
    config.write_text(json.dumps({
        "network": network.__dict__,
        "allowed_networks": [network.subnet],
    }))
    with patch("netcheck.service.scan") as scan:
        scan.return_value = ScanResult(str(tmp_path / "scan.xml"), True)
        assert main(["--config", str(config), "scan", "--confirm"]) == 0
    scan.assert_called_once_with(
        network.subnet, confirm=True, config_path=config, output_dir=None
    )
