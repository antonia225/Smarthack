import importlib.util
from pathlib import Path
from unittest.mock import patch

from netcheck.nmap_ports import port_specification


WRAPPER_PATH = Path(__file__).parents[1] / "scripts" / "macos" / "netcheck-nmap-wrapper.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("netcheck_wrapper", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_wrapper_resolves_allowed_directory_symlink(tmp_path):
    wrapper = load_wrapper()
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    wrapper.ALLOWED_DIR = link_dir
    output = link_dir / ("a" * 32 + ".xml")

    with patch.object(wrapper.os, "execv") as execv:
        assert wrapper.main(["wrapper", "172.20.10.0/28", str(output)]) == 1
    execv.assert_called_once()


def test_wrapper_rejects_non_rfc1918_target(tmp_path):
    wrapper = load_wrapper()
    wrapper.ALLOWED_DIR = tmp_path
    output = tmp_path / ("a" * 32 + ".xml")
    with patch.object(wrapper.os, "execv") as execv:
        assert wrapper.main(["wrapper", "8.8.8.8", str(output)]) == 2
    execv.assert_not_called()


def test_wrapper_uses_generated_nmap_services_specification(tmp_path):
    database = tmp_path / "nmap-services"
    database.write_text(
        "".join(f"s{i} {i}/tcp 0.5\n" for i in range(1, 1000))
        + "a 5000/tcp 0.1\nb 5001/tcp 0.1\nc 5002/tcp 0.1\n"
        + "d 6000/tcp 0.01\n",
        encoding="utf-8",
    )
    expected = port_specification(database)
    wrapper = load_wrapper()
    wrapper.ALLOWED_DIR = tmp_path
    wrapper.PORT_SPECIFICATION = expected
    output = tmp_path / ("b" * 32 + ".xml")
    with patch.object(wrapper.os, "execv") as execv:
        assert wrapper.main(["wrapper", "172.20.10.0/28", str(output)]) == 1
    assert execv.call_args.args[1][execv.call_args.args[1].index("-p") + 1] == expected
