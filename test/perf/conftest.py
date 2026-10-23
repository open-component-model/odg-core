import pathlib
import sys
import os

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(_root, 'src'))
sys.path.insert(0, os.path.join(_root, 'test', 'perf'))


def pytest_addoption(parser):
    parser.addoption(
        '--keep-containers',
        action='store_true',
        default=False,
        help='Skip container teardown after tests (for manual debugging via docker exec)',
    )


def pytest_configure(config):
    """Wipe all results/ dirs under test/perf/<suite>/ before each run."""
    perf_root = pathlib.Path(__file__).parent
    for results_dir in perf_root.rglob('results'):
        if results_dir.is_dir():
            for log_file in results_dir.glob('*.log'):
                log_file.unlink()
