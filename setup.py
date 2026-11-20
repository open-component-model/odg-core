import os

import setuptools
import setuptools.discovery


def modules() -> list[str]:
    return setuptools.discovery.ModuleFinder.find('src')


def packages() -> list[str]:
    return [
        package
        for package in setuptools.discovery.PackageFinder.find('src')
        if package
        not in (
            'bdba',  # already part of `bdba-client`
            'delivery',  # already part of `odg-client`
            'odg_client',  # already part of `odg-client`
        )
    ]


def package_data() -> dict[str, list[str]]:
    return {
        'migrations': ['alembic.ini', 'README.md', 'script.py.mako', 'versions/*.py'],
        'features': ['*.yaml'],
        'freshclam': ['freshclam.conf'],
        'odg': ['*.yaml'],
        'osinfo': ['*.yaml'],
        'responsibles': ['*.yaml'],
        'schema': ['*.yaml'],
        'secret_mgmt': ['*.yaml'],
        'sla_violation_profiler_extension': ['templates/*.mako'],
        'swagger': ['*.yaml'],
    }


setuptools.setup(
    version=os.environ.get('ODG_CORE_LIBS_VERSION', '0.1.0'),
    package_dir={'': 'src'},
    py_modules=modules(),
    packages=packages(),
    package_data=package_data(),
)
