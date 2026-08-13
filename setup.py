import os

import semver
import setuptools
import setuptools.discovery


own_dir = os.path.abspath(os.path.dirname(__file__))


def finalize_version() -> str:
    with open(os.path.join(own_dir, 'VERSION')) as f:
        return semver.finalize_version(f.read().strip())


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
        'features': ['*.yaml'],
        'freshclam': ['freshclam.conf'],
        'odg': ['*.yaml'],
        'osinfo': ['*.yaml'],
        'responsibles': ['*.yaml'],
        'schema': ['*.yaml'],
        'secret_mgmt': ['*.yaml'],
        'swagger': ['*.yaml'],
    }


setuptools.setup(
    version=os.environ.get('ODG_CORE_LIBS_VERSION', finalize_version()),
    package_dir={'': 'src'},
    py_modules=modules(),
    packages=packages(),
    package_data=package_data(),
)
