import os
import tomllib

import semver
import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'packages', 'odg-client', 'pyproject.toml'), 'rb') as f:
        return tomllib.load(f)['project']['dependencies']


def bump_version():
    with open(os.path.join(own_dir, 'ODG_CLIENT_VERSION')) as f:
        return semver.Version.parse(f.read().strip()).bump_minor()


setuptools.setup(
    name='odg-client',
    version=str(bump_version()),
    description='Client library for the Open Delivery Gear',
    python_requires='>=3.12',
    package_dir={'': '.'},
    py_modules=[],
    packages=[
        'delivery',
        'odg_client',
    ],
    install_requires=requirements(),
)
