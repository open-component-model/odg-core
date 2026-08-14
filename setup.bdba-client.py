import os
import tomllib

import semver
import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def requirements():
    with open(os.path.join(own_dir, 'packages', 'bdba-client', 'pyproject.toml'), 'rb') as f:
        return tomllib.load(f)['project']['dependencies']


def bump_version():
    with open(os.path.join(own_dir, 'BDBA_CLIENT_VERSION')) as f:
        return semver.Version.parse(f.read().strip()).bump_minor()


setuptools.setup(
    name='bdba-client',
    version=str(bump_version()),
    package_dir={'': '.'},
    py_modules=[],
    packages=['bdba'],
    install_requires=requirements(),
)
