import os
import tomllib

import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def read_pyproject():
    with open(os.path.join(own_dir, 'packages', 'bdba-client', 'pyproject.toml'), 'rb') as f:
        return tomllib.load(f)


setuptools.setup(
    name='bdba-client',
    version=read_pyproject()['project']['version'],
    package_dir={'': '.'},
    python_requires='>=3.14',
    py_modules=[],
    packages=['bdba'],
    install_requires=read_pyproject()['project']['dependencies'],
)
