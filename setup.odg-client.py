import os
import tomllib

import setuptools


own_dir = os.path.abspath(os.path.dirname(__file__))


def read_pyproject():
    with open(os.path.join(own_dir, 'packages', 'odg-client', 'pyproject.toml'), 'rb') as f:
        return tomllib.load(f)


setuptools.setup(
    name='odg-client',
    version=read_pyproject()['project']['version'],
    description='Client library for the Open Delivery Gear',
    python_requires='>=3.14',
    package_dir={'': '.'},
    py_modules=[],
    packages=[
        'delivery',
        'odg_client',
    ],
    install_requires=read_pyproject()['project']['dependencies'],
)
