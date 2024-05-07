'''Setup script.'''

import os
import setuptools

import pqc.utils


with open(f'{os.path.dirname(os.path.abspath(__file__))}/requirements.txt') as requirements:
    with open(f'{os.path.dirname(os.path.abspath(__file__))}/README.md') as readme:
        setuptools.setup(
            name='pqc',
            version='0.0.0',
            description='Post quantum cryptography library for Python',
            long_description=readme.read(),
            long_description_content_type='text/markdown',
            author='Terra Quantum AG',
            author_email='info@terraquantum.swiss',
            packages=['pqc'],
            package_data={
                'pqc': [pqc.utils.library],
            },
            scripts=[],
            install_requires=requirements.read().splitlines(),
        )
