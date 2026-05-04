from setuptools import setup, find_packages

setup(
    name='supply-chain-guard',
    version='0.1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'supply-chain-guard-install=supply_chain_guard:install',
        ],
    },
    python_requires='>=3.6',
)