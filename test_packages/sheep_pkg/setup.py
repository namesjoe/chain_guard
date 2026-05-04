from setuptools import setup

setup(
    name='sheep-pkg',
    version='0.1.0',
    packages=['sheep_pkg'],
    install_requires=[
        'wolf-pkg @ file:///Users/sedovda/repos/chain_guard/test_packages/wolf_pkg',
    ],
)