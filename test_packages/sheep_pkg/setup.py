from setuptools import setup
from pathlib import Path

wolf_uri = (Path(__file__).parent.parent / "wolf_pkg").resolve().as_uri()

setup(
    name='sheep-pkg',
    version='0.1.0',
    packages=['sheep_pkg'],
    install_requires=[
        f'wolf-pkg @ {wolf_uri}',
    ],
)