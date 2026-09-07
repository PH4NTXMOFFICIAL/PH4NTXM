from setuptools import setup, find_packages

setup(
    name="ph4ntxm-opsec-net",
    version="1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "ph4ntxm-opsec-net=ph4ntxm_opsec_net.cli:main"
        ]
    },
)