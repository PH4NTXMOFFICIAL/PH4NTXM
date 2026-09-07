from setuptools import setup, find_packages

setup(
    name="ph4ntxm-opsec-kernel",
    version="1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            (
                "ph4ntxm-opsec-kernel="
                "ph4ntxm_opsec_kernel.cli:main"
            )
        ]
    },
)