# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from setuptools import setup, find_packages

setup(
    name="ph4ntxm-opsec-radio",
    version="1.0",
    packages=find_packages(),
    entry_points={
        "console_scripts": ["ph4ntxm-opsec-radio=" "ph4ntxm_opsec_radio.cli:main"]
    },
)
