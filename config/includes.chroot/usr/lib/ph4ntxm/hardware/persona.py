#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import hashlib
import json
from pathlib import Path
import platform
import re
import shlex
import sys

from cpu_profile import specification, topology

CATALOG = json.loads(Path(__file__).with_name('personas.json').read_text())


def profile(identifier):
    matches = [item for item in CATALOG if item['id'] == identifier]
    if len(matches) != 1:
        raise ValueError('Unknown hardware profile')
    return matches[0]


def choose(mode, seed, architecture=None):
    if mode not in ('linux', 'windows', 'lonewolf') or not re.fullmatch(
        r'[0-9a-f]{64}', seed
    ):
        raise ValueError('Invalid session mode or seed')
    architecture = architecture or platform.machine()
    candidates = [
        p
        for p in CATALOG
        if specification(p['cpu'])['arch'] == architecture
        and (mode != 'windows' or p['vendor'] not in ('apple', 'google'))
    ]
    if not candidates:
        raise ValueError('No hardware profiles for this architecture')
    vendors = sorted({p['vendor'] for p in candidates})
    digest = hashlib.sha256((mode + seed).encode()).digest()
    vendor = vendors[int.from_bytes(digest[:8]) % len(vendors)]
    candidates = [p for p in candidates if p['vendor'] == vendor]
    return candidates[int.from_bytes(digest[8:16]) % len(candidates)]


def identity(p):
    return dict(
        PROFILE_ID=p['id'],
        VENDOR=p['vendor'],
        FAMILY=p['family'],
        SKU=p['id'],
        SYS_VENDOR=p['manufacturer'],
        PRODUCT_NAME=p.get('dmi_product_name', p['product']),
        BOARD_NAME=p['board'],
        BOARD_VENDOR=p.get('board_vendor', 'Not Specified'),
        BIOS_VENDOR=p.get('bios_vendor', 'Not Specified'),
        BIOS_VERSION=p.get('bios_version', 'Not Specified'),
        BIOS_DATE=p.get('bios_date', 'Not Specified'),
        BIOS_RELEASE=p.get('bios_release', 'Not Specified'),
        EC_FIRMWARE_RELEASE=p.get('ec_firmware_release', 'Not Specified'),
        PRODUCT_VERSION=p.get('product_version', 'Not Specified'),
        BOARD_VERSION=p.get('board_version', 'Not Specified'),
        PRODUCT_FAMILY=p.get('product_family', 'Not Specified'),
        PRODUCT_SKU=p.get('product_sku', 'Not Specified'),
        CHASSIS_VENDOR=p.get('chassis_vendor', p['manufacturer']),
        CHASSIS_TYPE=p['chassis'],
        CHASSIS_VERSION=p.get('chassis_version', 'Not Specified'),
        BOARD_ASSET_TAG='Not Specified',
        CHASSIS_ASSET_TAG='Not Specified',
        GPU_VENDOR=p['gpu_vendor'],
        GPU_FAMILY=p['gpu_family'],
        GPU_MODEL=p['gpu_model'],
        DEVICE_CLASS=(
            'server'
            if p['chassis'] == 23
            else 'desktop' if p['chassis'] in (3, 35) else 'laptop'
        ),
    )


def memory_layout(p):
    devices = p['memory_devices']
    if not isinstance(devices, list) or not 1 <= len(devices) <= 64:
        raise ValueError('Invalid memory device count')
    locations = set()
    installed = 0
    speeds = set()
    required = {
        'size_mib',
        'locator',
        'bank',
        'manufacturer',
        'part_number',
        'form_factor',
        'data_width',
        'total_width',
        'speed_mt_s',
        'configured_speed_mt_s',
        'rank',
        'type_detail',
        'minimum_mv',
        'maximum_mv',
        'configured_mv',
    }
    for device in devices:
        if not isinstance(device, dict):
            raise ValueError('Invalid memory device')
        populated = bool(device.get('size_mib'))
        expected = required if populated else {'size_mib', 'locator', 'bank'}
        if set(device) != expected:
            raise ValueError('Invalid memory device fields')
        for key in ('locator', 'bank') + (
            ('manufacturer', 'part_number') if populated else ()
        ):
            value = device[key]
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 256
                or any(ord(c) < 32 for c in value)
                or value.lower() in ('unknown', 'not specified', 'default string')
            ):
                raise ValueError('Invalid memory device string: ' + key)
        location = (device['locator'], device['bank'])
        if location in locations:
            raise ValueError('Duplicate memory device location')
        locations.add(location)
        for key, value in device.items():
            if key not in ('locator', 'bank', 'manufacturer', 'part_number'):
                if type(value) is not int or value < 0:
                    raise ValueError('Invalid memory device value: ' + key)
        if not populated:
            continue
        mib = device['size_mib']
        if mib > p.get('memory_module_max_gib', p['memory_max_gib']) * 1024:
            raise ValueError('Memory device exceeds supported capacity')
        if device['form_factor'] != p['memory_form']:
            raise ValueError('Inconsistent memory form factor')
        width = device['data_width']
        if width not in (8, 16, 32, 64, 128):
            raise ValueError('Invalid memory data width')
        if device['total_width'] != width + (8 if p['memory_ecc'] else 0):
            raise ValueError('Inconsistent memory ECC width')
        speed = device['speed_mt_s']
        configured = device['configured_speed_mt_s']
        if not 0 < configured <= speed <= 65535:
            raise ValueError('Inconsistent memory speed')
        if device['rank'] > 15 or device['type_detail'] > 65535:
            raise ValueError('Invalid memory rank or type detail')
        detail = device['type_detail']
        if detail & (1 << 13) and detail & (1 << 14):
            raise ValueError('Conflicting registered and unbuffered memory')
        if p['memory_type'].startswith('LPDDR') and detail & ((1 << 13) | (1 << 14)):
            raise ValueError('Invalid soldered memory type detail')
        low, high, current = (
            device[k] for k in ('minimum_mv', 'maximum_mv', 'configured_mv')
        )
        if max(low, high, current) > 65535:
            raise ValueError('Invalid memory voltage')
        if low and high and low > high:
            raise ValueError('Inconsistent memory voltage range')
        if current and ((low and current < low) or (high and current > high)):
            raise ValueError('Configured voltage outside memory range')
        installed += mib
        speeds.add(configured)
    if (
        not installed
        or installed % 1024
        or p['memory_gib'] != [installed // 1024]
        or p['memory_slots'] != len(devices)
        or installed > p['memory_max_gib'] * 1024
        or speeds != {p['memory_speed']}
    ):
        raise ValueError('Inconsistent memory layout')
    return devices


def resources(p, processors, memory_kib):
    if processors < 1 or memory_kib < 1:
        raise ValueError('Invalid host resource limits')
    spec = specification(p['cpu'])
    values = topology(spec['name'], processors)
    gib = 1024**3
    host_bytes = memory_kib * 1024
    installed = sum(d['size_mib'] for d in memory_layout(p)) // 1024
    usable = min(installed * gib, 1 << (host_bytes.bit_length() - 1))
    if usable < 128 * 1024**2:
        raise ValueError('Insufficient host memory for a hardware view')
    values.update(
        PH4_PROFILE_ID=p['id'],
        PH4_REPORTED_CORES=values['PH4_CPU_ACTIVE_THREADS'],
        PH4_REPORTED_RAM=max(1, usable // gib),
        PH4_USABLE_RAM_BYTES=usable,
        PH4_INSTALLED_RAM_BYTES=installed * gib,
        PH4_MEMORY_MAX_BYTES=p['memory_max_gib'] * gib,
        PH4_MEMORY_SLOTS=p['memory_slots'],
        PH4_MEMORY_MODULE_MAX_BYTES=p.get('memory_module_max_gib', p['memory_max_gib'])
        * gib,
        PH4_BIOS_ROM_BYTES=p.get('bios_rom_bytes', 0),
        PH4_BIOS_PRESENT=int(bool(p.get('bios_version'))),
        PH4_BIOS_SEGMENT=p.get('bios_segment', 0),
        PH4_MEMORY_FORM=p['memory_form'],
        PH4_MEMORY_TYPE={'DDR3': 24, 'DDR4': 26, 'LPDDR3': 29, 'LPDDR4': 30}[
            p['memory_type']
        ],
        PH4_MEMORY_SPEED=p['memory_speed'],
        PH4_MEMORY_ECC=int(p['memory_ecc']),
        PH4_HARDWARE_MODEL=p['product'],
        PH4_HARDWARE_ERA=spec['era'],
        PH4_DEVICE_CLASS=identity(p)['DEVICE_CLASS'],
        PH4_BIOS_CHARACTERISTICS=p.get('bios_characteristics', 1 << 3),
        PH4_BIOS_CHARACTERISTICS_EXT1=p.get('bios_characteristics_ext1', 0),
        PH4_BIOS_CHARACTERISTICS_EXT2=p.get('bios_characteristics_ext2', 0),
        PH4_BOARD_LOCATION=p.get('board_location', 'Not Specified'),
        PH4_CHASSIS_SKU=p.get('chassis_sku', 'Not Specified'),
        PH4_CPU_EXTERNAL_CLOCK_MHZ=p.get('cpu_external_clock_mhz', 0),
        PH4_CPU_UPGRADE=p['cpu_upgrade'],
        PH4_CPU_MANUFACTURER=p['cpu_manufacturer'],
        PH4_CPU_SOCKET=p.get('cpu_socket', 'Not Specified'),
        PH4_CPU_ARCHITECTURE=spec['arch'],
        PH4_CPU_VENDOR_ID=spec['vendor'],
        PH4_CPU_FAMILY=spec['family'],
        PH4_CPU_MODEL_ID=spec['model'],
        PH4_CPU_STEPPING=spec['stepping'],
        PH4_CPU_MODEL_NAME=spec['name'],
        PH4_CPU_FLAGS=spec['flags'],
    )
    for key in ('l1d', 'l1i', 'l2', 'l3'):
        values['PH4_CACHE_' + key.upper()] = spec[key] * 1024
    return values


def shell(values):
    return ''.join(
        'export ' + key + '=' + shlex.quote(str(value)) + '\n'
        for key, value in values.items()
    )


if __name__ == '__main__':
    try:
        operation, *arguments = sys.argv[1:]
        if operation == 'select' and len(arguments) == 2:
            result = identity(choose(*arguments))
        elif operation == 'show' and len(arguments) == 1:
            result = identity(profile(arguments[0]))
        elif operation == 'resources' and len(arguments) == 3:
            result = resources(
                profile(arguments[0]), int(arguments[1]), int(arguments[2])
            )
        else:
            raise ValueError('Invalid persona command')
        sys.stdout.write(shell(result))
    except (ValueError, KeyError, OSError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
