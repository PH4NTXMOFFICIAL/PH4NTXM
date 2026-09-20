#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import hashlib
import os
from pathlib import Path
import re
import shutil
import shlex
import struct
import sys
import tempfile
import uuid

from cpu_profile import specification, validate


def integer(env, key, minimum, maximum):
    value = env.get(key, '')
    if not re.fullmatch(r'[0-9]+', value) or not minimum <= int(value) <= maximum:
        raise ValueError('Invalid session value: ' + key)
    return int(value)


def usable_memory(env):
    if 'PH4_USABLE_RAM_BYTES' in env:
        return integer(env, 'PH4_USABLE_RAM_BYTES', 1024**2, 4096 * 1024**3)
    return integer(env, 'PH4_REPORTED_RAM', 1, 4096) * 1024**3


def cpuinfo(env):
    cpu = validate(env)
    count = cpu['PH4_CPU_ACTIVE_THREADS']
    threads = cpu['PH4_THREADS_PER_CORE']
    arch = env['PH4_CPU_ARCHITECTURE']
    model = env['PH4_CPU_MODEL_NAME']
    vendor = env['PH4_CPU_VENDOR_ID']
    family = integer(env, 'PH4_CPU_FAMILY', 0, 255)
    model_id = integer(env, 'PH4_CPU_MODEL_ID', 0, 65535)
    stepping = integer(env, 'PH4_CPU_STEPPING', 0, 255)
    spec = specification(model)
    current, cache = spec['base_mhz'], spec['l3']
    cpuinfo = []
    for i in range(count):
        fields = {
            'processor': i,
            'vendor_id': vendor,
            'cpu family': family,
            'model': model_id,
            'model name': model,
            'stepping': stepping,
            'cpu MHz': f'{current}.000',
            'cache size': f'{cache} KB',
            'physical id': 0,
            'siblings': count,
            'core id': i // threads,
            'cpu cores': count // threads,
            'apicid': i,
            'initial apicid': i,
            'fpu': 'yes',
            'fpu_exception': 'yes',
            'cpuid level': spec['cpuid_level'],
            'wp': 'yes',
            'flags': env['PH4_CPU_FLAGS'],
            'bogomips': f'{current * 2}.00',
            'clflush size': 64,
            'cache_alignment': 64,
            'address sizes': f"{spec['physical_bits']} bits physical, 48 bits virtual",
            'power management': '',
        }
        if arch == 'aarch64':
            fields = {
                'processor': i,
                'model name': model,
                'BogoMIPS': f'{current * 2}.00',
                'Features': env['PH4_CPU_FLAGS'],
                'CPU implementer': '0x61',
                'CPU architecture': 8,
                'CPU variant': '0x0',
                'CPU part': f"0x{(0x032 if 'M2' in model else 0x022) + (i >= count // 2):03x}",
                'CPU revision': stepping,
            }
        cpuinfo.append(
            '\n'.join(f'{key}\t: {value}' for key, value in fields.items()) + '\n\n'
        )
    return ''.join(cpuinfo)


def node_memory(ram):
    fields = {}
    for node in sorted(Path('/sys/devices/system/node').glob('node[0-9]*/meminfo')):
        for line in node.read_text().splitlines():
            match = re.fullmatch(r'Node [0-9]+ ([^:]+):\s+([0-9]+)(?:\s+(kB))?', line)
            if match:
                key, amount, unit = match.groups()
                previous = fields.get(key, (0, unit))[0]
                fields[key] = (previous + int(amount), unit)
    total = fields.get('MemTotal', (0, None))[0]
    if not total:
        raise ValueError('Native NUMA memory information is unavailable')
    lines = []
    for key, (amount, unit) in fields.items():
        if unit == 'kB' and key != 'SwapCached':
            amount = amount * (ram // 1024) // total
        lines.append(f'Node 0 {key}: {amount:8d}' + (' kB' if unit else '') + '\n')
    return ''.join(lines)


def prepare(
    root,
    env,
    dmi_directory=Path('/run/ph4ntxm/fake_dmi'),
    meminfo=Path('/proc/meminfo'),
):
    if not dmi_directory.is_dir():
        raise ValueError('Session DMI profile is unavailable')
    cpu = validate(env)
    count = cpu['PH4_CPU_ACTIVE_THREADS']
    ram = usable_memory(env)
    threads = integer(env, 'PH4_THREADS_PER_CORE', 1, count)
    if count % threads:
        raise ValueError('Inconsistent CPU topology')
    arch = env['PH4_CPU_ARCHITECTURE']
    if arch not in ('x86_64', 'aarch64'):
        raise ValueError('Invalid CPU architecture')
    model = env['PH4_CPU_MODEL_NAME']
    vendor = env['PH4_CPU_VENDOR_ID']
    for key in ('PH4_CPU_MODEL_NAME', 'PH4_CPU_VENDOR_ID', 'PH4_CPU_FLAGS'):
        if any(ord(c) < 32 for c in env[key]):
            raise ValueError('Invalid session string: ' + key)
    family = integer(env, 'PH4_CPU_FAMILY', 0, 255)
    model_id = integer(env, 'PH4_CPU_MODEL_ID', 0, 65535)
    stepping = integer(env, 'PH4_CPU_STEPPING', 0, 255)
    spec = specification(model)
    low, high, current, cache = (
        spec[key] for key in ('min_mhz', 'max_mhz', 'base_mhz', 'l3')
    )

    def write(path, data):
        target = root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else str(data).encode())

    write('/proc/cpuinfo', cpuinfo(env))
    original = meminfo.read_text()
    real_kib = int(re.search(r'^MemTotal:\s+(\d+)', original, re.M)[1])

    def memory_line(match):
        key, amount, suffix = match.groups()
        if key in ('SwapTotal', 'SwapFree', 'SwapCached', 'Hugepagesize'):
            return match[0]
        scaled = round(int(amount) * (ram // 1024) / real_kib)
        return f'{key}: {scaled:8d}{suffix}'

    memory_text = re.sub(
        r'^([A-Za-z_()]+):\s+(\d+)(\s+kB)$', memory_line, original, flags=re.M
    )
    write('/proc/meminfo', memory_text)
    block_size = 128 * 1024**2
    write('/sys/devices/system/memory/block_size_bytes', f'{block_size:x}\n')
    for index in range(ram // block_size):
        for base in (
            f'/sys/devices/system/memory/memory{index}',
            f'/sys/bus/memory/devices/memory{index}',
        ):
            for name, value in {
                'online': '1',
                'state': 'online',
                'phys_index': f'{index:08x}',
                'removable': '1',
            }.items():
                write(base + '/' + name, value + '\n')
            (root / base.lstrip('/') / 'node0').mkdir(exist_ok=True)
    write('/sys/devices/system/node/node0/distance', '10\n')
    write('/proc/kcore', b'')
    cpu_list = '0' if count == 1 else f'0-{count - 1}'
    cpu_root = '/sys/devices/system/cpu'
    for name in ('online', 'present', 'possible'):
        write(f'{cpu_root}/{name}', cpu_list + '\n')
    write(f'{cpu_root}/offline', '\n')
    write(f'{cpu_root}/kernel_max', count - 1)
    for i in range(count):
        base = f'{cpu_root}/cpu{i}'
        write(base + '/online', '1\n')
        (root / base.lstrip('/') / 'node0').mkdir(exist_ok=True)
        peers = ','.join(
            str(j) for j in range(i // threads * threads, (i // threads + 1) * threads)
        )
        for name, value in {
            'physical_package_id': 0,
            'core_id': i // threads,
            'die_id': 0,
            'thread_siblings_list': peers,
            'core_siblings_list': cpu_list,
            'package_cpus_list': cpu_list,
            'core_cpus_list': peers,
            'thread_siblings': format(sum(1 << int(j) for j in peers.split(',')), 'x'),
            'core_siblings': format((1 << count) - 1, 'x'),
        }.items():
            write(f'{base}/topology/{name}', f'{value}\n')
        policy = f'{cpu_root}/cpufreq/policy{i}'
        for name, value in {
            'cpuinfo_min_freq': low,
            'cpuinfo_max_freq': high,
            'cpuinfo_cur_freq': current,
            'scaling_min_freq': low,
            'scaling_max_freq': high,
            'scaling_cur_freq': current,
            'base_frequency': current,
        }.items():
            write(f'{policy}/{name}', f'{value * 1000}\n')
        for name in ('affected_cpus', 'related_cpus'):
            write(f'{policy}/{name}', f'{i}\n')
        (root / base.lstrip('/') / 'cpufreq').symlink_to(f'../cpufreq/policy{i}')
        for index, (level, kind, size) in enumerate(
            (
                (1, 'Data', spec['l1d']),
                (1, 'Instruction', spec['l1i']),
                (2, 'Unified', spec['l2']),
                (3, 'Unified', cache),
            )
        ):
            ways = spec['ways'][index]
            for key, value in {
                'level': level,
                'type': kind,
                'size': f'{size}K',
                'coherency_line_size': 64,
                'ways_of_associativity': ways,
                'number_of_sets': size * 1024 // (ways * 64),
                'shared_cpu_list': cpu_list if level == 3 else peers,
                'shared_cpu_map': format(
                    (
                        (1 << count) - 1
                        if level == 3
                        else sum(1 << int(j) for j in peers.split(','))
                    ),
                    'x',
                ),
                'id': 0 if level == 3 else i // threads,
            }.items():
                write(f'{base}/cache/index{index}/{key}', f'{value}\n')
    write('/sys/devices/system/node/online', '0\n')
    write('/sys/devices/system/node/possible', '0\n')
    write('/sys/devices/system/node/node0/cpulist', cpu_list + '\n')
    write('/sys/devices/system/node/node0/cpumap', format((1 << count) - 1, 'x') + '\n')
    write(
        '/sys/devices/system/node/node0/meminfo',
        node_memory(ram),
    )
    stat = Path('/proc/stat').read_text().splitlines()
    cpus = [line.split()[1:] for line in stat if re.match(r'^cpu\d+ ', line)]
    if cpus:
        stat = [line for line in stat if not re.match(r'^cpu\d+ ', line)]
        rows = [f'cpu{i} ' + ' '.join(cpus[i % len(cpus)]) for i in range(count)]
        totals = [
            str(sum(int(row.split()[j + 1]) for row in rows))
            for j in range(len(cpus[0]))
        ]
        stat[0] = 'cpu ' + ' '.join(totals)
        stat[1:1] = rows
    write('/proc/stat', '\n'.join(stat) + '\n')
    dmi = {}
    for name in (
        'sys_vendor',
        'product_name',
        'product_version',
        'product_family',
        'product_sku',
        'product_serial',
        'product_uuid',
        'board_vendor',
        'board_name',
        'board_version',
        'board_serial',
        'board_asset_tag',
        'bios_vendor',
        'bios_version',
        'bios_date',
        'bios_release',
        'ec_firmware_release',
        'modalias',
        'uevent',
        'chassis_vendor',
        'chassis_type',
        'chassis_version',
        'chassis_serial',
        'chassis_asset_tag',
    ):
        file = dmi_directory / name
        value = file.read_text().strip() if file.is_file() else 'Not Specified'
        if any(ord(c) < 32 for c in value):
            raise ValueError('Invalid DMI string')
        dmi[name] = value
        for base in ('/sys/class/dmi/id', '/sys/devices/virtual/dmi/id'):
            write(base + '/' + name, value + '\n')
    smbios(root, dmi, model, vendor, count, threads, ram, high, current, env, cache)
    result = {'PH4_INVENTORY_ROOT': str(root), 'PH4_INVENTORY_RAM_BYTES': str(ram)}
    for key in ('l1d', 'l1i', 'l2', 'l3'):
        result['PH4_CACHE_' + key.upper()] = str(spec[key] * 1024)
    for index, key in enumerate(('l1d', 'l1i', 'l2', 'l3')):
        result['PH4_CACHE_' + key.upper() + '_WAYS'] = str(spec['ways'][index])
    return result


def smbios(root, dmi, model, vendor, count, threads, ram, high, current, env, cache):
    records = []

    def record(kind, handle, length, values, strings):
        data = bytearray(length)
        struct.pack_into('<BBH', data, 0, kind, length, handle)
        for offset, value in values.items():
            if isinstance(value, bytes):
                data[offset : offset + len(value)] = value
            else:
                data[offset] = value
        records.append(
            bytes(data)
            + b'\0'.join(s.encode('utf-8') or b'Not Specified' for s in strings)
            + b'\0\0'
        )

    def setting(key, default, maximum=65535):
        return integer(env, key, 0, maximum) if key in env else default

    def revision(key):
        value = re.fullmatch(r'(\d{1,3})\.(\d{1,3})', dmi[key])
        if value and all(int(v) < 255 for v in value.groups()):
            return bytes(map(int, value.groups()))
        return b'\xff\xff'

    rom = (
        integer(env, 'PH4_BIOS_ROM_BYTES', 0, 16383 * 1024**2)
        if 'PH4_BIOS_ROM_BYTES' in env
        else 0
    )
    present = (
        integer(env, 'PH4_BIOS_PRESENT', 0, 1)
        if 'PH4_BIOS_PRESENT' in env
        else bool(rom)
    )
    if present:
        if rom % 65536 or (rom >= 16 * 1024**2 and rom % 1024**2):
            raise ValueError('Invalid BIOS ROM size')
        record(
            0,
            0,
            26,
            {
                4: 1,
                5: 2,
                6: struct.pack(
                    '<H',
                    (
                        integer(env, 'PH4_BIOS_SEGMENT', 0, 65535)
                        if 'PH4_BIOS_SEGMENT' in env
                        else 0
                    ),
                ),
                8: 3,
                9: min(rom // 65536 - 1, 255) if rom else 255,
                10: struct.pack(
                    '<Q', setting('PH4_BIOS_CHARACTERISTICS', 1 << 3, 2**64 - 1)
                ),
                18: setting('PH4_BIOS_CHARACTERISTICS_EXT1', 0, 255),
                19: setting('PH4_BIOS_CHARACTERISTICS_EXT2', 0, 255),
                20: revision('bios_release'),
                22: revision('ec_firmware_release'),
                24: struct.pack('<H', rom // 1024**2),
            },
            [dmi['bios_vendor'], dmi['bios_version'], dmi['bios_date']],
        )
        if setting('PH4_BIOS_CHARACTERISTICS_EXT2', 0, 255) & 8:
            (root / 'sys/firmware/efi').mkdir(parents=True, exist_ok=True)
    try:
        identifier = uuid.UUID(dmi['product_uuid']).bytes_le
    except ValueError:
        identifier = b'\0' * 16
    record(
        1,
        1,
        27,
        {4: 1, 5: 2, 6: 3, 7: 4, 8: identifier, 24: 2, 25: 5, 26: 6},
        [
            dmi[k]
            for k in (
                'sys_vendor',
                'product_name',
                'product_version',
                'product_serial',
                'product_sku',
                'product_family',
            )
        ],
    )
    record(
        2,
        2,
        15,
        {
            4: 1,
            5: 2,
            6: 3,
            7: 4,
            8: 5,
            9: 1,
            10: 6,
            11: struct.pack('<H', 3),
            13: 10,
        },
        [
            dmi[k]
            for k in (
                'board_vendor',
                'board_name',
                'board_version',
                'board_serial',
                'board_asset_tag',
            )
        ]
        + [env.get('PH4_BOARD_LOCATION', 'Not Specified')],
    )
    chassis_type = int(dmi['chassis_type']) if dmi['chassis_type'].isdigit() else 10
    if not 1 <= chassis_type <= 36:
        raise ValueError('Invalid chassis type')
    record(
        3,
        3,
        22,
        {
            4: 1,
            5: chassis_type,
            6: 2,
            7: 3,
            8: 4,
            9: 2,
            10: 2,
            11: 2,
            12: 2,
            21: 5,
        },
        [
            dmi[k]
            for k in (
                'chassis_vendor',
                'chassis_version',
                'chassis_serial',
                'chassis_asset_tag',
            )
        ]
        + [env.get('PH4_CHASSIS_SKU', 'Not Specified')],
    )
    arm = env['PH4_CPU_ARCHITECTURE'] == 'aarch64'
    cpu_family = int(env['PH4_CPU_FAMILY'])
    cpu_model = int(env['PH4_CPU_MODEL_ID'])
    cpu_step = int(env['PH4_CPU_STEPPING'])
    if arm:
        identifier = struct.pack(
            '<Q',
            (0x61 << 24)
            | (0xF << 16)
            | ((0x033 if 'M2' in model else 0x023) << 4)
            | (cpu_step & 15),
        )
        smbios_family = 0x101
    else:
        signature = (
            (cpu_step & 15) | ((cpu_model & 15) << 4) | (min(cpu_family, 15) << 8)
        )
        if cpu_family >= 15:
            signature |= (cpu_family - 15) << 20
        if cpu_family == 6 or cpu_family >= 15:
            signature |= (cpu_model >> 4) << 16
        flags = env['PH4_CPU_FLAGS'].split()
        edx_flags = {
            0: 'fpu',
            1: 'vme',
            2: 'de',
            3: 'pse',
            4: 'tsc',
            5: 'msr',
            6: 'pae',
            7: 'mce',
            8: 'cx8',
            9: 'apic',
            11: 'sep',
            12: 'mtrr',
            13: 'pge',
            14: 'mca',
            15: 'cmov',
            16: 'pat',
            17: 'pse36',
            19: 'clflush',
            23: 'mmx',
            24: 'fxsr',
            25: 'sse',
            26: 'sse2',
            28: 'ht',
        }
        identifier = struct.pack(
            '<II',
            signature,
            sum(1 << bit for bit, flag in edx_flags.items() if flag in flags),
        )
        if 'i7-' in model:
            smbios_family = 0xC6
        elif 'Ryzen' in model:
            smbios_family = 0x6B
        elif 'Xeon' in model:
            smbios_family = 0xB3
        else:
            smbios_family = 2
    topology = validate(env)
    enabled_cores = topology['PH4_CPU_ACTIVE_CORES']
    total_cores = topology['PH4_CPU_TOTAL_CORES']
    total_threads = topology['PH4_CPU_TOTAL_THREADS']
    characteristics = 4 | (8 if total_cores > 1 else 0) | (16 if threads > 1 else 0)
    record(
        4,
        4,
        50,
        {
            4: 1,
            5: 3,
            6: 0xFE,
            7: 2,
            8: identifier,
            16: 3,
            18: struct.pack('<H', setting('PH4_CPU_EXTERNAL_CLOCK_MHZ', 0)),
            20: struct.pack('<H', high),
            22: struct.pack('<H', current),
            24: 0x41,
            25: setting('PH4_CPU_UPGRADE', 2, 0x50),
            26: struct.pack('<H', 7),
            28: struct.pack('<H', 8),
            30: struct.pack('<H', 9),
            35: min(total_cores, 255),
            36: min(enabled_cores, 255),
            37: min(total_threads, 255),
            38: struct.pack('<H', characteristics),
            40: struct.pack('<H', smbios_family),
            42: struct.pack('<H', total_cores),
            44: struct.pack('<H', enabled_cores),
            46: struct.pack('<H', total_threads),
            48: struct.pack('<H', count),
        },
        [
            env.get('PH4_CPU_SOCKET', 'Not Specified'),
            env.get('PH4_CPU_MANUFACTURER', vendor),
            model,
        ],
    )
    spec = specification(model)
    l1d_ways, l1i_ways, l2_ways, l3_ways = spec['ways']
    ways_codes = {
        1: 3,
        2: 4,
        4: 5,
        8: 7,
        12: 9,
        16: 8,
        20: 14,
        24: 10,
        32: 11,
        48: 12,
        64: 13,
    }
    for level, size, ways in (
        (
            1,
            (spec['l1d'] + spec['l1i']) * total_cores,
            l1d_ways if l1d_ways == l1i_ways else 0,
        ),
        (2, spec['l2'] * total_cores, l2_ways),
        (3, cache, l3_ways),
    ):
        legacy_size = size if size < 0x8000 else 0x8000 | (size // 64)
        extended_size = size if size < 0x8000 else 0x80000000 | (size // 64)
        record(
            7,
            6 + level,
            27,
            {
                4: 1,
                5: struct.pack('<H', 0x180 | (level - 1)),
                7: struct.pack('<H', legacy_size),
                9: struct.pack('<H', legacy_size),
                11: b'\x02\x00',
                13: b'\x02\x00',
                16: 2,
                17: 5,
                18: ways_codes.get(ways, 2),
                19: struct.pack('<I', extended_size),
                23: struct.pack('<I', extended_size),
            },
            [f'L{level} Cache'],
        )
    installed = (
        integer(env, 'PH4_INSTALLED_RAM_BYTES', ram, 4096 * 1024**3)
        if 'PH4_INSTALLED_RAM_BYTES' in env
        else ram
    )
    maximum = (
        integer(env, 'PH4_MEMORY_MAX_BYTES', installed, 4096 * 1024**3)
        if 'PH4_MEMORY_MAX_BYTES' in env
        else installed
    )
    slots = integer(env, 'PH4_MEMORY_SLOTS', 1, 64) if 'PH4_MEMORY_SLOTS' in env else 1
    form = (
        integer(env, 'PH4_MEMORY_FORM', 1, 16)
        if 'PH4_MEMORY_FORM' in env
        else (11 if arm else 13 if chassis_type in (8, 9, 10, 14, 30, 31, 32) else 9)
    )
    memory_type = (
        integer(env, 'PH4_MEMORY_TYPE', 1, 35)
        if 'PH4_MEMORY_TYPE' in env
        else 30 if arm else 26
    )
    speed = (
        integer(env, 'PH4_MEMORY_SPEED', 0, 65535)
        if 'PH4_MEMORY_SPEED' in env
        else 2400
    )
    ecc = env.get('PH4_MEMORY_ECC') == '1'
    if 'PH4_PROFILE_ID' in env:
        from persona import memory_layout, profile

        selected = profile(env['PH4_PROFILE_ID'])
        devices = memory_layout(selected)
        if (
            installed != sum(d['size_mib'] for d in devices) * 1024**2
            or slots != len(devices)
            or maximum != selected['memory_max_gib'] * 1024**3
            or form != selected['memory_form']
            or speed != selected['memory_speed']
            or ecc != selected['memory_ecc']
            or model != specification(selected['cpu'])['name']
            or memory_type
            != {'DDR3': 24, 'DDR4': 26, 'LPDDR3': 29, 'LPDDR4': 30}[
                selected['memory_type']
            ]
        ):
            raise ValueError('Memory layout does not match the session profile')
    else:
        modules = 2 if form != 11 and installed >= 8 * 1024**3 and slots > 1 else 1
        module_max = (
            integer(env, 'PH4_MEMORY_MODULE_MAX_BYTES', 1024**2, maximum)
            if 'PH4_MEMORY_MODULE_MAX_BYTES' in env
            else maximum
        )
        while installed > modules * module_max:
            modules *= 2
        if modules > slots or installed % (modules * 1024**2):
            raise ValueError('Invalid memory module configuration')
        devices = []
        for slot in range(slots):
            device = dict(
                size_mib=installed // modules // 1024**2 if slot < modules else 0,
                locator=f'DIMM {slot}',
                bank=f'BANK {slot}',
            )
            if slot < modules:
                device.update(
                    manufacturer='Not Specified',
                    part_number='Not Specified',
                    form_factor=form,
                    total_width=72 if ecc else 64,
                    data_width=64,
                    speed_mt_s=speed,
                    configured_speed_mt_s=speed,
                    type_detail=(1 << 7)
                    | ((1 << 13) if ecc else (1 << 14) if form != 11 else 0),
                    rank=0,
                    minimum_mv=0,
                    maximum_mv=0,
                    configured_mv=0,
                )
            devices.append(device)
    record(
        16,
        16,
        23,
        {
            4: 3,
            5: 3,
            6: 6 if ecc else 3,
            7: struct.pack('<I', 0x80000000),
            11: b'\xfe\xff',
            13: struct.pack('<H', slots),
            15: struct.pack('<Q', maximum),
        },
        [],
    )
    for slot, device in enumerate(devices):
        mib = device['size_mib']
        populated = bool(mib)
        serial = (
            hashlib.sha256((dmi['product_uuid'] + ':memory:' + str(slot)).encode())
            .hexdigest()[:8]
            .upper()
            if populated and device['form_factor'] in (9, 13)
            else 'Not Specified'
        )
        record(
            17,
            0x100 + slot,
            40,
            {
                4: struct.pack('<H', 16),
                6: b'\xfe\xff',
                8: struct.pack('<H', device.get('total_width', 65535)),
                10: struct.pack('<H', device.get('data_width', 65535)),
                12: struct.pack('<H', min(mib, 0x7FFF)),
                14: device.get('form_factor', form),
                16: 1,
                17: 2,
                18: memory_type if populated else 2,
                19: struct.pack('<H', device.get('type_detail', 0)),
                21: struct.pack('<H', device.get('speed_mt_s', 0)),
                23: 3 if populated else 0,
                24: 4 if populated else 0,
                26: 5 if populated else 0,
                27: device.get('rank', 0),
                28: struct.pack('<I', mib if mib >= 0x7FFF else 0),
                32: struct.pack('<H', device.get('configured_speed_mt_s', 0)),
                34: struct.pack('<H', device.get('minimum_mv', 0)),
                36: struct.pack('<H', device.get('maximum_mv', 0)),
                38: struct.pack('<H', device.get('configured_mv', 0)),
            },
            [
                device['locator'],
                device['bank'],
                device.get('manufacturer', 'Not Specified'),
                serial,
                device.get('part_number', 'Not Specified'),
            ],
        )
    record(127, 127, 4, {}, [])
    table = b''.join(records)
    entry = bytearray(24)
    entry[:5] = b'_SM3_'
    entry[6:11] = bytes([24, 3, 6, 0, 1])
    struct.pack_into('<I', entry, 12, len(table))
    entry[5] = (-sum(entry)) & 255
    target = root / 'sys/firmware/dmi/tables'
    target.mkdir(parents=True, exist_ok=True)
    (target / 'smbios_entry_point').write_bytes(entry)
    (target / 'DMI').write_bytes(table)
    instances = {}
    for position, data in enumerate(records):
        kind, length, handle = struct.unpack_from('<BBH', data)
        instance = instances.get(kind, 0)
        instances[kind] = instance + 1
        entry = target.parent / 'entries' / f'{kind}-{instance}'
        entry.mkdir(parents=True, exist_ok=True)
        (entry / 'raw').write_bytes(data)
        for key, value in dict(
            type=kind,
            length=length,
            handle=handle,
            instance=instance,
            position=position,
        ).items():
            (entry / key).write_text(f'{value}\n')


def main():
    if sys.argv[1:] == ['--cpuinfo']:
        sys.stdout.write(cpuinfo(os.environ))
        return 0
    tool, real, *arguments = sys.argv[1:]
    if tool not in (
        'run',
        'lshw',
        'hwinfo',
        'inxi',
        'neofetch',
        'fastfetch',
        'screenfetch',
        'dmidecode',
        'free',
        'lscpu',
        'nproc',
        'getconf',
        'vmstat',
        'lsmem',
        'hwloc-ls',
        'lstopo',
        'lstopo-no-graphics',
        'hwloc-info',
        'hwloc-calc',
        'hwloc-distrib',
    ):
        raise ValueError('Unsupported command')
    library = Path('/usr/lib/ph4ntxm/hardware/query.so')
    if not library.is_file():
        raise ValueError('Inventory library is missing')
    supervisor = Path('/usr/lib/ph4ntxm/hardware/supervisor')
    if not supervisor.is_file():
        raise ValueError('Hardware supervisor is missing')
    temporary = tempfile.mkdtemp(prefix='.ph4ntxm-inventory-')
    try:
        environment = os.environ.copy()
        environment.update(prepare(Path(temporary), environment))
        environment['LD_PRELOAD'] = str(library) + (
            ':' + environment['LD_PRELOAD'] if environment.get('LD_PRELOAD') else ''
        )
        for variable in ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT'):
            environment.pop('PH4_CHILD_' + variable, None)
            if variable in environment:
                environment['PH4_CHILD_' + variable] = environment.pop(variable)
        environment['PH4_INVENTORY_ARGV0'] = real if tool == 'run' else tool
        if tool == 'lscpu':
            arguments = ['--sysroot', temporary, *arguments]
        if tool.startswith(('hwloc-', 'lstopo')):
            environment['HWLOC_COMPONENTS'] = '-x86'
        if tool == 'lshw' and not any(
            arg in ('-version', '-help', '--help') for arg in arguments
        ):
            arguments += ['-disable', 'cpuid']
        environment['PH4_INVENTORY_SYSCALLS'] = '1'
        (Path(temporary) / 'environment').write_text(
            ''.join(
                key + '=' + shlex.quote(value) + '\n'
                for key, value in sorted(environment.items())
                if (key.startswith(('PH4_CPU_', 'PH4_CACHE_', 'PH4_INVENTORY_'))
                    or key == 'PH4_REPORTED_CORES')
                and key not in ('PH4_INVENTORY_ARGV0', 'PH4_INVENTORY_OWNED')
                and re.fullmatch(r'[A-Z0-9_]+', key)
            )
        )
        environment['PH4_INVENTORY_OWNED'] = '1'
        os.execve(supervisor, [str(supervisor), real, *arguments], environment)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError) as error:
        print(f'{Path(sys.argv[0]).name}: {error}', file=sys.stderr)
        sys.exit(1)
