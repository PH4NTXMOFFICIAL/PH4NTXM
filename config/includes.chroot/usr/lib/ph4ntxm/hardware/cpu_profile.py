#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import re
import sys

PROFILES = {
    'i7-7Y75': (2, 4),
    'E5-2690': (8, 16),
    'i7-8550U': (4, 8),
    'i7-8650U': (4, 8),
    'i7-8700B': (6, 12),
    'i7-1165G7': (4, 8),
    'Ryzen 5 3500U': (4, 8),
    'Ryzen 7 5800X': (8, 16),
}
FIELDS = (
    'PH4_CPU_TOTAL_CORES',
    'PH4_CPU_TOTAL_THREADS',
    'PH4_CPU_ACTIVE_CORES',
    'PH4_CPU_ACTIVE_THREADS',
    'PH4_THREADS_PER_CORE',
)

SPECS = {
    'i7-7Y75': (6, 142, 9, 400, 1300, 3600, 32, 32, 256, 4096),
    'i7-8550U': (6, 142, 10, 400, 1800, 4000, 32, 32, 256, 8192),
    'i7-8650U': (6, 142, 10, 400, 1900, 4200, 32, 32, 256, 8192),
    'i7-8700B': (6, 158, 10, 800, 3200, 4600, 32, 32, 256, 12288),
    'i7-1165G7': (6, 140, 1, 400, 2800, 4700, 48, 32, 1280, 12288),
    'E5-2690': (6, 45, 7, 1200, 2900, 3800, 32, 32, 256, 20480),
    'Ryzen 5 3500U': (23, 24, 1, 1400, 2100, 3700, 32, 64, 512, 4096),
    'Ryzen 7 5800X': (25, 33, 0, 2200, 3800, 4700, 32, 32, 512, 32768),
}


def model_key(model):
    matches = [
        key
        for key in PROFILES
        if re.search(r'(?<![\w-])' + re.escape(key) + r'(?![\w-])', model)
    ]
    if not matches:
        raise ValueError('Unknown CPU model')
    matches.sort(key=len, reverse=True)
    if len(matches) > 1 and not matches[0].startswith(matches[1]):
        raise ValueError('Ambiguous CPU model')
    return matches[0]


def capacity(model):
    return PROFILES[model_key(model)]


def specification(model):
    key = model_key(model)
    fields = (
        'family',
        'model',
        'stepping',
        'min_mhz',
        'base_mhz',
        'max_mhz',
        'l1d',
        'l1i',
        'l2',
        'l3',
    )
    data = dict(zip(fields, SPECS[key]))
    amd = key.startswith('Ryzen')
    data.update(vendor='AuthenticAMD' if amd else 'GenuineIntel', arch='x86_64')
    data['physical_bits'] = 48 if amd else 46 if key == 'E5-2690' else 39
    data['cpuid_level'] = {
        'E5-2690': 13,
        'Ryzen 5 3500U': 13,
        'Ryzen 7 5800X': 16,
        'i7-1165G7': 27,
    }.get(key, 22)
    data['ways'] = {
        'i7-1165G7': (12, 8, 20, 12),
        'Ryzen 5 3500U': (8, 4, 8, 16),
        'Ryzen 7 5800X': (8, 8, 8, 16),
        'E5-2690': (8, 8, 8, 20),
    }.get(key, (8, 8, 4, 16))
    data['era'] = (
        'old'
        if key == 'E5-2690'
        else 'new' if key in ('i7-1165G7', 'Ryzen 7 5800X') else 'mid'
    )
    names = {
        'Ryzen 5 3500U': 'AMD Ryzen 5 3500U with Radeon Vega Mobile Gfx',
        'Ryzen 7 5800X': 'AMD Ryzen 7 5800X 8-Core Processor',
        'i7-1165G7': '11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz',
        'E5-2690': 'Intel(R) Xeon(R) CPU E5-2690 0 @ 2.90GHz',
    }
    data['name'] = names.get(
        key, f"Intel(R) Core(TM) {key} CPU @ {data['base_mhz'] / 1000:.2f}GHz"
    )
    flags = (
        'fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 '
        'clflush mmx fxsr sse sse2 ht syscall nx rdtscp lm constant_tsc rep_good '
        'nopl nonstop_tsc cpuid pni pclmulqdq ssse3 cx16 sse4_1 sse4_2 popcnt aes xsave avx'
    )
    if key != 'E5-2690':
        flags += ' f16c rdrand'
    if data['era'] != 'old':
        flags += ' avx2 fma bmi1 bmi2'
    flags += ' svm abm sse4a' if amd else ' vmx x2apic'
    data['flags'] = flags
    return data


def topology(model, requested):
    total_cores, total_threads = capacity(model)
    if not isinstance(requested, int) or requested < 1:
        raise ValueError('Invalid active CPU count')
    active_threads = min(requested, total_threads)
    smt = total_threads // total_cores
    if smt > 1 and active_threads >= 4:
        active_threads -= active_threads % smt
        threads = smt
    else:
        threads = 1
        active_threads = min(active_threads, total_cores)
    return dict(
        zip(
            FIELDS,
            (
                total_cores,
                total_threads,
                active_threads // threads,
                active_threads,
                threads,
            ),
        )
    )


def validate(env):
    values = {}
    for field in FIELDS:
        value = env.get(field, '')
        if not re.fullmatch(r'[1-9][0-9]*', value):
            raise ValueError('Invalid CPU topology field: ' + field)
        values[field] = int(value)
    cores, threads = capacity(env['PH4_CPU_MODEL_NAME'])
    active = values['PH4_CPU_ACTIVE_CORES']
    logical = values['PH4_CPU_ACTIVE_THREADS']
    smt = values['PH4_THREADS_PER_CORE']
    if (
        values['PH4_CPU_TOTAL_CORES'] != cores
        or values['PH4_CPU_TOTAL_THREADS'] != threads
        or active > cores
        or logical > threads
        or logical != active * smt
        or smt not in (1, threads // cores)
        or str(logical) != env.get('PH4_REPORTED_CORES')
    ):
        raise ValueError('Inconsistent CPU topology')
    return values


if __name__ == '__main__':
    try:
        result = topology(sys.argv[1], int(sys.argv[2]))
        print(' '.join(str(result[field]) for field in FIELDS))
    except (ValueError, IndexError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
