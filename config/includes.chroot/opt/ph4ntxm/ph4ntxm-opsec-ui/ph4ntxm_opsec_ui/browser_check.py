# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import copy
import json
import math
import os
import re
import secrets
import select
import shlex
import stat
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

STATE_DIRECTORY = Path('/run/ph4ntxm')
TEMPLATE_DIRECTORY = Path('/etc/firefox-esr/mode')
BROWSER_EXECUTABLE = '/usr/bin/firefox-esr-real'
MAX_STATE_BYTES = 65536
MAX_REPORT_BYTES = 16384
SESSION_SECONDS = 120


def read_protected(path, limit=MAX_STATE_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError(f'Unsafe permissions for {Path(path).name}')
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b''.join(chunks)
        if len(content) > limit:
            raise ValueError(f'{Path(path).name} exceeds the size limit')
        return content.decode('utf-8', 'strict')
    finally:
        os.close(descriptor)


def parse_environment(content):
    values = {}
    for line in content.splitlines():
        match = re.fullmatch(r'export ([A-Z][A-Z0-9_]*)=(.*)', line.strip())
        if not match:
            continue
        key, value = match.groups()
        if key in values:
            raise ValueError(f'Duplicate session field {key}')
        words = shlex.split(value, posix=True)
        if len(words) != 1:
            raise ValueError(f'Invalid session field {key}')
        values[key] = words[0]
    return values


def parse_preferences(content):
    values = {}
    expression = (
        r'user_pref\(\s*("(?:[^"\\]|\\.)*")\s*,\s*'
        r'("(?:[^"\\]|\\.)*"|true|false|-?[0-9]+(?:\.[0-9]+)?)\s*\);'
    )
    for match in re.finditer(expression, content):
        key = json.loads(match.group(1))
        if key in values:
            raise ValueError(f'Duplicate browser preference {key}')
        values[key] = json.loads(match.group(2))
    return values


def collect_fonts():
    font_directory = STATE_DIRECTORY / 'fonts-active'
    try:
        configuration = read_protected(font_directory / 'fonts.conf')
        if '<!ENTITY' in configuration:
            raise ValueError('Unsupported font configuration')
        root = ET.fromstring(configuration)
        directories = {(item.text or '').strip() for item in root.findall('dir')}
        if root.tag != 'fontconfig' or str(font_directory) not in directories:
            raise ValueError('The active font directory is not configured')
        environment = {
            'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
            'FONTCONFIG_PATH': str(font_directory),
            'FONTCONFIG_FILE': str(font_directory / 'fonts.conf'),
        }
        for key in ('HOME', 'XDG_CACHE_HOME', 'XDG_RUNTIME_DIR'):
            if key in os.environ:
                environment[key] = os.environ[key]
        process = subprocess.Popen(
            ['/usr/bin/fc-list', '--format', '%{family[0]}\n'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=environment, close_fds=True,
        )
        output = bytearray()
        deadline = time.monotonic() + 3
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('The font snapshot timed out')
                readable, _, _ = select.select([process.stdout], [], [], remaining)
                if not readable:
                    raise TimeoutError('The font snapshot timed out')
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > 131072:
                    raise ValueError('The font snapshot exceeds the size limit')
            if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
                raise ValueError('Fontconfig could not read the active profile')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)
            process.stdout.close()
        families = sorted({
            value.strip() for value in output.decode('utf-8', 'strict').splitlines()
            if value.strip() and len(value.strip()) <= 128
            and all(ord(char) >= 32 for char in value)
        })
        return families[:24] or None
    except (OSError, ValueError, TimeoutError, ET.ParseError, subprocess.SubprocessError):
        return None


def snapshot_expected():
    mode = read_protected(STATE_DIRECTORY / 'mode', 128).strip()
    if mode not in ('linux', 'windows'):
        raise ValueError('Browser Check is available in Linux and Windows modes')
    browser = parse_environment(read_protected(STATE_DIRECTORY / 'browser_env'))
    cores = parse_environment(read_protected(STATE_DIRECTORY / 'cores_env'))
    try:
        core_count = int(cores['PH4_REPORTED_CORES'])
        dpr = float(browser['PH4_DEVICE_PIXEL_RATIO'])
        width = int(browser['PH4_SCREEN_WIDTH'])
        height = int(browser['PH4_SCREEN_HEIGHT'])
        architecture = cores['PH4_CPU_ARCHITECTURE']
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError('The session browser values are incomplete') from error
    if not 1 <= core_count <= 65536 or not math.isfinite(dpr) or not 0 < dpr <= 16:
        raise ValueError('The session browser values are invalid')
    if (
        architecture not in ('x86_64', 'aarch64')
        or not 1 <= width <= 131072
        or not 1 <= height <= 131072
    ):
        raise ValueError('The session display or architecture is invalid')
    version = subprocess.run(
        [BROWSER_EXECUTABLE, '--version'], capture_output=True, text=True,
        encoding='utf-8', errors='replace', timeout=10, check=False,
    )
    found = re.search(r'\b([0-9]+)(?:\.[0-9]+)+(?:esr)?\b', version.stdout)
    if version.returncode != 0 or not found:
        raise ValueError('The installed Firefox version could not be read')
    template = read_protected(TEMPLATE_DIRECTORY / mode / 'user.js')
    replacements = {
        'CORES': core_count, 'DPR': browser['PH4_DEVICE_PIXEL_RATIO'],
        'ARCH': architecture, 'FIREFOX_MAJOR': found.group(1),
    }
    for name, value in replacements.items():
        template = template.replace('{{' + name + '}}', str(value))
    if re.search(r'\{\{[A-Z_][A-Z0-9_]*\}\}', template):
        raise ValueError('The browser template has unresolved session values')
    preferences = parse_preferences(template)
    try:
        greeter = read_protected('/etc/lightdm/lightdm-gtk-greeter.conf')
    except (OSError, ValueError):
        edition = None
    else:
        theme = re.search(r'^theme-name\s*=\s*PH4NTXM-(Ghost|Abyss)\s*$', greeter, re.MULTILINE)
        edition = theme.group(1).lower() if theme else None
    required = (
        'general.useragent.override', 'dom.maxHardwareConcurrency',
        'layout.css.devPixelsPerPx', 'intl.accept_languages', 'webgl.disabled',
        'media.peerconnection.enabled', 'dom.webaudio.enabled',
    )
    if any(name not in preferences for name in required):
        raise ValueError('The browser template is missing required preferences')
    for name in ('webgl.disabled', 'media.peerconnection.enabled', 'dom.webaudio.enabled'):
        if type(preferences[name]) is not bool:
            raise ValueError('The browser feature preferences are invalid')
    if (
        type(preferences['dom.maxHardwareConcurrency']) is not int
        or not 1 <= preferences['dom.maxHardwareConcurrency'] <= 65536
        or not isinstance(preferences['general.useragent.override'], str)
        or not isinstance(preferences['intl.accept_languages'], str)
    ):
        raise ValueError('The browser identity preferences are invalid')
    return {
        'mode': mode, 'edition': edition, 'version': found.group(0), 'preferences': preferences,
        'cores': core_count, 'dpr': dpr, 'screen_width': width, 'screen_height': height,
        'timezone': os.environ.get('TZ', '').lstrip(':') or None,
        'fonts': collect_fonts(),
    }


def unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate report field')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('Invalid numeric report value')


def validate_observed(raw):
    report = json.loads(
        raw, object_pairs_hook=unique_object, parse_constant=invalid_constant
    )
    expected_keys = {'schema_version', 'navigator', 'timezone', 'screen', 'features'}
    if (
        not isinstance(report, dict)
        or set(report) not in (expected_keys, expected_keys | {'fonts'})
        or type(report['schema_version']) is not int
        or report['schema_version'] != 1
    ):
        raise ValueError('Unsupported browser report')
    navigator = report['navigator']
    screen = report['screen']
    features = report['features']
    navigator_keys = {
        'userAgent', 'platform', 'oscpu', 'appVersion',
        'hardwareConcurrency', 'languages',
    }
    screen_keys = {
        'width', 'height', 'availWidth', 'availHeight',
        'devicePixelRatio', 'innerWidth', 'innerHeight',
    }
    if not isinstance(navigator, dict) or set(navigator) != navigator_keys:
        raise ValueError('Invalid browser identity report')
    if not isinstance(screen, dict) or set(screen) != screen_keys:
        raise ValueError('Invalid browser display report')
    if not isinstance(features, dict) or set(features) != {'webgl', 'webrtc', 'webaudio'}:
        raise ValueError('Invalid browser feature report')
    for name in ('userAgent', 'platform', 'oscpu', 'appVersion'):
        value = navigator[name]
        if value is not None and (
            not isinstance(value, str)
            or len(value) > 1024
            or any(ord(char) < 32 for char in value)
        ):
            raise ValueError('Invalid browser identity value')
    cores = navigator['hardwareConcurrency']
    if cores is not None and (type(cores) is not int or not 1 <= cores <= 65536):
        raise ValueError('Invalid browser processor value')
    languages = navigator['languages']
    if languages is not None and (
        not isinstance(languages, list)
        or len(languages) > 16
        or any(
            not isinstance(value, str)
            or not re.fullmatch(r'[A-Za-z0-9-]{1,64}', value)
            for value in languages
        )
    ):
        raise ValueError('Invalid browser language value')
    zone = report['timezone']
    if zone is not None and (
        not isinstance(zone, str)
        or not re.fullmatch(r'[A-Za-z0-9_+./:-]{1,128}', zone)
    ):
        raise ValueError('Invalid browser timezone value')
    for name, value in screen.items():
        if value is None:
            continue
        if name == 'devicePixelRatio':
            if (
                type(value) not in (int, float)
                or not math.isfinite(value)
                or not 0 < value <= 64
            ):
                raise ValueError('Invalid browser pixel ratio')
        elif type(value) is not int or not 0 <= value <= 131072:
            raise ValueError('Invalid browser display dimension')
    if any(value is not None and type(value) is not bool for value in features.values()):
        raise ValueError('Invalid browser feature value')
    fonts = report.get('fonts')
    if fonts is not None and (
        not isinstance(fonts, list) or len(fonts) > 24
        or len(set(value for value in fonts if isinstance(value, str))) != len(fonts)
        or any(
            not isinstance(value, str) or not 1 <= len(value) <= 128
            or any(ord(char) < 32 for char in value)
            for value in fonts
        )
    ):
        raise ValueError('Invalid browser font observation')
    return report


def compare_observed(expected, observed, request_headers=None):
    preferences = expected['preferences']
    rows = []

    def add(label, wanted, actual, status, detail=''):
        rows.append({
            'label': label, 'expected': wanted, 'observed': actual,
            'status': status, 'detail': detail,
        })

    def equality_status(wanted, actual):
        if actual is None:
            return 'unavailable'
        if wanted is None:
            return 'info'
        return 'match' if actual == wanted else 'different'

    for name, label, preference in (
        ('userAgent', 'User agent', 'general.useragent.override'),
        ('platform', 'Platform', 'general.platform.override'),
        ('oscpu', 'Operating system', 'general.oscpu.override'),
        ('appVersion', 'App version', 'general.appversion.override'),
    ):
        wanted = preferences.get(preference)
        actual = observed['navigator'][name]
        add(
            label, wanted or 'Browser default', actual,
            equality_status(wanted, actual),
            'No override is configured for this value.' if wanted is None else '',
        )
    if request_headers is not None:
        wanted_agent = preferences['general.useragent.override']
        actual_agent = request_headers.get('User-Agent')
        add(
            'HTTP user agent', wanted_agent, actual_agent,
            equality_status(wanted_agent, actual_agent),
            'Observed on the local report request.',
        )
    actual_cores = observed['navigator']['hardwareConcurrency']
    cap = preferences['dom.maxHardwareConcurrency']
    wanted_cores = expected['cores']
    core_status = 'unavailable'
    if actual_cores is not None:
        core_status = 'match' if actual_cores == wanted_cores else 'different'
    add(
        'Processor threads', wanted_cores, actual_cores, core_status,
        f'The session persona specifies {wanted_cores} threads. Firefox is capped at {cap} '
        'and may report fewer. This comparison checks the observed value against the persona.',
    )
    wanted_languages = [
        value.strip() for value in preferences['intl.accept_languages'].split(',')
        if value.strip()
    ]
    actual_languages = observed['navigator']['languages']
    language_status = 'unavailable'
    if actual_languages is not None:
        language_status = equality_status(
            [value.lower() for value in wanted_languages],
            [value.lower() for value in actual_languages],
        )
    add('Languages', wanted_languages, actual_languages, language_status)
    wanted_zone = expected.get('timezone')
    actual_zone = observed['timezone']
    aliases = {'Etc/UTC': 'UTC', 'Etc/GMT': 'UTC', 'GMT': 'UTC', 'UTC0': 'UTC'}
    zone_status = equality_status(
        aliases.get(wanted_zone, wanted_zone), aliases.get(actual_zone, actual_zone)
    )
    if zone_status == 'different':
        zone_status = 'info'
    add(
        'Timezone', wanted_zone or 'Desktop timezone', actual_zone, zone_status,
        'Timezone names can have aliases. No browser timezone override is configured.',
    )
    screen = observed['screen']
    actual_dpr = screen['devicePixelRatio']
    dpr_status = 'unavailable'
    if actual_dpr is not None:
        dpr_status = (
            'match' if math.isclose(actual_dpr, expected['dpr'], abs_tol=0.02) else 'info'
        )
    add(
        'Pixel ratio', expected['dpr'], actual_dpr, dpr_status,
        'Page zoom can change this value. Compare at 100% zoom.',
    )
    for label, width, height, wanted, detail in (
        (
            'Screen size', 'width', 'height',
            f"Nominal profile {expected['screen_width']} × {expected['screen_height']}",
            'The active monitor and display scaling affect the reported CSS size. '
            'The nominal profile is not a fixed browser viewport.',
        ),
        (
            'Available screen', 'availWidth', 'availHeight',
            'Current desktop work area', '',
        ),
        (
            'Page viewport', 'innerWidth', 'innerHeight', 'Current browser window',
            'Resizing the window changes this value.',
        ),
    ):
        actual = None
        if screen[width] is not None and screen[height] is not None:
            actual = f'{screen[width]} × {screen[height]} CSS pixels'
        add(label, wanted, actual, 'info' if actual is not None else 'unavailable', detail)
    for name, label, enabled in (
        ('webgl', 'WebGL', not preferences['webgl.disabled']),
        ('webrtc', 'WebRTC', preferences['media.peerconnection.enabled']),
        ('webaudio', 'Web Audio', preferences['dom.webaudio.enabled']),
    ):
        actual = observed['features'][name]
        if actual is None:
            status = 'unavailable'
        elif not enabled:
            status = 'different' if actual else 'blocked'
        else:
            status = 'match' if actual else 'info'
        add(
            label, 'Available' if enabled else 'Disabled by profile',
            None if actual is None else 'Available' if actual else 'Not exposed', status,
            'This checks API availability without contacting another host.',
        )
    candidate_fonts = expected.get('fonts')
    observed_fonts = observed.get('fonts')
    add(
        'Font sample', candidate_fonts or 'Active font sample unavailable',
        observed_fonts,
        'info' if candidate_fonts and observed_fonts is not None else 'unavailable',
        'At most 24 families from the active Fontconfig profile are tested by DOM metrics. '
        'This is a candidate sample, not a complete inventory or proof of font availability.',
    )
    return {
        'mode': expected['mode'], 'collected_at': datetime.now(timezone.utc).isoformat(),
        'browser_version': expected.get('version'), 'edition': expected.get('edition'),
        'rows': rows,
        'scope': 'Local browser values only. No external server, public IP, '
                 'DNS path or uniqueness test.',
    }


class BrowserCheckSession:
    def __init__(self, expected=None):
        if os.geteuid() == 0:
            raise RuntimeError('Run Browser Check as the desktop user, without sudo')
        self.expected = copy.deepcopy(expected) if expected is not None else snapshot_expected()
        self._token = secrets.token_hex(32)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._server = None
        self._thread = None
        self._result = None
        self._error = None
        self._started = False
        self._closed = False
        self._requests = 0
        self._deadline = 0
        self._origin = None
        self._path = '/' + self._token + '/'

    def start(self):
        asset_directory = Path(__file__).with_name('browser_check_assets')
        assets = {
            name: (asset_directory / name).read_bytes()
            for name in ('index.html', 'probe.js', 'style.css')
        }

        with self._lock:
            if self._started or self._closed:
                raise RuntimeError('The browser check session cannot be started again')
            self._started = True
        session = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.0'

            def setup(self):
                super().setup()
                self.connection.settimeout(2)

            def log_message(self, format, *args):
                pass

            def send_result(self, status, payload=b'', content_type='application/json'):
                self.send_response(status)
                self.send_header('Content-Type', content_type)
                self.send_header('Content-Length', str(len(payload)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Referrer-Policy', 'no-referrer')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('X-Frame-Options', 'DENY')
                self.send_header(
                    'Content-Security-Policy',
                    "default-src 'none'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src data:; base-uri 'none'; "
                    "form-action 'none'; frame-ancestors 'none'",
                )
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def allowed(self):
                session._requests += 1
                if session._requests > 64 or time.monotonic() >= session._deadline:
                    session._stop.set()
                    self.send_result(410)
                    return False
                if sum(len(key) + len(value) for key, value in self.headers.items()) > 8192:
                    self.send_result(431)
                    return False
                hosts = self.headers.get_all('Host', [])
                if hosts != [session._origin.removeprefix('http://')]:
                    self.send_result(403)
                    return False
                if self.headers.get('Sec-Fetch-Site') not in (None, 'none', 'same-origin'):
                    self.send_result(403)
                    return False
                return True

            def do_GET(self):
                if not self.allowed():
                    return
                if self.path == session._path:
                    self.send_result(200, assets['index.html'], 'text/html; charset=utf-8')
                elif self.path == session._path + 'config':
                    payload = json.dumps({'font_families': session.expected.get('fonts') or []})
                    self.send_result(200, payload.encode('utf-8'))
                elif self.path == session._path + 'probe.js':
                    self.send_result(200, assets['probe.js'], 'application/javascript; charset=utf-8')
                elif self.path == session._path + 'style.css':
                    self.send_result(200, assets['style.css'], 'text/css; charset=utf-8')
                else:
                    self.send_result(404)

            def do_POST(self):
                if not self.allowed():
                    return
                if self.path != session._path + 'result':
                    self.send_result(404)
                    return
                if (
                    self.headers.get_all('Origin', []) != [session._origin]
                    or self.headers.get_all('Content-Type', []) != ['application/json']
                    or self.headers.get_all('Transfer-Encoding', [])
                ):
                    self.send_result(403)
                    return
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,6}', lengths[0]):
                    self.send_result(400)
                    return
                length = int(lengths[0])
                if not 0 < length <= MAX_REPORT_BYTES:
                    self.send_result(413)
                    return
                try:
                    payload = self.rfile.read(length)
                    if len(payload) != length:
                        raise ValueError('Incomplete report')
                    observed = validate_observed(payload.decode('utf-8', 'strict'))
                    report = compare_observed(session.expected, observed, self.headers)
                except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                    self.send_result(400)
                    return
                with session._lock:
                    if session._result is not None or session._closed:
                        self.send_result(410)
                        return
                    session._result = report
                response = json.dumps({'ok': True, **report}, ensure_ascii=True)
                self.send_result(200, response.encode('utf-8'))
                session._stop.set()

        class QuietServer(HTTPServer):
            def handle_error(self, request, client_address):
                pass

        server = QuietServer(('127.0.0.1', 0), Handler)
        server.timeout = 0.2
        self._server = server
        self._origin = f'http://127.0.0.1:{server.server_port}'
        self._deadline = time.monotonic() + SESSION_SECONDS
        self._thread = threading.Thread(target=self._serve, daemon=True, name='ph4ntxm-browser-check')
        self._thread.start()
        return self._origin + self._path

    def _serve(self):
        try:
            while not self._stop.is_set() and time.monotonic() < self._deadline:
                self._server.handle_request()
            with self._lock:
                if self._result is None and not self._closed:
                    self._error = 'The browser check timed out. Open the browser tab and try again.'
        except (OSError, ValueError):
            with self._lock:
                if not self._closed:
                    self._error = 'The local browser check could not complete'
        finally:
            self._server.server_close()

    def poll(self):
        with self._lock:
            if self._error:
                raise RuntimeError(self._error)
            return copy.deepcopy(self._result)

    def close(self):
        with self._lock:
            self._closed = True
        self._stop.set()
        if self._server is not None:
            self._server.server_close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=0.3)
