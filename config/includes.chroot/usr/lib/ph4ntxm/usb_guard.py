# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile
import time

STATE = Path('/run/ph4ntxm-usb-guard')
STATE_FILE = STATE / 'session.json'
UNIT = 'ph4ntxm-usb-guard.service'
CLIENT = '/usr/local/sbin/ph4ntxm-usb-guard-client'
MANIFEST = '/usr/lib/ph4ntxm/usb-guard.sha256'
CONTROLLERS = Path('/sys/bus/usb/devices')
CONFIG = '/etc/ph4ntxm-usb-guard.conf'
SAFE_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
OPTIONS = {
    'ImplicitPolicyTarget': 'block', 'PresentDevicePolicy': 'keep',
    'PresentControllerPolicy': 'keep', 'InsertedDevicePolicy': 'block',
    'AuthorizedDefault': 'none', 'RestoreControllerDeviceState': 'false',
    'DeviceManagerBackend': 'uevent', 'IPCAllowedUsers': 'root',
    'HidePII': 'true', 'AuditBackend': 'FileAudit',
    'AuditFilePath': '/run/ph4ntxm-usb-guard/audit.log',
}


class GuardError(Exception):
    pass


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError('Invalid USB Guard data.')
        result[key] = value
    return result


def decode_json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=strict_object)


def protected_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise GuardError('USB Guard storage is not protected.')


def protected_read(path, maximum=65536):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > maximum:
            raise GuardError('USB Guard files are not protected.')
        data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise GuardError('USB Guard data exceeds its limit.')
        return data


def run(argv, payload=None, timeout=8):
    try:
        result = subprocess.run(argv, input=payload, stdin=subprocess.DEVNULL if payload is None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=SAFE_ENV,
                                timeout=timeout, check=False, close_fds=True)
    except subprocess.TimeoutExpired as error:
        raise GuardError('USB Guard did not respond in time.') from error
    if len(result.stdout) > 524288:
        raise GuardError('USB Guard response exceeds its limit.')
    return result


def service_info():
    result = run(['/usr/bin/systemctl', 'show', '--no-pager',
                  '--property=ActiveState,SubState,MainPID,InvocationID', UNIT], timeout=5)
    if result.returncode:
        raise GuardError('USB Guard service state is unavailable.')
    fields = {}
    for line in result.stdout.decode('ascii').splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in fields:
            raise GuardError('USB Guard service state is invalid.')
        fields[key] = value
    if set(fields) != {'ActiveState', 'SubState', 'MainPID', 'InvocationID'} or not fields['MainPID'].isdigit():
        raise GuardError('USB Guard service state is invalid.')
    generation = fields['InvocationID']
    if generation and not re.fullmatch('[0-9a-f]{32}', generation):
        raise GuardError('USB Guard service identity is invalid.')
    return {'state': fields['ActiveState'], 'pid': int(fields['MainPID']), 'generation': generation}


def controller_records():
    records = []
    for entry in sorted(CONTROLLERS.glob('usb*')):
        if not re.fullmatch('usb[1-9][0-9]*', entry.name):
            continue
        path = entry.resolve(strict=True)
        if not str(path).startswith('/sys/devices/'):
            raise GuardError('USB controller path is invalid.')
        with contextlib.ExitStack() as stack:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if info.st_uid != 0:
                raise GuardError('USB controller ownership is invalid.')
            value_fd = os.open('authorized_default', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            stack.callback(os.close, value_fd)
            value = os.read(value_fd, 16).decode('ascii').strip()
            if value not in {'0', '1', '2'}:
                raise GuardError('USB controller policy is unavailable.')
            records.append({'path': str(path), 'dev': info.st_dev, 'ino': info.st_ino, 'value': value})
    if len(records) > 128:
        raise GuardError('USB controller count exceeds its limit.')
    return records


def validate_records(records):
    if not isinstance(records, list) or len(records) > 128:
        raise GuardError('Saved USB controller state is invalid.')
    seen = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {'path', 'dev', 'ino', 'value'}:
            raise GuardError('Saved USB controller state is invalid.')
        path = record['path']
        if not isinstance(path, str) or len(path) > 4096 or not path.startswith('/sys/devices/') or '..' in Path(path).parts or not re.fullmatch('usb[1-9][0-9]*', Path(path).name) or path in seen:
            raise GuardError('Saved USB controller path is invalid.')
        if any(type(record[key]) is not int or record[key] < 0 for key in ['dev', 'ino']) or record['value'] not in {'0', '1', '2'}:
            raise GuardError('Saved USB controller state is invalid.')
        seen.add(path)
    return records


def load_state():
    if not STATE.exists():
        return None
    protected_directory(STATE)
    try:
        data = decode_json(protected_read(STATE_FILE))
    except FileNotFoundError:
        return None
    if not isinstance(data, dict) or set(data) != {'controllers'}:
        raise GuardError('Saved USB Guard state is invalid.')
    return {'controllers': validate_records(data['controllers'])}


def save_state(records):
    validate_records(records)
    descriptor, name = tempfile.mkstemp(prefix='session-', dir=STATE)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write((json.dumps({'controllers': records}) + '\n').encode())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, STATE_FILE)
    finally:
        Path(name).unlink(missing_ok=True)


@contextlib.contextmanager
def state_lock():
    protected_directory(Path('/run'))
    if STATE.is_symlink():
        raise GuardError('USB Guard storage is not protected.')
    STATE.mkdir(mode=0o700, exist_ok=True)
    protected_directory(STATE)
    STATE.chmod(0o700)
    descriptor = os.open(STATE / 'control.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise GuardError('USB Guard lock is not protected.')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise GuardError('USB Guard is busy. Try again.') from error
        yield
    finally:
        os.close(descriptor)


def validate_installation():
    config = protected_read(CONFIG, 4096).decode('ascii')
    settings = {}
    for line in config.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in settings:
            raise GuardError('USB Guard configuration is invalid.')
        settings[key] = value
    if settings != OPTIONS:
        raise GuardError('USB Guard configuration does not match the protected policy.')
    manifest = protected_read(MANIFEST, 256).decode('ascii')
    match = re.fullmatch(r'([0-9a-f]{64})  /usr/local/sbin/ph4ntxm-usb-guard-client\n', manifest)
    if not match or hashlib.sha256(protected_read(CLIENT, 16777216)).hexdigest() != match[1]:
        raise GuardError('USB Guard client verification failed.')


def native_snapshot():
    result = run([CLIENT, 'snapshot'])
    data = decode_json(result.stdout)
    if result.returncode or not isinstance(data, dict) or data.get('ok') is not True:
        raise GuardError('USB device inspection is unavailable.')
    if data.get('inserted_policy') != 'block' or data.get('implicit_target') != 'block' or not isinstance(data.get('devices'), list) or len(data['devices']) > 512:
        raise GuardError('USB Guard blocking policy could not be verified.')
    return data


def device_view(device):
    if not isinstance(device, dict):
        raise GuardError('USB device metadata is invalid.')
    identifier = device.get('id')
    if type(identifier) is not int or not 1 <= identifier <= 0xfffffffe:
        raise GuardError('USB device identity is invalid.')
    identity_hex = device.get('identity_hex')
    name_hex = device.get('name_hex')
    if not isinstance(identity_hex, str) or not 2 <= len(identity_hex) <= 131072 or len(identity_hex) % 2 or not re.fullmatch('[0-9a-f]+', identity_hex):
        raise GuardError('USB device identity is invalid.')
    if not isinstance(name_hex, str) or len(name_hex) > 506 or len(name_hex) % 2 or name_hex and not re.fullmatch('[0-9a-f]+', name_hex):
        raise GuardError('USB device name is invalid.')
    name = bytes.fromhex(name_hex).decode('utf-8', 'replace')
    name = ''.join(c if c.isprintable() else ' ' for c in name).strip()[:160] or 'USB device'
    interfaces = device.get('interfaces')
    if not isinstance(interfaces, list) or len(interfaces) > 256 or any(not isinstance(i, str) or not re.fullmatch('[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}', i) for i in interfaces):
        raise GuardError('USB device functions are invalid.')
    target = device.get('target')
    device_id = device.get('device_id')
    port = device.get('port')
    if target not in {'allow', 'block', 'reject'} or not isinstance(device_id, str) or not re.fullmatch('[0-9a-fA-F]{4}:[0-9a-fA-F]{4}', device_id) or not isinstance(port, str) or len(port) > 256 or not re.fullmatch(r'(usb[1-9][0-9]*|[1-9][0-9]*-[1-9][0-9]*(\.[1-9][0-9]*)*)', port):
        raise GuardError('USB device attributes are invalid.')
    reason = device.get('approval_reason')
    messages = {'': '', 'root_controller': 'USB host controller', 'unavailable_identity': 'Device identity could not be verified', 'unavailable_interfaces': 'Device functions could not be verified', 'sensor_device': 'Audio/video functions are disabled by the sensor policy', 'not_blocked': ''}
    if reason not in messages or type(device.get('approval_allowed')) is not bool:
        raise GuardError('USB device approval state is invalid.')
    can_allow = device['approval_allowed'] and target == 'block' and bool(interfaces) and not port.startswith('usb') and all(int(i[:2], 16) not in {0, 1, 14, 16} for i in interfaces) and reason == ''
    return {'id': identifier, 'identity': hashlib.sha256(bytes.fromhex(identity_hex)).hexdigest(), 'name': name,
            'vendor_id': device_id.lower(), 'port': port, 'interfaces': [i.lower() for i in interfaces], 'state': target,
            'can_allow': can_allow, 'controller': reason == 'root_controller' or port.startswith('usb'), 'restriction': messages[reason]}


def snapshot():
    state = load_state()
    info = service_info()
    response = {'ok': True, 'state': 'off', 'enabled': state is not None, 'generation': '',
                'message': 'Enable USB Guard before connecting a new USB device.', 'devices': []}
    if state is None and info['state'] in {'inactive', 'failed'}:
        return response
    response.update(state='degraded', message='USB Guard protection could not be verified. Approvals are unavailable.')
    if info['state'] == 'activating':
        response.update(state='starting', message='USB Guard is starting. Approvals will become available when protection is ready.')
        return response
    if state is None or info['state'] != 'active' or info['pid'] < 1 or not info['generation']:
        return response
    controllers = controller_records()
    if not controllers or any(c['value'] != '0' for c in controllers):
        return response
    data = native_snapshot()
    after = service_info()
    if after != info:
        raise GuardError('USB Guard restarted during inspection. Refresh the device list.')
    devices = [device_view(d) for d in data['devices']]
    if len({d['id'] for d in devices}) != len(devices):
        raise GuardError('USB device list is invalid.')
    response.update(state='ready', enabled=True, generation=info['generation'],
                    message='New USB connections stay blocked until approved. Connected devices remain available.', devices=devices)
    return response


def prepare():
    if load_state() is not None:
        return
    with state_lock():
        if load_state() is None:
            save_state(controller_records())


def enable():
    if load_state() is None:
        save_state(controller_records())
    if service_info()['state'] == 'failed':
        if run(['/usr/bin/systemctl', 'reset-failed', UNIT], timeout=5).returncode:
            raise GuardError('USB Guard could not reset its service state.')
    if run(['/usr/bin/systemctl', 'start', UNIT], timeout=20).returncode:
        raise GuardError('USB Guard could not start. Controller defaults remain protected where already sealed.')
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            status = snapshot()
            if status['state'] == 'ready':
                return status
        except GuardError:
            pass
        time.sleep(0.2)
    raise GuardError('USB Guard did not become ready. Check its status before connecting devices.')


def restore_controller(record):
    try:
        fd = os.open(record['path'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_dev != record['dev'] or info.st_ino != record['ino']:
            raise GuardError('A USB controller changed before its defaults could be restored.')
        value_fd = os.open('authorized_default', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            value = (record['value'] + '\n').encode()
            if os.write(value_fd, value) != len(value):
                raise GuardError('A USB controller default could not be restored.')
        finally:
            os.close(value_fd)
    finally:
        os.close(fd)


def disable():
    state = load_state()
    if state is None:
        return snapshot()
    if run(['/usr/bin/systemctl', 'stop', UNIT], timeout=15).returncode or service_info()['state'] not in {'inactive', 'failed'}:
        raise GuardError('USB Guard could not stop. Controller defaults have not been released.')
    errors = []
    for record in state['controllers']:
        try:
            restore_controller(record)
        except (OSError, GuardError):
            errors.append(record['path'])
    saved = {(c['path'], c['dev'], c['ino']) for c in state['controllers']}
    if any((c['path'], c['dev'], c['ino']) not in saved and c['value'] == '0' for c in controller_records()):
        errors.append('new_controller')
    if errors:
        raise GuardError('USB Guard is partially disabled. Some controller defaults could not be restored. Retry Disable or reboot.')
    STATE_FILE.unlink()
    return snapshot()


def approve(request):
    if not isinstance(request, dict) or set(request) != {'generation', 'id', 'identity'} or type(request['id']) is not int or not 1 <= request['id'] <= 0xfffffffe or not isinstance(request['generation'], str) or not re.fullmatch('[0-9a-f]{32}', request['generation']) or not isinstance(request['identity'], str) or not re.fullmatch('[0-9a-f]{64}', request['identity']):
        raise GuardError('Invalid USB approval request.')
    current = snapshot()
    if current['state'] != 'ready' or current['generation'] != request['generation']:
        raise GuardError('USB Guard changed. Refresh the device list and approve again.')
    selected = next((d for d in current['devices'] if d['id'] == request['id'] and d['identity'] == request['identity']), None)
    if selected is None or not selected['can_allow']:
        raise GuardError('This USB device cannot be approved from the current selection.')
    raw = native_snapshot()
    original = next((d for d in raw['devices'] if d['id'] == request['id'] and device_view(d)['identity'] == request['identity']), None)
    if original is None or service_info()['generation'] != request['generation']:
        raise GuardError('USB device changed. Refresh the list and approve again.')
    result = run([CLIENT, 'allow', str(request['id'])], payload=(original['identity_hex'] + '\n').encode('ascii'))
    answer = decode_json(result.stdout)
    if result.returncode or not isinstance(answer, dict) or answer.get('ok') is not True:
        raise GuardError('The USB device was not approved. Refresh the list and try again.')
    status = snapshot()
    confirmed = next((d for d in status['devices'] if d['id'] == request['id'] and d['identity'] == request['identity'] and d['state'] == 'allow'), None)
    if status['state'] != 'ready' or status['generation'] != request['generation'] or confirmed is None:
        raise GuardError('USB approval could not be confirmed. Refresh the device list.')
    return status


def main(argv):
    if os.geteuid() != 0 or len(argv) != 1 or argv[0] not in {'snapshot', 'enable', 'disable', 'allow', 'prepare'}:
        return 2
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    ctypes.CDLL(None).prctl(4, 0, 0, 0, 0)
    validate_installation()
    action = argv[0]
    if action == 'prepare':
        prepare()
        return 0
    if action == 'snapshot':
        result = snapshot()
    else:
        with state_lock():
            if action == 'enable':
                result = enable()
            elif action == 'disable':
                result = disable()
            else:
                raw = sys.stdin.buffer.read(4097)
                if len(raw) > 4096 or not raw.endswith(b'\n'):
                    raise GuardError('USB approval request exceeds its limit or is incomplete.')
                result = approve(decode_json(raw))
    print(json.dumps(result, ensure_ascii=True))
    return 0


def entry():
    try:
        return main(sys.argv[1:])
    except (GuardError, OSError, ValueError, UnicodeError, RecursionError, TypeError, KeyError):
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, GuardError) else 'USB Guard could not complete the request.'
        print(json.dumps({'ok': False, 'error': message}))
        return 1
