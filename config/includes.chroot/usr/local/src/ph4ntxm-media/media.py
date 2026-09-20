#!/usr/bin/env python3
# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import argparse
import configparser
import ctypes
import fcntl
import json
import os
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree as ET

LIB = Path('/usr/local/lib/ph4ntxm-media')
EXEC = Path('/usr/local/libexec/ph4ntxm-media')
KINDS = {'image': 'ristretto', 'video': 'parole'}
TITLES = {'image': 'PH4NTXM Image Viewer', 'video': 'PH4NTXM Media Player'}
MAX_FILES = 32
MAX_IMAGE_BYTES = 128 * 1024 * 1024
RESERVE = 192 * 1024 * 1024


class MediaError(Exception):
    pass


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=kwargs.pop('timeout', 10), **kwargs)


def local_file(value):
    if value.startswith('file:'):
        uri = urlsplit(value)
        if uri.netloc not in ('', 'localhost') or uri.query or uri.fragment:
            raise MediaError('Choose a local file.')
        value = unquote(uri.path)
    elif re.match(r'^[A-Za-z][A-Za-z0-9+.-]*:', value):
        raise MediaError('Online addresses are not supported.')
    path = Path(value).expanduser().resolve(strict=True)
    if str(path).startswith(('/proc/', '/sys/', '/dev/', '/run/user/')):
        raise MediaError('Choose a regular media file.')
    return path


def open_files(values, kind):
    if not 1 <= len(values) <= MAX_FILES:
        raise MediaError('Choose between one and 32 files.')
    opened = []
    try:
        for value in values:
            path = local_file(value)
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
            opened.append((path, fd))
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
                raise MediaError('Choose a non-empty regular media file.')
            if kind == 'image' and info.st_size > MAX_IMAGE_BYTES:
                raise MediaError('Images must be smaller than 128 MiB.')
        return opened
    except BaseException:
        for _, fd in opened:
            os.close(fd)
        raise


def runtime_directory():
    path = Path('/run/user') / str(os.getuid())
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise MediaError('A private desktop runtime directory is required.')
    result = command(['/usr/bin/findmnt', '-n', '-o', 'FSTYPE', '-T', str(path)], capture_output=True, text=True)
    if result.stdout.strip() != 'tmpfs':
        raise MediaError('Temporary media storage must reside in RAM.')
    return path


def memory_limit(kind):
    memory = dict(re.findall(r'^(\w+):\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M))
    available = int(memory['MemAvailable']) * 1024
    limit = min(512 if kind == 'image' else 768, (available - RESERVE) // (1024 * 1024))
    if limit < (192 if kind == 'image' else 256):
        raise MediaError('Not enough available RAM. Close another application and try again.')
    return limit * 1024 * 1024


def filter_fd():
    data = command([str(EXEC / 'filter')], capture_output=True).stdout
    if not data or len(data) % 8 or len(data) > 32768:
        raise MediaError('The media syscall filter is invalid.')
    fd = os.memfd_create('ph4ntxm-media-filter', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    return fd


def sandbox(filter_number):
    args = [str(EXEC / 'bwrap'), '--unshare-all', '--die-with-parent', '--new-session',
            '--cap-drop', 'ALL', '--clearenv', '--hostname', 'media',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/sbin', '/sbin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--dir', '/proc', '--dev', '/dev',
            '--size', str(64 * 1024 * 1024), '--tmpfs', '/tmp',
            '--size', str(32 * 1024 * 1024), '--tmpfs', '/run',
            '--size', str(32 * 1024 * 1024), '--tmpfs', '/home/viewer',
            '--dir', '/etc', '--dir', '/media', '--dir', '/var/cache',
            '--tmpfs', '/usr/share/dbus-1/services', '--chdir', '/home/viewer',
            '--seccomp', str(filter_number)]
    for path in ['/etc/fonts', '/etc/ld.so.cache', '/etc/alternatives', '/var/cache/fontconfig']:
        if Path(path).exists():
            args += ['--ro-bind', path, path]
    env = {'PATH': '/usr/bin:/bin', 'HOME': '/home/viewer', 'LANG': 'C.UTF-8',
           'XDG_RUNTIME_DIR': '/run', 'XDG_CONFIG_HOME': '/home/viewer/.config',
           'XDG_CACHE_HOME': '/home/viewer/.cache', 'XDG_DATA_HOME': '/home/viewer/.local/share',
           'XDG_CONFIG_DIRS': '/config/xdg', 'NO_AT_BRIDGE': '1',
           'GDK_BACKEND': 'x11', 'LIBGL_ALWAYS_SOFTWARE': 'true', 'GDK_GL': 'disable',
           'GIO_USE_VFS': 'local', 'GIO_USE_VOLUME_MONITOR': 'unix'}
    for key, value in env.items():
        args += ['--setenv', key, value]
    return args


def ready(kind):
    if os.getuid() == 0:
        raise MediaError('Open the viewer from the normal desktop account.')
    for path in [EXEC / 'bwrap', EXEC / 'filter', EXEC / KINDS[kind],
                 EXEC / 'Xephyr', Path('/usr/bin/xfwm4'), EXEC / 'wmctrl']:
        if not os.access(path, os.X_OK):
            raise MediaError('A media runtime component is missing. Rebuild the image.')
    runtime_directory()
    fd = filter_fd()
    try:
        command(sandbox(fd) + ['/usr/bin/python3', '-c',
            "import socket,os;\nfor family in (socket.AF_INET,socket.AF_INET6):\n"
            " try: socket.socket(family)\n except PermissionError: pass\n"
            " else: raise SystemExit('Network filter is not active')\n"
            "assert not os.listdir('/proc')\n"
            "assert not os.path.exists('/run/user')\nassert not os.path.exists('/dev/dri')\n"
            "assert not os.path.exists('/tmp/.X11-unix/X0')"],
            pass_fds=(fd,), capture_output=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode(errors='replace').strip() if exc.stderr else 'namespace or syscall-filter setup failed'
        raise MediaError('Media isolation is unavailable: ' + detail[-1000:]) from exc
    finally:
        os.close(fd)
    command(['/usr/bin/systemctl', '--user', 'show-environment'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def authority(number, cookie):
    values = [b'', str(number).encode(), b'MIT-MAGIC-COOKIE-1', cookie]
    return struct.pack('>H', 65535) + b''.join(struct.pack('>H', len(x)) + x for x in values)


def write_channel(directory, name, entries):
    root = ET.Element('channel', name=name, version='1.0')
    for path, kind, value in entries:
        node = root
        parts = path.split('/')
        for part in parts[:-1]:
            child = next((x for x in node if x.get('name') == part), None)
            if child is None:
                child = ET.SubElement(node, 'property', name=part, type='empty')
            node = child
        ET.SubElement(node, 'property', name=parts[-1], type=kind, value=str(value))
    directory.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(root).write(directory / (name + '.xml'), encoding='utf-8', xml_declaration=True)


def configure(path, settings, display_number=100):
    path.mkdir(mode=0o700)
    home = path / 'home'
    gtk = home / 'gtk-3.0'
    gtk.mkdir(parents=True)
    ini = configparser.ConfigParser(interpolation=None)
    ini['Settings'] = {key: str(settings.get_property(key)) for key in
                       ['gtk-theme-name', 'gtk-icon-theme-name', 'gtk-font-name']}
    ini['Settings']['gtk-recent-files-enabled'] = 'false'
    with (gtk / 'settings.ini').open('w') as stream:
        ini.write(stream)
    channels = home / 'xfce4/xfconf/xfce-perchannel-xml'
    theme = settings.get_property('gtk-theme-name')
    write_channel(channels, 'xfwm4', [('general/theme', 'string', theme),
                  ('general/use_compositing', 'bool', 'false'),
                  ('general/borderless_maximize', 'bool', 'true'),
                  ('general/titleless_maximize', 'bool', 'true'),
                  ('general/workspace_count', 'int', 1)])
    write_channel(channels, 'parole', [('video/videosink', 'string', 'ximagesink'),
                  ('video/enable-xv', 'bool', 'false'), ('playlist/remember-playlist', 'bool', 'false')])
    write_channel(channels, 'ristretto', [('errors/missing-thumbnailer', 'bool', 'false'),
                  ('window/thumbnails/show', 'bool', 'false')])
    (path / 'nested.auth').write_bytes(authority(display_number, os.urandom(16)))
    (path / 'display').write_text(':%d' % display_number)
    (path / 'passwd').write_text('viewer:x:%d:%d:Viewer:/home/viewer:/bin/false\n' % (os.getuid(), os.getgid()))
    (path / 'group').write_text('viewer:x:%d:\n' % os.getgid())
    (path / 'machine-id').write_text(uuid.uuid4().hex + '\n')
    (path / 'dbus.conf').write_text('<busconfig><type>session</type><listen>unix:path=/run/bus</listen>'
        '<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
        '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>\n')
    pulse = home / 'pulse'
    pulse.mkdir()
    (pulse / 'cookie').write_bytes(os.urandom(256))
    (pulse / 'client.conf').write_text('autospawn=no\nenable-shm=no\n')
    (pulse / 'daemon.conf').write_text('high-priority=no\nrealtime-scheduling=no\n'
        'enable-shm=no\nuse-pid-file=no\nexit-idle-time=-1\nallow-exit=no\n'
        'allow-module-loading=no\ndefault-sample-rate=48000\ndefault-sample-channels=2\n')
    (path / 'pulse.pa').write_text('load-module module-pipe-sink sink_name=output file=/run/audio/pcm '
        'format=s16le rate=48000 channels=2\n'
        'load-module module-native-protocol-unix socket=/run/pulse/native auth-anonymous=1\n'
        'set-default-sink output\n')


def configured(args, config):
    args += ['--ro-bind', str(config), '/config']
    for name in ['passwd', 'group', 'machine-id']:
        args += ['--ro-bind', str(config / name), '/etc/' + name]
    return args


def wait_socket(path, process):
    for _ in range(150):
        if process.poll() is not None:
            raise MediaError('An isolated media component could not start.')
        try:
            if stat.S_ISSOCK(path.stat().st_mode):
                return
        except FileNotFoundError:
            pass
        time.sleep(0.04)
    raise MediaError('The isolated display or audio service did not become ready.')


def inside(kind, files):
    shutil.copytree('/config/home', '/home/viewer/.config', dirs_exist_ok=True)
    os.environ.update(DISPLAY=Path('/config/display').read_text(), XAUTHORITY='/config/nested.auth',
                      DBUS_SESSION_BUS_ADDRESS='unix:path=/run/bus',
                      PULSE_SERVER='unix:/run/pulse/native', GST_REGISTRY_UPDATE='yes')
    children = []
    def spawn(args):
        p = subprocess.Popen(args, stdin=subprocess.DEVNULL)
        children.append(p)
        return p
    try:
        bus = spawn(['/usr/bin/dbus-daemon', '--nofork', '--config-file=/config/dbus.conf'])
        wait_socket(Path('/run/bus'), bus)
        xfconf = next(Path('/usr/lib').glob('*/xfce4/xfconf/xfconfd'))
        spawn([str(xfconf)])
        spawn(['/usr/bin/xfwm4', '--compositor=off', '--sm-client-disable'])
        if kind == 'video':
            Path('/run/pulse').mkdir(mode=0o700)
            pulse = spawn(['/usr/bin/pulseaudio', '-n', '--file=/config/pulse.pa', '--daemonize=no',
                           '--use-pid-file=no', '--disable-shm', '--log-target=stderr'])
            wait_socket(Path('/run/pulse/native'), pulse)
        player = spawn([str(EXEC / KINDS[kind]), '--', *files])
        maximized = False
        while player.poll() is None:
            if not maximized:
                result = subprocess.run([str(EXEC / 'wmctrl'), '-lx'], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    if KINDS[kind] in line.lower():
                        command([str(EXEC / 'wmctrl'), '-i', '-r', line.split()[0], '-b',
                                 'add,maximized_vert,maximized_horz'], stdout=subprocess.DEVNULL)
                        maximized = True
                        break
            time.sleep(0.15)
        return player.returncode
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()


def session(kind, directory, values=None):
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('GdkX11', '3.0')
    from gi.repository import Gtk, GdkX11, GLib

    group = next(x.split(':', 2)[2] for x in Path('/proc/self/cgroup').read_text().splitlines() if x.startswith('0::'))
    cgroup = Path('/sys/fs/cgroup') / group.lstrip('/')
    if (cgroup / 'memory.max').read_text().strip() == 'max' or (cgroup / 'memory.swap.max').read_text().strip() != '0':
        raise MediaError('The media memory limits are not active.')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024 * 1024, 8 * 1024 * 1024))
    directory = Path(directory)
    if values is None:
        request = directory / 'request.json'
        with request.open('rb') as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise MediaError('The media request is too large.')
        values = json.loads(data)
        request.unlink()
        if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
            raise MediaError('The media request is invalid.')
    config = directory / 'config'
    display = re.fullmatch(r':(\d+)(?:\.\d+)?', os.environ.get('DISPLAY', ''))
    if not display:
        raise MediaError('A local X11 desktop is required.')
    number = int(display.group(1))
    nested = 100 if number != 100 else 101
    configure(config, Gtk.Settings.get_default(), nested)
    host_socket = Path('/tmp/.X11-unix/X%d' % number)
    if not host_socket.is_socket():
        raise MediaError('The desktop display socket is unavailable.')
    auth_path = Path(os.environ.get('XAUTHORITY') or str(Path.home() / '.Xauthority'))
    with auth_path.open('rb') as stream:
        data = stream.read(1024 * 1024 + 1)
    if not data or len(data) > 1024 * 1024:
        raise MediaError('The desktop display credentials are unavailable.')
    host_auth = directory / 'host.auth'
    host_auth.write_bytes(data)
    sockets = directory / 'x11'
    sockets.mkdir(mode=0o700)
    audio = directory / 'audio'
    audio.mkdir(mode=0o700)
    opened = open_files(values, kind)
    fd = filter_fd()
    log = (directory / 'session.log').open('wb')
    children = []
    descriptors = [fd]
    status = [0]
    def spawn(args, extra_fds=(), **kwargs):
        child_filter = os.open('/proc/self/fd/%d' % fd, os.O_RDONLY | os.O_CLOEXEC)
        args = list(args)
        args[args.index('--seccomp') + 1] = str(child_filter)
        try:
            p = subprocess.Popen(args, pass_fds=(child_filter, *extra_fds), stdin=kwargs.pop('stdin', subprocess.DEVNULL),
                                 stdout=log, stderr=log, **kwargs)
        finally:
            os.close(child_filter)
        children.append(p)
        return p
    window = Gtk.Window(title=TITLES[kind])
    window.set_icon_name('ph4ntxm-image-viewer' if kind == 'image' else 'ph4ntxm-video-viewer')
    window.set_position(Gtk.WindowPosition.CENTER)
    screen = window.get_screen()
    xlib = ctypes.CDLL('libX11.so.6')
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XDefaultVisual.argtypes = [ctypes.c_void_p, ctypes.c_int]
    xlib.XDefaultVisual.restype = ctypes.c_void_p
    xlib.XVisualIDFromVisual.argtypes = [ctypes.c_void_p]
    xlib.XVisualIDFromVisual.restype = ctypes.c_ulong
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xlib.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                               ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)),
                               ctypes.POINTER(ctypes.c_uint)]
    xlib.XMoveResizeWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                                     ctypes.c_uint, ctypes.c_uint]
    xlib.XFlush.argtypes = [ctypes.c_void_p]
    xlib.XFree.argtypes = [ctypes.c_void_p]
    connection = xlib.XOpenDisplay(None)
    if not connection:
        raise MediaError('The desktop display could not be opened.')
    visual_id = xlib.XVisualIDFromVisual(xlib.XDefaultVisual(connection, screen.get_number()))
    visual = GdkX11.X11Screen.lookup_visual(screen, visual_id)
    window.set_visual(visual)
    work = screen.get_monitor_workarea(screen.get_primary_monitor())
    width, height = min(1000, max(480, work.width - 100)), min(680, max(320, work.height - 100))
    window.set_default_size(width, height)
    canvas = Gtk.DrawingArea()
    canvas.set_visual(visual)
    window.add(canvas)
    window.connect('destroy', lambda *_: Gtk.main_quit())
    window.show_all()
    canvas.get_display().sync()
    try:
        parent = GdkX11.X11Window.get_xid(canvas.get_window())
        display_args = configured(sandbox(fd), config)
        display_args += ['--bind', str(sockets), '/tmp/.X11-unix',
                         '--ro-bind', str(host_socket), '/tmp/.X11-unix/X%d' % number,
                         '--ro-bind', str(host_auth), '/run/host.auth',
                         '--setenv', 'DISPLAY', ':%d' % number, '--setenv', 'XAUTHORITY', '/run/host.auth',
                         str(EXEC / 'Xephyr'), ':%d' % nested, '-parent', str(parent), '-screen', '%dx%d' % (width, height),
                         '-resizeable', '-nolisten', 'tcp', '-no-host-grab',
                         '-auth', '/config/nested.auth', '-extension', 'GLX', '-extension', 'XTEST', '-noreset']
        display_process = spawn(display_args)
        wait_socket(sockets / ('X%d' % nested), display_process)
        root_id, parent_id = ctypes.c_ulong(), ctypes.c_ulong()
        windows = ctypes.POINTER(ctypes.c_ulong)()
        count = ctypes.c_uint()
        display_window = 0
        for _ in range(150):
            if display_process.poll() is not None:
                break
            if not xlib.XQueryTree(connection, parent, ctypes.byref(root_id), ctypes.byref(parent_id),
                                   ctypes.byref(windows), ctypes.byref(count)):
                break
            try:
                if count.value > 1:
                    break
                if count.value == 1:
                    display_window = windows[0]
                    break
            finally:
                xlib.XFree(windows)
            time.sleep(0.02)
        if not display_window:
            raise MediaError('The isolated display window is unavailable.')
        def resize_display(widget, allocation):
            if display_process.poll() is None:
                xlib.XMoveResizeWindow(connection, display_window, 0, 0,
                                      max(1, allocation.width), max(1, allocation.height))
                xlib.XFlush(connection)
        canvas.connect('size-allocate', resize_display)
        resize_display(canvas, canvas.get_allocation())
        args = configured(sandbox(fd), config)
        args += ['--ro-bind', str(sockets / ('X%d' % nested)), '/tmp/.X11-unix/X%d' % nested]
        names = []
        for index, (path, file_fd) in enumerate(opened):
            name = '/media/%02d-%s' % (index + 1, path.name)
            args += ['--ro-bind', '/proc/self/fd/%d' % file_fd, name]
            names.append(name)
        if kind == 'video':
            pipe = audio / 'pcm'
            os.mkfifo(pipe, 0o600)
            read_fd = os.open(pipe, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            hold_fd = os.open(pipe, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
            os.set_blocking(read_fd, True)
            descriptors += [read_fd, hold_fd]
            pulse_socket = runtime_directory() / 'pulse/native'
            if not pulse_socket.is_socket():
                raise MediaError('The desktop audio service is unavailable.')
            output = sandbox(fd) + ['--ro-bind', str(pulse_socket), '/run/pulse/native',
                '--ro-bind', str(config / 'home/pulse/client.conf'), '/etc/pulse/client.conf',
                '--ro-bind', str(config / 'home/pulse/cookie'), '/etc/pulse/cookie',
                '--setenv', 'PULSE_COOKIE', '/etc/pulse/cookie',
                '--setenv', 'PULSE_SERVER', 'unix:/run/pulse/native',
                '/usr/bin/pacat', '--playback', '--raw', '--format=s16le', '--rate=48000',
                '--channels=2', '--latency-msec=80', '--client-name=PH4NTXM Media', '--stream-name=Playback']
            audio_process = spawn(output, stdin=read_fd)
            args += ['--bind', str(audio), '/run/audio']
        else:
            audio_process = None
        player = spawn(args + ['/usr/bin/python3', str(LIB / 'media.py'), '--inside', kind, *names],
                       extra_fds=tuple(x[1] for x in opened))
        def poll():
            failed = display_process.poll() is not None or (audio_process is not None and audio_process.poll() is not None)
            if failed or player.poll() is not None:
                status[0] = 1 if failed else player.returncode
                if status[0]:
                    print('Media component status: display=%s audio=%s viewer=%s' % (
                        display_process.poll(), audio_process.poll() if audio_process else None,
                        player.poll()), file=sys.stderr)
                window.destroy()
                return False
            return True
        GLib.timeout_add(200, poll)
        Gtk.main()
        if status[0]:
            raise MediaError('The isolated viewer stopped. The file may be unsupported or exceed the memory limit.')
        return 0
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
        for p in children:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for _, opened_fd in opened:
            os.close(opened_fd)
        for descriptor in descriptors:
            os.close(descriptor)
        xlib.XCloseDisplay(connection)
        log.close()
        if sys.exc_info()[0] is not None:
            with (directory / 'session.log').open('rb') as stream:
                stream.seek(max(0, stream.seek(0, os.SEEK_END) - 4000))
                print(stream.read().decode(errors='replace'), file=sys.stderr)


def choose(kind):
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.FileChooserDialog(title='Open images' if kind == 'image' else 'Open media', action=Gtk.FileChooserAction.OPEN)
    dialog.add_buttons('Cancel', Gtk.ResponseType.CANCEL, 'Open', Gtk.ResponseType.ACCEPT)
    dialog.set_local_only(True)
    dialog.set_select_multiple(True)
    dialog.set_preview_widget_active(False)
    result = dialog.get_filenames() if dialog.run() == Gtk.ResponseType.ACCEPT else []
    dialog.destroy()
    return result


def notify_error(message):
    print('PH4NTXM Media: ' + message, file=sys.stderr)
    if not os.environ.get('DISPLAY'):
        return
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    dialog = Gtk.MessageDialog(message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.CLOSE,
                               text='The isolated viewer could not open.')
    dialog.format_secondary_text(message)
    dialog.run()
    dialog.destroy()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        return inside(sys.argv[2], sys.argv[3:])
    if len(sys.argv) > 1 and sys.argv[1] == '--session':
        return session(sys.argv[2], sys.argv[3])
    parser = argparse.ArgumentParser(description='Open local media in a disposable offline sandbox')
    parser.add_argument('--kind', choices=KINDS)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('files', nargs='*')
    options = parser.parse_args()
    invoked = Path(sys.argv[0]).name
    kind = options.kind or ('image' if invoked == 'ristretto' else 'video')
    unit = None
    directory = None
    try:
        ready(kind)
        limit = memory_limit(kind)
        if options.check:
            unit = 'ph4ntxm-media-check-' + uuid.uuid4().hex
            command(['/usr/bin/systemd-run', '--user', '--quiet', '--wait', '--collect', '--unit=' + unit,
                     '-p', 'MemoryMax=%d' % limit, '-p', 'MemorySwapMax=0', '-p', 'TasksMax=128',
                     '/usr/bin/true'], capture_output=True)
            print('Media namespaces, network filter, runtime and resource controls passed.')
            return 0
        values = options.files or choose(kind)
        if not values:
            return 0
        opened = open_files(values, kind)
        values = [str(x[0]) for x in opened]
        for _, descriptor in opened:
            os.close(descriptor)
        directory = tempfile.mkdtemp(prefix='ph4ntxm-media-', dir=runtime_directory())
        (Path(directory) / 'request.json').write_text(json.dumps(values))
        unit = 'ph4ntxm-media-' + uuid.uuid4().hex
        args = ['/usr/bin/systemd-run', '--user', '--quiet', '--wait', '--collect', '--service-type=exec',
                '--unit=' + unit, '-p', 'Description=' + TITLES[kind],
                '-p', 'MemoryMax=%d' % limit, '-p', 'MemorySwapMax=0',
                '-p', 'TasksMax=128', '-p', 'CPUQuota=200%', '-p', 'OOMPolicy=kill', '-p', 'KillMode=control-group',
                '-p', 'TimeoutStopSec=5', '-p', 'UMask=0077']
        for key in ['DISPLAY', 'XAUTHORITY']:
            if os.environ.get(key):
                args += ['--setenv=' + key + '=' + os.environ[key]]
        result = subprocess.run(args + ['/usr/bin/python3', str(LIB / 'media.py'), '--session', kind, directory])
        if result.returncode:
            notify_error('Playback could not start or exceeded its resource limit. Check the session journal for details.')
        return result.returncode
    except (MediaError, OSError, ValueError, subprocess.SubprocessError) as exc:
        if options.check:
            print('PH4NTXM Media: ' + str(exc), file=sys.stderr)
        else:
            notify_error(str(exc))
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if unit:
            subprocess.run(['/usr/bin/systemctl', '--user', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if directory:
            shutil.rmtree(directory, ignore_errors=True)


if __name__ == '__main__':
    raise SystemExit(main())
