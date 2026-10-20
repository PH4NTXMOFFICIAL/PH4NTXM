# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from pathlib import Path
import concurrent.futures
import ctypes
import fcntl
import json
import os
import re
import socket
import stat
import struct
import sys
import threading
import time
from urllib.parse import unquote_to_bytes, urlsplit

MAX_MESSAGE = 270336


class ControllerError(ValueError):
    pass


def urls(values):
    if not isinstance(values, list) or len(values) > 32:
        raise ControllerError("Open up to 32 browser links at a time.")
    for value in values:
        if not isinstance(value, str) or len(value.encode("utf-8")) > 8192 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ControllerError("The browser link is invalid.")
        parsed = urlsplit(value)
        if parsed.scheme == "file":
            raise ControllerError("Use Import Files to select and copy a local file into the browser.")
        if not ((parsed.scheme in ("http", "https") and parsed.netloc) or value == "about:blank"):
            raise ControllerError("Open an HTTP, HTTPS or about:blank link.")
    return values


def imports(values):
    if not isinstance(values, list) or len(values) > 32:
        raise ControllerError("Import up to 32 selected files at a time.")
    for value in values:
        if (
            not isinstance(value, str)
            or len(value.encode("utf-8")) > 8192
            or not value.startswith("/")
            or ".." in Path(value).parts
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or value.startswith(("/proc/", "/sys/", "/dev/"))
        ):
            raise ControllerError("Select an absolute regular file path to import.")
    return values


def selected_file(value):
    if value.startswith("/"):
        path = value
    else:
        parsed = urlsplit(value)
        if parsed.scheme != "file" or parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment or re.search(r"%(?![0-9a-fA-F]{2})", parsed.path):
            raise ControllerError("Select a local file URL without an external host, query or fragment.")
        path = unquote_to_bytes(parsed.path).decode("utf-8", "strict")
    imports([path])
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ControllerError("Import a selected regular file.")
    return path


def validate_request(value):
    if not isinstance(value, dict) or set(value) != {"urls", "private_window", "imports"} or type(value["private_window"]) is not bool:
        raise ControllerError("Invalid browser link request.")
    urls(value["urls"])
    imports(value["imports"])
    if len(value["urls"]) + len(value["imports"]) > 32:
        raise ControllerError("Open up to 32 selected links and files at a time.")
    return value


def parse_arguments(arguments):
    values = []
    files = []
    private = False
    ready = None
    check = False
    for argument in arguments:
        if argument in ("-private-window", "--private-window"):
            private = True
        elif argument.startswith("--pilot-ready-fd="):
            if ready is not None or not re.fullmatch(r"[3-9][0-9]*|[12][0-9]+", argument.split("=", 1)[1]):
                raise ControllerError("Invalid browser launch acknowledgement descriptor.")
            ready = int(argument.split("=", 1)[1])
        elif argument == "--check":
            check = True
        elif argument.startswith("-"):
            raise ControllerError("Unsupported browser launch argument: " + argument)
        elif argument.startswith("/") or urlsplit(argument).scheme == "file":
            files.append(selected_file(argument))
        else:
            values.append(argument)
    if check and (values or files or private or ready is not None):
        raise ControllerError("Use --check without browser launch arguments.")
    result = validate_request({"urls": values, "imports": files, "private_window": private})
    return {**result, "ready_fd": ready, "check": check}


def ready_descriptor(descriptor):
    if descriptor is None:
        return None
    info = os.fstat(descriptor)
    access = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    if not stat.S_ISFIFO(info.st_mode) or access not in (os.O_WRONLY, os.O_RDWR):
        raise ControllerError("The browser launch acknowledgement requires a writable pipe.")
    os.set_inheritable(descriptor, False)
    os.set_blocking(descriptor, False)
    return descriptor


def acknowledge(descriptor):
    if descriptor is not None:
        try:
            if os.write(descriptor, b"accepted\n") != 9:
                raise ControllerError("Browser launch acknowledgement failed.")
        finally:
            os.close(descriptor)


def decode_request(raw):
    if len(raw) > MAX_MESSAGE:
        raise ControllerError("The browser link request exceeds its size limit.")
    def fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ControllerError("Duplicate browser request field.")
            result[key] = value
        return result
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=fields)
    return validate_request(value)


def receive_message(connection):
    content = bytearray()
    while len(content) <= MAX_MESSAGE:
        chunk = connection.recv(min(8192, MAX_MESSAGE + 1 - len(content)))
        if not chunk:
            return bytes(content)
        content.extend(chunk)
    raise ControllerError("The browser link request exceeds its size limit.")


def private_runtime():
    if os.getuid() == 0:
        raise ControllerError("Open the browser from the normal desktop account.")
    path = Path("/run/user") / str(os.getuid())
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ControllerError("A private desktop runtime directory is required.")
    return path


def verified_socket(path):
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ControllerError("The browser controller socket is unprotected.")
    return info


def same_peer(connection):
    _, owner, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    if owner != os.getuid():
        raise ControllerError("The browser controller account does not match.")


class Broker:
    def __init__(self, runtime):
        self.path = Path(runtime) / "ph4ntxm-browser-airlock.sock"
        self.lock = os.open(Path(runtime) / "ph4ntxm-browser-airlock.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        info = os.fstat(self.lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
            os.close(self.lock)
            self.lock = None
            raise ControllerError("The browser controller lock is unprotected.")
        self.server = None
        self.identity = None
        self.closed = threading.Event()
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.primary = True
        except BlockingIOError:
            self.primary = False

    def listen(self, handler):
        if self.path.exists() or self.path.is_symlink():
            verified_socket(self.path)
            self.path.unlink()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        self.path.chmod(0o600)
        self.identity = verified_socket(self.path).st_ino
        self.server.listen(8)
        self.server.settimeout(0.5)
        def serve():
            while not self.closed.is_set():
                try:
                    connection, _ = self.server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with connection:
                    try:
                        same_peer(connection)
                        connection.settimeout(3)
                        request = decode_request(receive_message(connection))
                        result = handler(request)
                    except Exception as error:
                        result = {"ok": False, "error": str(error)}
                    try:
                        connection.sendall(json.dumps(result).encode("utf-8"))
                    except OSError:
                        pass
        threading.Thread(target=serve, daemon=True).start()

    def forward(self, request, timeout=65):
        deadline = time.monotonic() + 8
        while True:
            try:
                verified_socket(self.path)
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(timeout)
                connection.connect(str(self.path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if "connection" in locals():
                    connection.close()
                if time.monotonic() >= deadline:
                    raise ControllerError("The active browser controller is unavailable.") from None
                time.sleep(0.1)
        with connection:
            same_peer(connection)
            connection.sendall(json.dumps(request).encode("utf-8"))
            connection.shutdown(socket.SHUT_WR)
            result = json.loads(receive_message(connection).decode("utf-8"))
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise ControllerError(result.get("error", "The active browser could not open the links.") if isinstance(result, dict) else "Invalid browser controller response.")

    def close(self):
        self.closed.set()
        if self.server is not None:
            self.server.close()
        if self.identity is not None:
            try:
                if verified_socket(self.path).st_ino == self.identity:
                    self.path.unlink()
            except FileNotFoundError:
                pass
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None


def load_backend():
    import browser_airlock
    return browser_airlock


class BrowserState:
    def __init__(self, backend):
        self.backend = backend
        self.session = None

    def open(self, request, settings, parent):
        validate_request(request)
        if self.session is None:
            self.session = self.backend.Session()
        values = list(request["urls"])
        if request["imports"]:
            previous = len(self.session.items)
            self.session.add(request["imports"])
            values.extend(Path(item["path"]).as_uri() for item in self.session.items[previous:])
        if self.session.snapshot()["running"]:
            self.session.open_urls(values, private_window=request["private_window"])
        else:
            self.session.start(settings=settings, urls=values, parent_window=parent, private_window=request["private_window"])
        snapshot = self.session.snapshot()
        if not snapshot["running"] or snapshot["state"] != "running":
            raise ControllerError(snapshot.get("message", "The isolated browser did not become ready."))
        return snapshot

    def review(self):
        if self.session is None:
            return []
        self.session.stop()
        return self.session.outputs()

    def prepare_close(self):
        if self.session is None:
            return [], None
        self.session.stop()
        try:
            return self.session.outputs(), None
        except Exception as error:
            return [], str(error)


def root_visual(screen, gdk_x11):
    xlib = ctypes.CDLL("libX11.so.6")
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = ctypes.c_void_p
    xlib.XDefaultVisual.argtypes = [ctypes.c_void_p, ctypes.c_int]
    xlib.XDefaultVisual.restype = ctypes.c_void_p
    xlib.XVisualIDFromVisual.argtypes = [ctypes.c_void_p]
    xlib.XVisualIDFromVisual.restype = ctypes.c_ulong
    xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]
    xlib.XCloseDisplay.restype = ctypes.c_int
    connection = xlib.XOpenDisplay(screen.get_display().get_name().encode("utf-8"))
    if not connection:
        raise ControllerError("Cannot inspect the X11 display visual.")
    try:
        visual = xlib.XDefaultVisual(connection, screen.get_number())
        visual_id = xlib.XVisualIDFromVisual(visual) if visual else 0
    finally:
        xlib.XCloseDisplay(connection)
    result = gdk_x11.X11Screen.lookup_visual(screen, visual_id) if visual_id else None
    if result is None:
        raise ControllerError("The X11 root visual is unavailable for the isolated display.")
    return result


def paint_display(_widget, context):
    context.set_source_rgb(0, 0, 0)
    context.paint()
    return False


def desktop(backend, broker, request, ready_fd):
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("Gdk", "3.0")
    gi.require_version("GdkX11", "3.0")
    from gi.repository import Gdk, GdkX11, GLib, Gtk, Pango

    class Window(Gtk.Window):
        def __init__(self):
            super().__init__(title="PH4NTXM Browser Airlock")
            self.set_icon_name("ph4ntxm-browser-airlock")
            self.engine = BrowserState(backend)
            self.busy = False
            self.closing = False
            self.close_started = False
            self.dialog_active = False
            self.finished = False
            self.running = False
            self.exit_code = 0
            self.ready_fd = ready_fd
            self.pending = []
            self.exported = set()
            self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            self.set_wmclass("ph4ntxm-browser-airlock", "PH4NTXM Browser Airlock")
            screen = self.get_screen()
            monitor = screen.get_monitor_workarea(screen.get_primary_monitor())
            self.set_default_size(min(1100, max(420, monitor.width - 40)), min(760, max(360, monitor.height - 60)))
            self.set_position(Gtk.WindowPosition.CENTER)
            self.connect("delete-event", self.close_requested)
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
            toolbar = Gtk.Box(spacing=8)
            toolbar.set_border_width(8)
            self.import_button = Gtk.Button(label="Import Files")
            self.download_button = Gtk.Button(label="Downloads")
            self.resume_button = Gtk.Button(label="Resume")
            for button in (self.import_button, self.download_button, self.resume_button):
                button.set_focus_on_click(False)
                toolbar.pack_start(button, False, False, 0)
            self.import_button.connect("clicked", self.import_files)
            self.download_button.connect("clicked", self.downloads)
            self.resume_button.connect("clicked", lambda *_: self.open_request({"urls": [], "imports": [], "private_window": request["private_window"]}))
            self.resume_button.set_no_show_all(True)
            content.pack_start(toolbar, False, False, 0)
            self.socket = Gtk.Socket()
            self.socket.set_can_focus(True)
            self.socket.set_visual(root_visual(screen, GdkX11))
            self.socket.set_hexpand(True)
            self.socket.set_vexpand(True)
            self.socket.connect("realize", lambda *_: GLib.idle_add(self.open_request, request, None, True))
            self.socket.connect("plug-removed", self.plug_removed)
            self.socket.connect("draw", paint_display)
            content.pack_start(self.socket, True, True, 0)
            self.status = Gtk.Label(label="Preparing the isolated browser…", xalign=0)
            self.status.set_ellipsize(Pango.EllipsizeMode.END)
            self.status.set_hexpand(True)
            self.status.set_max_width_chars(100)
            self.status.set_single_line_mode(True)
            self.status.set_tooltip_text(self.status.get_text())
            self.status.connect("notify::label", lambda label, *_: label.set_tooltip_text(label.get_text()))
            self.status.set_margin_start(10)
            self.status.set_margin_end(10)
            self.status.set_margin_top(6)
            self.status.set_margin_bottom(6)
            content.pack_start(self.status, False, False, 0)
            self.add(content)
            self.show_all()
            self.socket.grab_focus()
            self.controls()
            broker.listen(self.receive)
            GLib.timeout_add(1500, self.poll)

        @property
        def session(self):
            return self.engine.session

        def controls(self):
            for button in (self.import_button, self.download_button, self.resume_button):
                button.set_sensitive(not self.busy and not self.closing and not self.dialog_active and self.session is not None)
            self.resume_button.set_visible(not self.running)

        def message(self, text, question=False):
            self.dialog_active = True
            self.controls()
            dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION if question else Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.NONE, text=text)
            dialog.add_button("Cancel" if question else "Close", Gtk.ResponseType.CANCEL)
            if question:
                dialog.add_button("Discard and Close", Gtk.ResponseType.ACCEPT)
            response = dialog.run()
            dialog.destroy()
            self.dialog_active = False
            self.controls()
            return response == Gtk.ResponseType.ACCEPT

        def work(self, operation, completed, fatal=False):
            self.busy = True
            self.controls()
            future = self.pool.submit(operation)
            def done(result):
                try:
                    value, error = result.result(), None
                except Exception as caught:
                    value, error = None, caught
                GLib.idle_add(finish, value, error)
            def finish(value, error):
                self.busy = False
                if error is not None:
                    print("PH4NTXM Browser Airlock: " + str(error), file=sys.stderr)
                    self.status.set_text(str(error))
                    self.message(str(error))
                    if fatal:
                        self.exit_code = 1
                        self.closing = True
                completed(value, error)
                self.controls()
                if self.closing and not self.close_started and not self.busy and not self.finished:
                    self.stop_for_close()
                elif not self.busy and not self.dialog_active and self.pending:
                    next_request, callback = self.pending.pop(0)
                    self.open_request(next_request, callback)
                return False
            future.add_done_callback(done)

        def receive(self, value):
            event = threading.Event()
            result = {}
            deadline = time.monotonic() + 60
            def completed(error):
                result.update({"ok": error is None, "error": str(error) if error is not None else ""})
                event.set()
            completed.expired = lambda: time.monotonic() >= deadline
            GLib.idle_add(self.open_request, value, completed)
            if not event.wait(60):
                return {"ok": False, "error": "The browser controller is busy. Try again."}
            return result

        def open_request(self, value, callback=None, initial=False):
            self.present()
            if callback is not None and getattr(callback, "expired", lambda: False)():
                callback(ControllerError("The browser request expired. Try again."))
                return False
            if self.closing:
                if callback:
                    callback(ControllerError("The browser is closing."))
                return False
            if self.busy or self.dialog_active:
                if len(self.pending) >= 8:
                    if callback:
                        callback(ControllerError("The browser request queue is full."))
                else:
                    self.pending.append((value, callback))
                return False
            allocation = self.socket.get_allocation()
            settings = {"screen_width": max(128, min(8192, allocation.width)), "screen_height": max(128, min(8192, allocation.height))}
            gtk_settings = Gtk.Settings.get_default()
            if gtk_settings is not None:
                for key in ("gtk-theme-name", "gtk-icon-theme-name", "gtk-font-name"):
                    setting_value = gtk_settings.get_property(key)
                    if isinstance(setting_value, str) and setting_value and len(setting_value) <= 256 and all(ord(char) >= 32 for char in setting_value):
                        settings[key] = setting_value
            parent = self.socket.get_id()
            self.status.set_text("Opening the isolated browser…")
            def operation():
                return self.engine.open(value, settings, parent)
            def completed(snapshot, error):
                if error is None:
                    self.running = True
                    self.exported.clear()
                    self.status.set_text("Isolated browser running · Files: /workspace/imports · Downloads: /workspace/downloads")
                    if not self.closing and self.ready_fd is not None:
                        descriptor, self.ready_fd = self.ready_fd, None
                        try:
                            acknowledge(descriptor)
                        except (OSError, ControllerError) as caught:
                            print("PH4NTXM Browser Airlock: " + str(caught), file=sys.stderr)
                            self.exit_code = 1
                            self.closing = True
                if callback:
                    callback(error if error is not None else ControllerError("The browser is closing.") if self.closing else None)
            self.work(operation, completed, fatal=initial)
            return False

        def plug_removed(self, *_):
            self.socket.queue_draw()
            self.running = False
            self.controls()
            return True

        def poll(self):
            if self.finished:
                return False
            if not self.busy and not self.closing and not self.dialog_active and self.session is not None:
                def completed(snapshot, error):
                    if error is None:
                        self.running = snapshot["running"]
                        if not self.running:
                            reason = snapshot.get("message") or "Browser stopped."
                            self.status.set_text(reason[:1024] + " The private profile is retained. Resume or review Downloads.")
                self.work(self.session.snapshot, completed)
            return True

        def import_files(self, *_):
            self.dialog_active = True
            self.controls()
            chooser = Gtk.FileChooserDialog(title="Import Files", transient_for=self, action=Gtk.FileChooserAction.OPEN)
            chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Import", Gtk.ResponseType.ACCEPT)
            chooser.set_select_multiple(True)
            response = chooser.run()
            paths = chooser.get_filenames() if response == Gtk.ResponseType.ACCEPT else []
            chooser.destroy()
            self.dialog_active = False
            if paths:
                def operation():
                    self.session.add(paths)
                    return len(paths)
                self.work(operation, lambda count, error: self.status.set_text(f"Imported {count} file(s). Open them at /workspace/imports in the browser.") if error is None else None)
            else:
                self.drain()

        def downloads(self, *_):
            self.dialog_active = True
            self.controls()
            if self.running:
                dialog = Gtk.MessageDialog(transient_for=self, modal=True, message_type=Gtk.MessageType.QUESTION, buttons=Gtk.ButtonsType.NONE, text="Stop the browser to review and export downloads?")
                dialog.format_secondary_text("The private profile is retained. You can resume after reviewing files.")
                dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
                dialog.add_button("Stop + Review", Gtk.ResponseType.ACCEPT)
                response = dialog.run()
                dialog.destroy()
                self.dialog_active = False
                if response != Gtk.ResponseType.ACCEPT:
                    self.drain()
                    return
            self.dialog_active = False
            def completed(items, error):
                if error is None:
                    self.running = False
                    self.status.set_text("Browser stopped. The private profile is retained.")
                    self.review(items)
            self.work(self.engine.review, completed)

        def review(self, items):
            self.dialog_active = True
            self.controls()
            dialog = Gtk.Dialog(title="Downloads", transient_for=self, modal=True)
            dialog.set_default_size(620, 360)
            dialog.add_button("Close", Gtk.ResponseType.CLOSE)
            export_button = dialog.add_button("Export Selected", Gtk.ResponseType.APPLY)
            store = Gtk.ListStore(str, str, str)
            for item in items:
                store.append((item["id"], item["name"], f"{item['size']:,} bytes"))
            tree = Gtk.TreeView(model=store)
            tree.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)
            filename = Gtk.CellRendererText()
            filename.set_property("ellipsize", Pango.EllipsizeMode.MIDDLE)
            filename.set_property("max-width-chars", 64)
            file_column = Gtk.TreeViewColumn("File", filename, text=1)
            file_column.set_expand(True)
            tree.append_column(file_column)
            tree.append_column(Gtk.TreeViewColumn("Size", Gtk.CellRendererText(), text=2))
            scroller = Gtk.ScrolledWindow()
            scroller.add(tree)
            dialog.get_content_area().pack_start(scroller, True, True, 8)
            export_button.set_sensitive(bool(items))
            dialog.show_all()
            while dialog.run() == Gtk.ResponseType.APPLY:
                model, selected = tree.get_selection().get_selected_rows()
                records = [(model[path][0], model[path][1]) for path in selected]
                if not records:
                    continue
                destinations = []
                for identifier, name in records:
                    chooser = Gtk.FileChooserDialog(title="Export Download", transient_for=dialog, action=Gtk.FileChooserAction.SAVE)
                    chooser.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Export", Gtk.ResponseType.ACCEPT)
                    chooser.set_current_name(Path(name).name)
                    if chooser.run() == Gtk.ResponseType.ACCEPT:
                        destinations.append((identifier, chooser.get_filename()))
                    chooser.destroy()
                if destinations:
                    dialog.destroy()
                    self.dialog_active = False
                    def operation():
                        exported = []
                        for identifier, destination in destinations:
                            self.session.export(identifier, destination)
                            exported.append(identifier)
                        return exported
                    def completed(exported, error):
                        if error is None:
                            self.exported.update(exported)
                            self.status.set_text(f"Exported {len(exported)} download(s). The browser remains stopped.")
                    self.work(operation, completed)
                    return
            dialog.destroy()
            self.dialog_active = False

        def close_requested(self, *_):
            if self.finished:
                return False
            self.closing = True
            self.status.set_text("Stopping the isolated browser…")
            self.controls()
            if not self.busy and not self.close_started:
                self.stop_for_close()
            return True

        def stop_for_close(self):
            self.close_started = True
            for value, callback in self.pending:
                if callback:
                    callback(ControllerError("The browser is closing."))
            self.pending.clear()
            def completed(review, error):
                self.running = False
                if error is not None:
                    self.closing = False
                    self.close_started = False
                    return
                items, review_error = review
                remaining = [item for item in items if item["id"] not in self.exported]
                question = (
                    "The stopped browser downloads cannot be reviewed. " + review_error + "\nDiscard temporary downloads and close Browser Airlock?"
                    if review_error else "Close Browser Airlock and discard its temporary downloads?"
                )
                question += "\nFiles already exported will not be affected."
                if (review_error or remaining) and not self.message(question, question=True):
                    self.closing = False
                    self.close_started = False
                    self.status.set_text("Browser stopped. Review Downloads or resume the retained profile.")
                    return
                self.closing = True
                def cleanup():
                    if self.session is not None:
                        self.session.close()
                def cleaned(value, cleanup_error):
                    if cleanup_error is not None:
                        self.closing = False
                        self.close_started = False
                        return
                    self.finished = True
                    if self.ready_fd is not None:
                        os.close(self.ready_fd)
                        self.ready_fd = None
                    broker.close()
                    self.pool.shutdown(wait=False)
                    self.destroy()
                    Gtk.main_quit()
                self.work(cleanup, cleaned)
            self.work(self.engine.prepare_close, completed)

        def drain(self):
            self.controls()
            if self.pending and not self.busy and not self.closing and not self.dialog_active:
                value, callback = self.pending.pop(0)
                self.open_request(value, callback)

    window = Window()
    Gtk.main()
    return window.exit_code


def report_error(error):
    print("PH4NTXM Browser Airlock: " + str(error), file=sys.stderr)
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk
        if Gtk.init_check()[0]:
            dialog = Gtk.MessageDialog(message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.CLOSE, text=str(error))
            dialog.run()
            dialog.destroy()
    except Exception:
        pass


def main(arguments=None):
    broker = None
    descriptor = None
    try:
        options = parse_arguments(sys.argv[1:] if arguments is None else arguments)
        descriptor = ready_descriptor(options["ready_fd"])
        backend = load_backend()
        if options["check"]:
            backend.check_ready()
            print("PH4NTXM Browser Airlock isolation checks passed.")
            return 0
        broker = Broker(private_runtime())
        request = {"urls": options["urls"], "private_window": options["private_window"], "imports": options["imports"]}
        if not broker.primary:
            broker.forward(request)
            acknowledge(descriptor)
            descriptor = None
            return 0
        owned_descriptor, descriptor = descriptor, None
        return desktop(backend, broker, request, owned_descriptor)
    except Exception as error:
        report_error(error)
        return 1
    finally:
        if broker is not None:
            broker.close()
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
