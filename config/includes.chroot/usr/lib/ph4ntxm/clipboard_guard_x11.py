# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import ctypes.util
import os
import re
import time

from clipboard_guard import GuardError
from clipboard_guard_manager import disable_xfce_clipboard, pause_clipman


class SelectionEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int), ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong), ("subtype", ctypes.c_int),
        ("owner", ctypes.c_ulong), ("selection", ctypes.c_ulong),
        ("timestamp", ctypes.c_ulong), ("selection_timestamp", ctypes.c_ulong),
    ]


class PropertyEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int), ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong), ("atom", ctypes.c_ulong),
        ("time", ctypes.c_ulong), ("state", ctypes.c_int),
    ]


class XEvent(ctypes.Union):
    _fields_ = [("type", ctypes.c_int), ("selection", SelectionEvent),
               ("property", PropertyEvent), ("padding", ctypes.c_long * 24)]


class ClientIdSpec(ctypes.Structure):
    _fields_ = [("client", ctypes.c_ulong), ("mask", ctypes.c_uint)]


class ClientIdValue(ctypes.Structure):
    _fields_ = [("spec", ClientIdSpec), ("length", ctypes.c_long), ("value", ctypes.c_void_p)]


class X11Backend:
    def __init__(self, glib):
        self.glib = glib
        self.display = None
        self.window = 0
        self.watch = 0
        self.idle = 0
        self.callback = None
        self.atoms = {}
        self.names = {}
        self.event_base = 0
        self.server_time = 0
        try:
            self.xlib = ctypes.CDLL(ctypes.util.find_library("X11") or "libX11.so.6")
            self.fixes = ctypes.CDLL(ctypes.util.find_library("Xfixes") or "libXfixes.so.3")
        except OSError as error:
            raise GuardError("X11 clipboard monitoring libraries are unavailable.") from error
        self.bind()

    def bind(self):
        pointer = ctypes.c_void_p
        integer = ctypes.c_int
        number = ctypes.c_ulong
        signatures = {
            "XOpenDisplay": ([ctypes.c_char_p], pointer),
            "XDefaultRootWindow": ([pointer], number),
            "XCreateSimpleWindow": ([pointer, number, integer, integer, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, number, number], number),
            "XInternAtom": ([pointer, ctypes.c_char_p, integer], number),
            "XSelectInput": ([pointer, number, ctypes.c_long], integer),
            "XChangeProperty": ([pointer, number, number, number, integer, integer, ctypes.POINTER(ctypes.c_ubyte), integer], integer),
            "XGetSelectionOwner": ([pointer, number], number),
            "XSetSelectionOwner": ([pointer, number, number, number], integer),
            "XGrabServer": ([pointer], integer),
            "XUngrabServer": ([pointer], integer),
            "XSync": ([pointer, integer], integer),
            "XFlush": ([pointer], integer),
            "XPending": ([pointer], integer),
            "XNextEvent": ([pointer, ctypes.POINTER(XEvent)], integer),
            "XConnectionNumber": ([pointer], integer),
            "XDestroyWindow": ([pointer, number], integer),
            "XCloseDisplay": ([pointer], integer),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.xlib, name)
            function.argtypes = arguments
            function.restype = result
        self.fixes.XFixesQueryExtension.argtypes = [pointer, ctypes.POINTER(integer), ctypes.POINTER(integer)]
        self.fixes.XFixesQueryExtension.restype = integer
        self.fixes.XFixesQueryVersion.argtypes = [pointer, ctypes.POINTER(integer), ctypes.POINTER(integer)]
        self.fixes.XFixesQueryVersion.restype = integer
        self.fixes.XFixesSelectSelectionInput.argtypes = [pointer, number, number, ctypes.c_ulong]
        self.fixes.XFixesSelectSelectionInput.restype = None

    def manager_check(self):
        if self.xlib.XGetSelectionOwner(self.display, self.atoms["MANAGER"]):
            raise GuardError("A clipboard history manager is active. Close its tray application or panel plugin, then enable Clipboard Guard again. Existing history is unchanged.")

    def pause_manager(self):
        owner = int(self.xlib.XGetSelectionOwner(self.display, self.atoms["MANAGER"]))
        if not owner:
            return
        try:
            resource = ctypes.CDLL(ctypes.util.find_library("XRes") or "libXRes.so.1")
            pointer = ctypes.c_void_p
            integer = ctypes.c_int
            resource.XResQueryVersion.argtypes = [pointer, ctypes.POINTER(integer), ctypes.POINTER(integer)]
            resource.XResQueryVersion.restype = integer
            resource.XResQueryClientIds.argtypes = [pointer, ctypes.c_long, ctypes.POINTER(ClientIdSpec), ctypes.POINTER(ctypes.c_long), ctypes.POINTER(ctypes.POINTER(ClientIdValue))]
            resource.XResQueryClientIds.restype = integer
            resource.XResGetClientPid.argtypes = [ctypes.POINTER(ClientIdValue)]
            resource.XResGetClientPid.restype = integer
            resource.XResClientIdsDestroy.argtypes = [ctypes.c_long, ctypes.POINTER(ClientIdValue)]
            resource.XResClientIdsDestroy.restype = None
            major, minor = integer(), integer()
            if not resource.XResQueryVersion(self.display, ctypes.byref(major), ctypes.byref(minor)) or (major.value, minor.value) < (1, 2):
                raise GuardError("The clipboard manager cannot be identified safely. Close it manually before enabling protection.")
            spec = ClientIdSpec(owner, 2)
            count = ctypes.c_long()
            values = ctypes.POINTER(ClientIdValue)()
            status = resource.XResQueryClientIds(self.display, 1, ctypes.byref(spec), ctypes.byref(count), ctypes.byref(values))
            pid = None
            try:
                if status == 0 and count.value == 1 and values and values[0].spec.mask == 2:
                    pid = int(resource.XResGetClientPid(ctypes.byref(values[0])))
            finally:
                if values:
                    resource.XResClientIdsDestroy(count, values)
            if pid is None or pid <= 0:
                raise GuardError("The clipboard manager process could not be identified safely. Close it manually before enabling protection.")
            if int(self.xlib.XGetSelectionOwner(self.display, self.atoms["MANAGER"])) != owner:
                raise GuardError("The clipboard manager changed during setup. Enable protection again.")
            if not pause_clipman(pid):
                if not disable_xfce_clipboard(pid):
                    raise GuardError("An unrecognized clipboard history manager is active. Close it manually before enabling protection.")
                deadline = time.monotonic() + 2
                while int(self.xlib.XGetSelectionOwner(self.display, self.atoms["MANAGER"])) == owner:
                    if time.monotonic() >= deadline:
                        raise GuardError("The clipboard manager did not release ownership. Enable protection again after it stops.")
                    time.sleep(0.02)
            self.manager_check()
        except (OSError, AttributeError) as error:
            raise GuardError("The clipboard manager cannot be identified safely. Close it manually before enabling protection.") from error

    def lock(self):
        self.xlib.XGrabServer(self.display)
        self.xlib.XSync(self.display, 0)

    def unlock(self):
        if self.display:
            self.xlib.XUngrabServer(self.display)
            self.xlib.XFlush(self.display)

    def timestamp(self):
        value = ctypes.c_ulong(0)
        self.xlib.XChangeProperty(
            self.display, self.window, self.stamp_atom, 19, 32, 0,
            ctypes.cast(ctypes.pointer(value), ctypes.POINTER(ctypes.c_ubyte)), 1,
        )
        self.xlib.XSync(self.display, 0)
        for _ in range(4096):
            if not self.xlib.XPending(self.display):
                break
            event = XEvent()
            self.xlib.XNextEvent(self.display, ctypes.byref(event))
            if event.type == 28 and not event.property.send_event and event.property.window == self.window and event.property.atom == self.stamp_atom:
                timestamp = int(event.property.time) & 0xffffffff
                if timestamp:
                    return timestamp
        raise GuardError("The X11 server did not provide a usable clipboard timestamp.")

    def start(self, include_primary, callback):
        if self.display:
            raise GuardError("Clipboard monitoring is already connected.")
        display_name = os.environ.get("DISPLAY", "")
        if not re.fullmatch(r":\d+(?:\.\d+)?", display_name):
            raise GuardError("Clipboard Guard requires the local X11 desktop.")
        self.callback = callback
        self.display = self.xlib.XOpenDisplay(display_name.encode("ascii"))
        if not self.display:
            raise GuardError("The local X11 clipboard display is unavailable.")
        try:
            base, error = ctypes.c_int(), ctypes.c_int()
            if not self.fixes.XFixesQueryExtension(self.display, ctypes.byref(base), ctypes.byref(error)):
                raise GuardError("XFixes clipboard ownership notifications are unavailable.")
            major, minor = ctypes.c_int(1), ctypes.c_int(0)
            if not self.fixes.XFixesQueryVersion(self.display, ctypes.byref(major), ctypes.byref(minor)) or major.value < 1:
                raise GuardError("XFixes clipboard ownership notifications are unavailable.")
            self.event_base = base.value
            root = self.xlib.XDefaultRootWindow(self.display)
            self.window = self.xlib.XCreateSimpleWindow(self.display, root, 0, 0, 1, 1, 0, 0, 0)
            self.xlib.XSelectInput(self.display, self.window, 1 << 22)
            self.stamp_atom = self.xlib.XInternAtom(self.display, b"_PH4NTXM_CLIPBOARD_GUARD_TIME", 0)
            selections = ["CLIPBOARD"] + (["PRIMARY"] if include_primary else [])
            self.atoms = {name: self.xlib.XInternAtom(self.display, ("CLIPBOARD_MANAGER" if name == "MANAGER" else name).encode("ascii"), 0) for name in selections + ["MANAGER"]}
            self.names = {value: name for name, value in self.atoms.items()}
            self.pause_manager()
            self.lock()
            try:
                for atom in self.atoms.values():
                    self.fixes.XFixesSelectSelectionInput(self.display, self.window, atom, 7)
                self.manager_check()
                timestamp = self.timestamp()
                initial = {name: (int(self.xlib.XGetSelectionOwner(self.display, self.atoms[name])), timestamp) for name in selections}
            finally:
                self.unlock()
            condition = self.glib.IOCondition.IN | self.glib.IOCondition.HUP | self.glib.IOCondition.ERR
            self.watch = self.glib.io_add_watch(self.xlib.XConnectionNumber(self.display), self.glib.PRIORITY_DEFAULT, condition, self.ready)
            return initial
        except BaseException:
            self.close()
            raise

    def events(self):
        values = []
        for _ in range(256):
            if not self.xlib.XPending(self.display):
                break
            event = XEvent()
            self.xlib.XNextEvent(self.display, ctypes.byref(event))
            if event.type != self.event_base:
                continue
            item = event.selection
            if item.send_event or item.window != self.window or item.selection not in self.names or item.subtype not in (0, 1, 2):
                continue
            timestamp = int(item.selection_timestamp) & 0xffffffff
            owner = int(item.owner) if item.subtype == 0 else 0
            if owner and not timestamp:
                raise GuardError("A clipboard change has no usable ownership timestamp.")
            values.append({"selection": self.names[item.selection], "owner": owner, "timestamp": timestamp})
        return values

    def deliver(self):
        if not self.display:
            return False
        try:
            self.xlib.XSync(self.display, 0)
            values = self.events()
            for event in values:
                if not self.display:
                    return False
                self.callback(event)
            if self.display and self.xlib.XPending(self.display) and not self.idle:
                self.idle = self.glib.idle_add(self.deliver_idle)
        except GuardError as error:
            self.callback({"error": str(error)})
        return bool(self.display)

    def deliver_idle(self):
        self.idle = 0
        self.deliver()
        return False

    def ready(self, _source, condition):
        if condition & (self.glib.IOCondition.HUP | self.glib.IOCondition.ERR):
            self.watch = 0
            self.abandon()
            self.callback({"error": "The X11 clipboard connection stopped. Protection is disabled."})
            return False
        return self.deliver()

    def abandon(self):
        if self.idle:
            self.glib.source_remove(self.idle)
            self.idle = 0
        display, self.display = self.display, None
        self.window = 0
        if display:
            descriptor = self.xlib.XConnectionNumber(display)
            try:
                os.close(descriptor)
            except OSError:
                pass

    def expire(self, name, owner, timestamp):
        if not self.display or name not in self.atoms:
            raise GuardError("The clipboard monitor is unavailable.")
        self.lock()
        try:
            values = self.events()
            if self.xlib.XPending(self.display):
                return {"cleared": False, "events": values, "retry": True}
            self.manager_check()
            if any(event["selection"] == name for event in values):
                return {"cleared": False, "events": values, "retry": False}
            current = int(self.xlib.XGetSelectionOwner(self.display, self.atoms[name]))
            if not current:
                return {"cleared": True, "events": values, "retry": False}
            if current != owner or not timestamp:
                return {"cleared": False, "events": values, "retry": False}
            self.xlib.XSetSelectionOwner(self.display, self.atoms[name], 0, timestamp)
            self.xlib.XSync(self.display, 0)
            values.extend(self.events())
            cleared = not self.xlib.XGetSelectionOwner(self.display, self.atoms[name])
            return {"cleared": cleared, "events": values, "retry": False}
        finally:
            self.unlock()

    def clear_now(self, include_primary):
        if not self.display:
            raise GuardError("The clipboard monitor is unavailable.")
        names = ["CLIPBOARD"] + (["PRIMARY"] if include_primary else [])
        self.lock()
        try:
            self.manager_check()
            timestamp = self.timestamp()
            cleared = []
            for name in names:
                if self.xlib.XGetSelectionOwner(self.display, self.atoms[name]):
                    self.xlib.XSetSelectionOwner(self.display, self.atoms[name], 0, timestamp)
                    cleared.append(name)
            self.xlib.XSync(self.display, 0)
            if any(self.xlib.XGetSelectionOwner(self.display, self.atoms[name]) for name in names):
                raise GuardError("The clipboard could not be cleared safely.")
            return {"cleared": cleared, "events": self.events()}
        finally:
            self.unlock()

    def close(self):
        for name in ("watch", "idle"):
            source = getattr(self, name)
            if source:
                self.glib.source_remove(source)
                setattr(self, name, 0)
        display, self.display = self.display, None
        if display:
            if self.window:
                self.xlib.XDestroyWindow(display, self.window)
            self.xlib.XCloseDisplay(display)
        self.window = 0
