# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import ctypes
import os
import re


class DisplayError(RuntimeError):
    pass


class ConfigureEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int),
        ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int),
        ("display", ctypes.c_void_p),
        ("event", ctypes.c_ulong),
        ("window", ctypes.c_ulong),
        ("x", ctypes.c_int),
        ("y", ctypes.c_int),
        ("width", ctypes.c_int),
        ("height", ctypes.c_int),
        ("border_width", ctypes.c_int),
        ("above", ctypes.c_ulong),
        ("override_redirect", ctypes.c_int),
    ]


class Event(ctypes.Union):
    _fields_ = [("configure", ConfigureEvent), ("padding", ctypes.c_long * 24)]


class ScreenSize(ctypes.Structure):
    _fields_ = [
        ("width", ctypes.c_int),
        ("height", ctypes.c_int),
        ("millimeters_width", ctypes.c_int),
        ("millimeters_height", ctypes.c_int),
    ]


class DisplaySync:
    def __init__(self):
        name = os.environ.get("DISPLAY", "")
        if not re.fullmatch(r":[0-9]{1,5}", name):
            raise DisplayError("The private display must use a local connection.")
        self.connection = None
        self.xlib = ctypes.CDLL("libX11.so.6")
        self.randr = ctypes.CDLL("libXrandr.so.2")
        declarations = [
            (self.xlib, "XOpenDisplay", [ctypes.c_char_p], ctypes.c_void_p),
            (self.xlib, "XDefaultRootWindow", [ctypes.c_void_p], ctypes.c_ulong),
            (self.xlib, "XSelectInput", [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_long], ctypes.c_int),
            (self.xlib, "XPending", [ctypes.c_void_p], ctypes.c_int),
            (self.xlib, "XNextEvent", [ctypes.c_void_p, ctypes.POINTER(Event)], ctypes.c_int),
            (self.xlib, "XFlush", [ctypes.c_void_p], ctypes.c_int),
            (self.xlib, "XCloseDisplay", [ctypes.c_void_p], ctypes.c_int),
            (self.randr, "XRRGetScreenInfo", [ctypes.c_void_p, ctypes.c_ulong], ctypes.c_void_p),
            (self.randr, "XRRConfigCurrentConfiguration", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ushort)], ctypes.c_ushort),
            (self.randr, "XRRConfigSizes", [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)], ctypes.POINTER(ScreenSize)),
            (self.randr, "XRRSetScreenConfig", [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ushort, ctypes.c_ulong], ctypes.c_int),
            (self.randr, "XRRFreeScreenConfigInfo", [ctypes.c_void_p], None),
        ]
        for library, function, arguments, result in declarations:
            call = getattr(library, function)
            call.argtypes = arguments
            call.restype = result
        self.connection = self.xlib.XOpenDisplay(name.encode("ascii"))
        if not self.connection:
            raise DisplayError("The private display connection is unavailable.")
        self.root = self.xlib.XDefaultRootWindow(self.connection)
        self.dimensions = None
        self.dirty = True
        self.retries = 0
        self.last_event_dimensions = None
        self.xlib.XSelectInput(self.connection, self.root, 1 << 17)
        self.xlib.XFlush(self.connection)

    def poll(self):
        event = Event()
        for _ in range(64):
            if not self.xlib.XPending(self.connection):
                break
            self.xlib.XNextEvent(self.connection, ctypes.byref(event))
            if event.configure.type == 22 and not event.configure.send_event and event.configure.window == self.root:
                dimensions = (event.configure.width, event.configure.height)
                if dimensions != self.last_event_dimensions:
                    self.retries = 0
                    self.last_event_dimensions = dimensions
                self.dirty = True
        if not self.dirty:
            return True
        configuration = self.randr.XRRGetScreenInfo(self.connection, self.root)
        if not configuration:
            raise DisplayError("The private display configuration is unavailable.")
        try:
            rotation = ctypes.c_ushort()
            index = self.randr.XRRConfigCurrentConfiguration(configuration, ctypes.byref(rotation))
            count = ctypes.c_int()
            sizes = self.randr.XRRConfigSizes(configuration, ctypes.byref(count))
            if not sizes or not 0 <= index < count.value <= 4096:
                return self.retry("The private display mode is unavailable.")
            size = sizes[index]
            dimensions = (size.width, size.height)
            if not all(1 <= value <= 16384 for value in dimensions):
                raise DisplayError("The private display dimensions are invalid.")
            if dimensions != self.dimensions or self.retries:
                status = self.randr.XRRSetScreenConfig(self.connection, configuration, self.root, index, rotation, 0)
                if status != 0:
                    return self.retry("The private display could not synchronize input after resizing.")
                self.dimensions = dimensions
            self.retries = 0
            self.dirty = False
        finally:
            self.randr.XRRFreeScreenConfigInfo(configuration)
        return True

    def retry(self, message):
        self.retries += 1
        if self.retries >= 10:
            raise DisplayError(message)
        return True

    def close(self):
        if self.connection:
            self.xlib.XCloseDisplay(self.connection)
            self.connection = None
