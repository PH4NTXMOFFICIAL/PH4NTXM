# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

import math


class GuardError(Exception):
    pass


class GLibScheduler:
    def __init__(self, glib):
        self.glib = glib

    def after(self, seconds, callback):
        return self.glib.timeout_add(max(1, math.ceil(seconds * 1000)), callback)

    def cancel(self, source):
        if source:
            self.glib.source_remove(source)


class Guard:
    def __init__(self, scheduler, backend_factory, on_change):
        self.scheduler = scheduler
        self.backend_factory = backend_factory
        self.on_change = on_change
        self.enabled = False
        self.seconds = 60
        self.include_primary = False
        self.message = "Clipboard protection is disabled."
        self.error = ""
        self.backend = None
        self.leases = {}
        self.generation = 0

    def changed(self):
        self.on_change(self)

    def forget(self, selection):
        lease = self.leases.pop(selection, None)
        if lease is not None and lease["source"] is not None:
            self.scheduler.cancel(lease["source"])

    def shutdown(self):
        self.enabled = False
        for selection in tuple(self.leases):
            self.forget(selection)
        backend, self.backend = self.backend, None
        if backend is not None:
            backend.close()

    def fail(self, error):
        self.shutdown()
        self.error = str(error)
        self.message = self.error
        self.changed()

    def start(self, seconds, include_primary):
        if self.enabled:
            raise GuardError("Disable protection before changing its settings.")
        if type(seconds) is not int or not 1 <= seconds <= 86400 or type(include_primary) is not bool:
            raise GuardError("Choose a whole number of seconds between 1 and 86400.")
        try:
            self.backend = self.backend_factory()
            initial = self.backend.start(include_primary, self.event)
            self.seconds = seconds
            self.include_primary = include_primary
            self.enabled = True
            self.error = ""
            self.message = f"Copied content expires after {seconds} seconds."
            for name, (owner, timestamp) in initial.items():
                self.event({"selection": name, "owner": owner, "timestamp": timestamp})
            self.changed()
        except GuardError as error:
            self.fail(error)
            raise

    def stop(self):
        self.shutdown()
        self.error = ""
        self.message = "Clipboard protection is disabled. Existing contents are unchanged."
        self.changed()

    def event(self, event):
        if not self.enabled:
            return
        if event.get("error"):
            self.fail(GuardError(event["error"]))
            return
        name = event["selection"]
        if name == "MANAGER":
            if event["owner"]:
                self.fail(GuardError("A clipboard history manager appeared. Protection stopped. Close that manager before enabling Clipboard Guard again."))
            return
        if name not in ("CLIPBOARD", "PRIMARY") or name == "PRIMARY" and not self.include_primary:
            return
        self.forget(name)
        if not event["owner"]:
            return
        self.generation += 1
        generation = self.generation
        lease = {"owner": event["owner"], "timestamp": event["timestamp"], "generation": generation, "source": None}
        self.leases[name] = lease
        lease["source"] = self.scheduler.after(self.seconds, lambda: self.expire(name, generation))

    def expire(self, selection, generation):
        lease = self.leases.get(selection)
        if not self.enabled or lease is None or lease["generation"] != generation:
            return False
        lease["source"] = None
        try:
            result = self.backend.expire(selection, lease["owner"], lease["timestamp"])
            for event in result.get("events", ()):
                self.event(event)
            lease = self.leases.get(selection)
            if not self.enabled:
                return False
            if result["cleared"]:
                if lease is None or lease["generation"] == generation:
                    self.forget(selection)
                    self.message = "Clipboard cleared." if selection == "CLIPBOARD" else "Selected text cleared for middle-click paste."
                    self.changed()
                return False
            if lease is None or lease["generation"] != generation:
                return False
            if result.get("retry"):
                lease["source"] = self.scheduler.after(0.01, lambda: self.expire(selection, generation))
            else:
                self.fail(GuardError("Clipboard ownership changed without a usable notification. Protection stopped. Enable it again to take a fresh snapshot."))
        except GuardError as error:
            self.fail(error)
        return False

    def clear_now(self, include_primary):
        if type(include_primary) is not bool:
            raise GuardError("The selection coverage is invalid.")
        temporary = None
        was_enabled = self.enabled
        try:
            if self.enabled:
                backend = self.backend
                include_primary = self.include_primary
            else:
                temporary = self.backend_factory()
                temporary.start(include_primary, lambda _event: None)
                backend = temporary
            result = backend.clear_now(include_primary)
            for name in result["cleared"]:
                self.forget(name)
            for event in result.get("events", ()):
                self.event(event)
            if was_enabled and not self.enabled:
                raise GuardError(self.error or "Clipboard protection stopped.")
            self.error = ""
            self.message = "Clipboard cleared." if result["cleared"] else "The selected clipboard areas are already empty."
            self.changed()
        except GuardError as error:
            if self.enabled or self.error != str(error):
                self.fail(error)
            raise
        finally:
            if temporary is not None:
                temporary.close()
