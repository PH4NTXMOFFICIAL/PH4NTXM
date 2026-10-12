# Copyright (C) PH4NTXM
# Licensed under the GNU General Public License v3.0.

from airlock import AirlockError, encode_password


def ask_password(parent, title, message):
    import gi

    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk

    dialog = Gtk.Dialog(title=title, transient_for=parent, modal=True, destroy_with_parent=True)
    dialog.add_buttons("Cancel", Gtk.ResponseType.CANCEL, "Unlock", Gtk.ResponseType.ACCEPT)
    dialog.set_default_response(Gtk.ResponseType.ACCEPT)
    dialog.set_resizable(False)
    dialog.set_default_size(400, -1)
    content = dialog.get_content_area()
    content.set_border_width(18)
    content.set_spacing(12)
    label = Gtk.Label(label=message, xalign=0)
    label.set_line_wrap(True)
    label.set_max_width_chars(48)
    entry = Gtk.Entry()
    entry.set_visibility(False)
    entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
    entry.set_max_length(1024)
    entry.set_activates_default(True)
    content.pack_start(label, False, False, 0)
    content.pack_start(entry, False, False, 0)
    parent.password_dialog = dialog
    dialog.show_all()
    entry.grab_focus()
    try:
        while dialog.run() == Gtk.ResponseType.ACCEPT and not parent.closing:
            password = entry.get_text()
            try:
                if not encode_password(password):
                    raise AirlockError("Enter the file password.")
            except AirlockError as error:
                label.set_text(str(error))
                entry.grab_focus()
                continue
            return password
        return None
    finally:
        entry.set_text("")
        parent.password_dialog = None
        dialog.destroy()
