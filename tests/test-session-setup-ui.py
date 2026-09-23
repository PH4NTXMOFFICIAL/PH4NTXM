#!/usr/bin/env python3
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import sys
import shutil
import tempfile

r=Path(__file__).resolve().parents[1]
output=Path(sys.argv[2]) if len(sys.argv)>2 else Path(tempfile.mkdtemp(prefix='ph4ntxm-setup-check-'))
output.mkdir(parents=True,exist_ok=True)
merged=tempfile.TemporaryDirectory(prefix='ph4ntxm-setup-theme-')
share=Path(merged.name)/'share'
share.mkdir()
edition=sys.argv[1]
assert edition in ('abyss','ghost')
shutil.copytree(r/f'editions/{edition}/config/includes.chroot/usr/share/themes',share/'themes')
shutil.copytree(r/'config/includes.chroot/usr/share/ph4ntxm/themes',share/'ph4ntxm/themes')
os.environ['XDG_DATA_DIRS']=str(share)+':/usr/share'
p=r/'config/includes.chroot/usr/local/bin/ph4ntxm-session-setup'
loader=importlib.machinery.SourceFileLoader('setup',str(p)); spec=importlib.util.spec_from_loader('setup',loader)
m=importlib.util.module_from_spec(spec); loader.exec_module(m)
Gtk,GLib,Gdk=m.Gtk,m.GLib,m.Gdk
config=r/f'editions/{edition}/config/includes.chroot/etc/lightdm/lightdm-gtk-greeter.conf'
staged=Path(merged.name)/f'{edition}.conf'
staged.write_text(config.read_text().replace('/usr/share/backgrounds/',str(r/f'editions/{edition}/config/includes.chroot/usr/share/backgrounds')+'/'))
m.install_style(str(staged),str(r/f'editions/{edition}/config/includes.chroot/usr/share/ph4ntxm'))
window=m.SetupWindow(exchange=lambda *_: {'ok':True})
m.place(window,Gdk.Display.get_default().get_monitor(0))
checks=[]
def verify():
 try:
  assert not window.start.get_sensitive()
  assert not window.password.get_visibility()
  toggle=Gtk.CheckButton(); toggle.set_active(True)
  window.toggle_visibility(toggle)
  assert window.password.get_visibility() and window.confirmation.get_visibility()
  toggle.set_active(False); window.toggle_visibility(toggle)
  pix=Gdk.pixbuf_get_from_window(window.get_window(),0,0,window.get_allocated_width(),window.get_allocated_height())
  pix.savev(str(output/(edition+'.png')),'png',[],[])
  window.password.set_text('abcde'); window.confirmation.set_text('abcde')
  assert not window.start.get_sensitive()
  window.password.set_text('abcdef'); window.confirmation.set_text('ghijkl')
  assert not window.start.get_sensitive()
  window.confirmation.set_text('abcdef')
  assert window.start.get_sensitive()
  window.finish({'ok':False,'error':'Test backend failure'})
  assert window.password.get_sensitive()
  assert not window.completed
  window.password.set_text('abcdef'); window.confirmation.set_text('abcdef')
  window.submit()
  assert not window.start.get_sensitive()
  assert window.password.get_text()==''
  checks.append(True)
 except Exception as e:
  checks.append(e); Gtk.main_quit()
 return False
GLib.timeout_add(700,verify)
GLib.timeout_add_seconds(8,lambda: (Gtk.main_quit(),False)[1])
Gtk.main()
assert checks==[True],checks
assert window.completed
window.destroy()
print(edition+': GTK validation, retry, submit and screenshot passed')
