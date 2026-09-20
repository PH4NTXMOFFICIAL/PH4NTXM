# [ DOCUMENT AIRLOCK ]

## [ OVERVIEW ]

Converts supported PDF, Office documents and single-frame images into an image-only PDF using an offline disposable virtual machine.

## [ STARTUP ]

Available through the applications menu and default associations for PDF and Office documents. Opening a file starts conversion.  
Supported images remain available through Open With or the document chooser.  
Runs from the desktop account after checking KVM access, isolation support and available memory.

## [ RUNTIME ]

Parses and renders the document inside the guest. The host validates returned pixels and constructs a new PDF without copying original metadata or active content.  
Allows one conversion per account with bounded memory, page count and execution time.  
Displays converted pages for review and explicit export to a new filename. The original remains unchanged; visible personal information remains in the rendered pages.  
Cancellation or timeout terminates the VM. Closing the window discards temporary results.

## [ SOURCE ]

[ph4ntxm-document-airlock](../../../config/includes.chroot/usr/local/bin/ph4ntxm-document-airlock)  
[airlock.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/airlock.py)  
[guest.py](../../../config/includes.chroot/usr/local/src/ph4ntxm-document-airlock/guest.py)
