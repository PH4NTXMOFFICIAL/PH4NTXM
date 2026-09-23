# [ OPERATIONAL TOOLS ]

## [ OVERVIEW ]

Groups the tools selected for the PH4NTXM live environment.

## [ STARTUP ]

The package list supplies the installed operational tools, while selected applications use first-run wrappers. A desktop entry being present does not mean every large upstream payload has already been downloaded.

Burp Suite and Metasploit have separate bootstrap and cache behavior. Their wrappers run in the user's context and pass launch arguments to the application.

## [ RUNTIME ]

Burp requires Java and stores its versioned JAR under the user's PH4NTXM cache. The wrapper pins both a release version and SHA-256 digest. A cached JAR is reused only after its digest matches.

A missing or invalid JAR is downloaded over HTTPS into a temporary file, with bounded connection setup and retries. The digest is checked before rename into the cache. A mismatch aborts. Download failure can open the upstream manual-download page, but it does not execute an unchecked temporary JAR.

Metasploit requires Git, Ruby and Bundler. On first use, it shallow-clones the upstream framework when no checkout exists, installs gems into the local `vendor/bundle` path and excludes development/test dependency groups.

Its ready marker is created only after bundle installation succeeds. Later launches reuse an executable `msfconsole` with that marker. Unlike the Burp wrapper, this bootstrap is not pinned to a specific commit/digest and does not revalidate the cached checkout on each launch.

Both caches follow `XDG_CACHE_HOME`, falling back to `~/.cache`, with private cache-directory creation. First use needs network access and storage for the payload/dependencies. Existing cache reuse does not imply a new download or automatic update.

## [ CHECKS ]

For failures, distinguish a missing runtime dependency, unavailable download, integrity rejection and incomplete dependency installation. Run the wrapper in a terminal when the graphical launcher hides output.

Read the selected mode's network restrictions before expecting every tool transport to work. Lone Wolf's TCP/Tor path does not provide arbitrary UDP or raw-packet capability.

## [ SOURCE ]

[ph4ntxm-tools.list.chroot](../../../config/package-lists/ph4ntxm-tools.list.chroot)  
[0090-install-burpsuite-wrapper.chroot](../../../config/hooks/normal/0090-install-burpsuite-wrapper.chroot)  
[0092-install-metasploit-wrapper.chroot](../../../config/hooks/normal/0092-install-metasploit-wrapper.chroot)
