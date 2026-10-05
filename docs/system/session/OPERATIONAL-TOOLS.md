# [ OPERATIONAL TOOLS ]

## [ OVERVIEW ]

Groups the tools selected for the PH4NTXM live environment.

## [ STARTUP ]

The package list supplies the installed operational tools, while selected applications use first-run wrappers. A desktop entry being present does not mean every large upstream payload has already been downloaded.

Burp Suite and Metasploit have separate bootstrap and cache behavior. Their wrappers run in the user's context and pass launch arguments to the application.

## [ RUNTIME ]

Burp requires Java and stores its versioned JAR under the user's PH4NTXM cache. The wrapper pins both a release version and SHA-256 digest. A cached JAR is reused only after its digest matches.

A missing or invalid JAR is downloaded over HTTPS into a temporary file, with bounded connection setup and retries. The digest is checked before rename into the cache. A mismatch aborts. Download failure can open the upstream manual-download page, but it does not execute an unchecked temporary JAR.

Metasploit requires Git, Ruby, Bundler and `flock`. Its first launch downloads the latest upstream checkout into a temporary directory, then moves it into the cache after checking that the checkout is complete. Setup is locked so simultaneous launches wait for each other. An incomplete existing checkout is preserved in a recovery directory before replacement.

Each launch checks for missing tracked files and runs `bundle check`, which also validates Ruby requirements. Missing gems trigger installation into `vendor/bundle`, excluding development/test groups. The wrapper uses the system Bundler and keeps the upstream dependency lockfile frozen. Failed downloads or gem installation can be retried by reopening the launcher. A complete cached checkout is reused without an automatic source update.

Both caches follow `XDG_CACHE_HOME`, falling back to `~/.cache`, with private cache-directory creation. First use needs network access and storage for the payload/dependencies. Existing cache reuse does not imply a new download or automatic update.

In Lone Wolf, OnionShare and its CLI use PH4NTXM's system Tor SOCKS endpoint and a restricted Unix control broker instead of starting bundled Tor. Connection and bridge settings are managed by PH4NTXM. Linux and Windows retain the upstream launch behavior.

Wireshark captures as the desktop user through a group-restricted `dumpcap` helper with `CAP_NET_ADMIN` and `CAP_NET_RAW`. The graphical application does not need to run as root.

## [ CHECKS ]

For failures, distinguish a missing runtime dependency, unavailable download, integrity rejection and incomplete dependency installation. Run the wrapper in a terminal when the graphical launcher hides output.

Read the selected mode's network restrictions before expecting every tool transport to work. Lone Wolf's TCP/Tor path does not provide arbitrary UDP or raw-packet capability.

## [ SOURCE ]

[ph4ntxm-tools.list.chroot](../../../config/package-lists/ph4ntxm-tools.list.chroot)  
[0090-install-burpsuite-wrapper.chroot](../../../config/hooks/normal/0090-install-burpsuite-wrapper.chroot)  
[0092-install-metasploit-wrapper.chroot](../../../config/hooks/normal/0092-install-metasploit-wrapper.chroot)  
[ph4ntxm-onionshare](../../../config/includes.chroot/usr/local/bin/ph4ntxm-onionshare)  
[ph4ntxm-onionshare-control](../../../config/includes.chroot/usr/local/libexec/ph4ntxm-onionshare-control)  
[ph4ntxm-onionshare-control.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-onionshare-control.service)  
[0096-configure-wireshark.chroot](../../../config/hooks/normal/0096-configure-wireshark.chroot)
