# [ BROWSER POLICY ]

## [ OVERVIEW ]

Writes the Firefox enterprise policy for Linux and Windows.

## [ STARTUP ]

The one-shot service runs after local filesystems and mode selection, before the display manager. The normal-mode marker selects it for Linux and Windows.

The script also checks the mode itself: a missing or unsupported value fails, while Lone Wolf exits without writing Firefox policy.

## [ RUNTIME ]

The generated `/etc/firefox/policies/policies.json` supplies the shared Firefox enterprise settings. Linux and Windows receive the same policy. Their persona-specific preferences are supplied separately by the [browser wrapper](BROWSER.md).

The policy disables application updates, telemetry, Firefox studies, feedback commands and Pocket. It suppresses the default-browser check, clears the first-run page and hides the bookmarks toolbar.

Password-manager use, offers to save logins and form history are disabled. New location and notification requests are blocked. Hardware acceleration is disabled, and Firefox DNS-over-HTTPS is turned off so browser DNS follows the configured system resolver.

These settings are written as one JSON document under the `policies` object. The script creates the destination directory, writes a temporary file there, changes it to `0644`, then renames it to `policies.json`. Consumers receive the completed file instead of a partly written JSON document.

The helper does not launch Firefox, generate the session profile or change Tor Browser's policy. It also does not test a running browser's acceptance of the JSON. Successful file installation and successful policy loading are separate observations.

## [ CHECKS ]

Check the service's completion result and the generated JSON, then inspect `about:policies` in Firefox for active policies and parsing errors. Compare persona preferences separately with the wrapper's runtime profile.

If the service is skipped in Lone Wolf, follow [Tor Browser](TOR-BROWSER.md) rather than treating the missing Firefox policy stage as a failure.

## [ SOURCE ]

[ph4ntxm-browser-policy.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-browser-policy.sh)  
[ph4ntxm-browser-policy.service](../../../config/includes.chroot/etc/systemd/system/ph4ntxm-browser-policy.service)
