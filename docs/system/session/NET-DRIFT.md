# [ NET DRIFT ]

## [ OVERVIEW ]

Applies changing netem timing and packet variation to Linux/Windows default-route interfaces.

## [ STARTUP ]

The normal-mode service follows network-online and network randomization. It requires the saved persona seed and boot jitter. Lone Wolf exits without entering the loop.

Optional positional values provide initial delay, jitter and loss. Defaults are 20 ms, 5 ms and 1 percent. Inputs are clamped to 5–150 ms delay, 1–50 ms jitter and 0–5 percent loss.

## [ RUNTIME ]

Before each update, the process sleeps for a fresh 20–59 seconds. Delay then moves by at most two milliseconds, while jitter and loss move by at most one unit. Every update reapplies the same bounds.

Only interfaces with an IPv4 address and a default route qualify. Loopback and common virtual, container, tunnel, WireGuard and dummy prefixes are excluded. Wireless interfaces receive tighter limits: jitter stays at or below 10 ms and loss at or below one percent.

For each qualifying interface, `tc qdisc replace` installs a root netem qdisc with normally distributed delay, the selected loss, 0.02 percent duplication and 0.05 percent reordering. This affects actual traffic. It is separate from the locally generated delay metadata stored by network randomization.

Failed qdisc updates are tolerated so the loop can continue. Successfully managed interfaces are tracked in memory. Normal exit, interrupt or termination removes their root qdiscs. It does not restore an earlier custom root qdisc that was replaced.

The service restarts the process if it exits. A forced kill cannot run shell cleanup, so process absence alone does not establish that all previously installed qdiscs are gone.

## [ CHECKS ]

Use `tc qdisc show` on the active routed interface and inspect the service journal. Allow for the initial sleep before expecting a netem entry.

When investigating delay or loss, compare the active qdisc with the selected bounds and wireless caps. An interface with no default route is deliberately skipped. A failed update is not a reason to expect the whole service to stop.

## [ SOURCE ]

[ph4ntxm-net-drift.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-net-drift.sh)
