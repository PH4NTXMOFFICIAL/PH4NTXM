# [ LINK JITTER ]

## [ OVERVIEW ]

Adds a randomized delay before the network-release sequence proceeds.

## [ STARTUP ]

The one-shot follows Link Block and the DHCP generator dependencies. Mode conditions select the applicable generator. Its ordering keeps it ahead of network preparation and NetworkManager.

The executable stage is deliberately small: it draws an integer from two through seven with `shuf`, then sleeps for that many seconds.

## [ RUNTIME ]

The delay shifts the timing of the startup chain once. It does not alter packet contents, DHCP options, interface addresses or the kernel TCP/IP profile. The following services remain responsible for their own checks.

Each invocation draws again. The value is not saved in `/run/ph4ntxm`, and it is unrelated to the `boot_jitter` record used by hardware and persona generation. Reusing that name as an explanation for both would hide two different mechanisms.

There is no recurring timer or background loop after the sleep finishes. This unit does not use `RemainAfterExit`, so an inactive state after a successful one-shot is not by itself a failure.

With shell error handling enabled, a failed random draw or sleep prevents normal completion. No persistent settings have been changed by this script, so there is no configuration rollback to perform.

Actual per-packet timing changes belong to [Network Drift](NET-DRIFT.md), while the final decision to raise prepared physical adapters belongs to [Link Unblock](LINK-UNBLOCK.md). Completing this delay alone authorizes neither.

## [ CHECKS ]

Read the unit's result and exit status when checking boot ordering. A successful completed one-shot should not be judged using only whether a long-running process is present.

An observed wait of two to seven seconds is expected here. Longer startup delays can come from preceding dependencies or later readiness checks. This script does not contain a second wait loop.

## [ SOURCE ]

[ph4ntxm-link-jitter.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-link-jitter.sh)
