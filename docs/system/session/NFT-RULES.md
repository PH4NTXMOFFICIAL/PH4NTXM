# [ NFT RULES ]

## [ OVERVIEW ]

Loads the normal Linux/Windows nftables profile.

## [ STARTUP ]

Runs for Linux and Windows before network release.

## [ RUNTIME ]

Verifies `/etc/firewall/normal.nft` against `/etc/firewall/rules.sha256` and checks nftables syntax.  
A checksum or syntax failure stops application. A successful load is followed by best-effort connection-tracking cleanup.

## [ SOURCE ]

[ph4ntxm-nft-rules.sh](../../../config/includes.chroot/usr/local/sbin/ph4ntxm-nft-rules.sh)
