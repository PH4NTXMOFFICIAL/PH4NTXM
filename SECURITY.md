# [ SECURITY ]

## [ REPORTING A VULNERABILITY ]

Send security reports privately to [ph4ntxmofficial@proton.me](mailto:ph4ntxmofficial@proton.me).  
Do not publish exploit details in a public issue before coordination.

Use [ph4ntxm-public-key.asc](ph4ntxm-public-key.asc) for encrypted reports. Confirm the key fingerprint through a trusted independent channel.

## [ REPORT CONTENT ]

Include the source commit, build date, boot mode, affected component, and reproduction steps.  
Describe expected and observed behavior, security impact, and any local modifications.  
Attach relevant logs or packet captures with credentials and unrelated personal data removed.

## [ VALIDATION ]

Test only systems you own or are authorized to assess.  
Do not disable protection checks to obtain a passing result. Report failed checks and skipped tests explicitly.

## [ SECURITY MODEL ]

PH4NTXM is intended for bare-metal live use. Virtualized environments compromise its security model.  
Protection depends on trusted boot media and an uncompromised runtime. See [THREAT_MODEL.md](THREAT_MODEL.md) for scope and limits.

## [ SOURCE VERIFICATION ]

Verify signed source before building and retain the tested commit identifier.  
See [DISTRIBUTION.md](DISTRIBUTION.md) for verification instructions.
