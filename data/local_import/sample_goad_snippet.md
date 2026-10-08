# Sample GOAD-style writeup (local import for extensibility test)

## Recon

We scanned the lab network with nmap:

```
nmap -Pn -sC -sV 192.168.56.10-12
```

The scan revealed domain controllers and SMB services.

## AS-REP Roasting

Using a valid username list, we requested AS-REP hashes for accounts without pre-authentication:

```
GetNPUsers.py north.sevenkingdoms.local/ -usersfile users.txt -no-pass
```

We cracked one hash offline and obtained credentials for a domain user.

## Lateral movement

With the cracked credentials, we authenticated to a file server over SMB and listed shares.
