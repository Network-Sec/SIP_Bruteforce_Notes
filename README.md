# SIP BruteForce Extensions (from notes)

Built for MSF6 or higher. 
- Enable msf DB
- `use auxiliary/scanner/sip/enumerator` and succesfully enum **extensions**
- Extensions are stored in "notes" in DB
- Use this script with the same IP, it will use the extensions from DB and attempt Bruteforce

The script attempts
```msf
user1:pass1
user2:pass1
user3:pass1
...
```
instead of
```msf
user1:pass1
user1:pass2
user1:pass3
...
```

and provides a throttle option.
