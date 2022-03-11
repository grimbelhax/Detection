# Kerberoasting

## Detection concepts (Elastic)

### System Pre-Setup
---------


### Log TGS request [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) request with encryption type 0x17,0x18 [RC4](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 

#### Custom KQL Rule.

```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:"0x40810000" AND winlog.event_data.TicketEncryptionType:"0x17") AND (NOT (winlog.event_data.ServiceName:$*)))
```

[Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_susp_rc4_kerberos.yml)

---------

### Count TGS requests [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) request with encryption type 0x11,0x12 [AES](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 

```sql
(@timestamp >= "now-120m" and winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:"0x40810000" AND winlog.event_data.TicketEncryptionType:"0x17") AND (NOT (winlog.event_data.ServiceName:$*)))
```


---------

### Setup a honey service and log for TGS requests. 

---------
## Reference

[adsecurity.org](https://adsecurity.org/?p=3458)
