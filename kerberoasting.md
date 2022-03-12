# Kerberoasting

## Detection concepts (Elastic)

### System Pre-Setup
---------


### Kerberoast (RC4)

Log TGS request [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x17,0x18 [RC4](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769) and TicketOptions set to 0x40810000.

#### Custom KQL Rule

```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:("0x40810000" OR "0x40800000")  AND winlog.event_data.TicketEncryptionType:("0x17" OR "0x18")) AND (NOT (winlog.event_data.ServiceName:$*)))
```

> Ticketoptionen: 0x40800000 could be an indicator for a feature of rubeues.exe. 

[Default sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_susp_rc4_kerberos.yml)

---------

### Kerberoast (AES)
Count TGS requests [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x11,0x12 [AES](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 


**Must be set as threshold rule.**
```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:("0x40810000" OR "0x40800000")  AND winlog.event_data.TicketEncryptionType:("0x11" OR "0x12")) AND (NOT (winlog.event_data.ServiceName:$*)))
```
> Set the threshold and schedule on the volume of traffic within the infrastructure. 



---------

### Setup a honey service and log for TGS requests. 

---------
## Reference

[adsecurity.org](https://adsecurity.org/?p=3458)
