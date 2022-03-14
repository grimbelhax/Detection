# Kerberoasting

## Detection concepts (Elastic)

### Prior Knowledge

- In a Domain with Windows Server 2016 and older as Domain Controller enabled AES encryption is not enforced.
- In a Domain with Windows Server 2019 as Domain Controller enabled AES encryption is enforced. It returns highest encryption which service account supports.


### System Pre-Setup
---------

- To enforce AES on a specific account: `This account supports Kerberos AES 128/256 bit encryption` in Active Directory Users and Computers user properties.

- Enable kerberos eventlogs on the DC.
```
auditpol /set /category:"account logon" /subcategory:"kerberos Authentication Service" /success:enable
auditpol /set /category:"account logoff" /subcategory:"kerberos Authentication Service" /failure:enable
```

- Setup a honey service and log for TGS requests. 

```powershell
PS C:\> Setspn -s http/honeysvc.pwnable.net honeysvc                                       
Die Domäne "DC=pwnable,DC=net" wird überprüft.

Dienstprinzipalnamen (SPN) für CN=honeysvc,CN=Users,DC=pwnable,DC=net werden registriert.
        http/honeysvc.pwnable.net
Aktualisiertes Objekt
```
----

### Kerberoast (RC4)

Count TGS requests [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x17,0x18 [RC4](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 

**Must be set as threshold rule.**
```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketEncryptionType:("0x17" OR "0x18")) AND (NOT (winlog.event_data.ServiceName:$*)))
```
> Set the threshold and schedule on the volume of traffic within the infrastructure. 


---------

### Kerberoast (AES)
Count TGS requests [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x11,0x12 [AES](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 


**Must be set as threshold rule.**
```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketEncryptionType:("0x11" OR "0x12")) AND (NOT (winlog.event_data.ServiceName:$*)))
```
> Set the threshold and schedule on the volume of traffic within the infrastructure. 



---------

### Kerberoast (Honey Service)



```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.ServiceName:"honeysvc")
```

---------

## Further Investigation

### Tool Indicators

- Ticketoptionen: `0x40800000` could be an indicator for a feature of `rubeues.exe kerberoast`. 
- Ticketoptionen: `0x40800010` could be an indicator for a feature of `rubeues.exe kerberoast /tgtdeleg`. 
- Ticketoptionen: `0x40810000` could be an indicator for a feature of `Invoke-Kerberoast` (Powerview). 

## References

- [adsecurity.org](https://adsecurity.org/?p=3458)
- [Default sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_susp_rc4_kerberos.yml)
- [Good summary](https://dev-2null.github.io/Kerberoasting-AES-Encryption-Protected-Users-Group-and-gMSA/)



