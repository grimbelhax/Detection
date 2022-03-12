# Kerberoasting

## Detection concepts (Elastic)

### System Pre-Setup
---------

[...] TGT encryption type – As mentioned before, a TGT is only read by domain controllers in the issuing domain.  As a result, the encryption type of the TGT only needs to be supported by the domain controllers.  Once your `domain functional level (DFL) is 2008 or higher, you KRBTGT account will always default to AES encryption`.  For all other account types (user and computer) the selected encryption type is determined by the `msDS-SupportedEncryptionTypes` attribute on the account.  You can modify the attribute directly or you can enable AES using the checkboxes in the Account tab. [...] [Source](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797)


- gpmc.msc
- Default Domain Policy
- Right-click Default Domain Policy and select Edit
- Click `Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options`.
- Click `Network security: Configure encryption types allowed for Kerberos`.
- Choose AES128/AES256


https://www.ibm.com/docs/en/elm/6.0?topic=encryption-enforcing-algorithms-domain-clients


### Kerberoast (RC4)

Log TGS request [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x17,0x18 [RC4](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769) and TicketOptions set to 0x40810000. 


```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:("0x40810000" OR "0x40800000")  AND winlog.event_data.TicketEncryptionType:("0x17" OR "0x18")) AND (NOT (winlog.event_data.ServiceName:$*)))
```

> Ticketoptionen: 0x40800000 could be an indicator for a feature of rubeues.exe. 


---------

### Kerberoast (AES)
Count TGS requests [4679](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4769) with encryption type 0x11,0x12 [AES](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769). 


**Must be set as threshold rule.**
```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:("0x40810000" OR "0x40800000")  AND winlog.event_data.TicketEncryptionType:("0x11" OR "0x12")) AND (NOT (winlog.event_data.ServiceName:$*)))
```
> Set the threshold and schedule on the volume of traffic within the infrastructure. 



---------

### Kerberoast (Honey Service)

Setup a honey service and log for TGS requests. 

```powershell
PS C:\> Setspn -s http/honeysvc.pwnable.net honeysvc                                       
Die Domäne "DC=pwnable,DC=net" wird überprüft.

Dienstprinzipalnamen (SPN) für CN=honeysvc,CN=Users,DC=pwnable,DC=net werden registriert.
        http/honeysvc.pwnable.net
Aktualisiertes Objekt
```

```sql
(winlog.channel:"Security" AND (winlog.event_id:"4769" AND winlog.event_data.TicketOptions:("0x40810000" OR "0x40800000")) AND winlog.event_data.ServiceName:"honeysvc")
```

---------
## Reference

- [adsecurity.org](https://adsecurity.org/?p=3458)
- [Default sigma rule](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_susp_rc4_kerberos.yml)
