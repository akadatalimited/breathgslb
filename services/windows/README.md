# Windows service for BreathGSLB

This directory provides a registry file to run BreathGSLB as a Windows service.

## Installation

1. Place `breathgslb.exe` and `config.yaml` in `C:\breathgslb`.
2. Import the service definition from an elevated prompt:
   ```cmd
   reg import breathgslb.reg
   ```
3. Start the service:
   ```cmd
   net start BreathGSLB
   ```
4. Open firewall ports:
   ```cmd
   netsh advfirewall firewall add rule name="BreathGSLB DNS UDP" dir=in
       action=allow protocol=UDP localport=53
   netsh advfirewall firewall add rule name="BreathGSLB DNS TCP" dir=in
       action=allow protocol=TCP localport=53
   ```

Adjust paths in `breathgslb.reg` if your installation differs.
