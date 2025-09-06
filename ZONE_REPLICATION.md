# BreathGSLB Zone Replication Guide

This document explains how to configure zone replication between BreathGSLB servers to achieve high availability and redundancy.

## Overview

BreathGSLB supports standard DNS zone replication using AXFR (Authoritative Zone Transfer) and IXFR (Incremental Zone Transfer) protocols. This allows you to set up primary-secondary relationships between servers for redundancy and load distribution.

## Configuration Options

### Primary Server Configuration

To configure a server as a primary zone server:

```yaml
zones:
  - name: "example.com."
    serve: "primary"  # Optional - default behavior for zones with local records
    ns: 
      - "ns1.example.com."
      - "ns2.example.com."
    # ... other zone configuration
```

### Secondary Server Configuration

To configure a server as a secondary zone server:

```yaml
zones:
  - name: "example.com."
    serve: "secondary"  # Required for secondary zones
    masters:
      - "192.0.2.1"  # IP address of primary server
      - "2001:db8::1"  # IPv6 address of primary server (optional)
    # ... other zone configuration
```

### Zone Transfer Security with TSIG

For secure zone transfers, use TSIG (Transaction Signatures):

**Primary server TSIG configuration:**
```yaml
zones:
  - name: "example.com."
    # ... other configuration
    tsig:
      keys:
        - name: "transfer-key."
          algorithm: "hmac-sha256"
          secret: "base64encodedTSIGsecret=="
          allow_xfr_from:
            - "192.0.2.2"  # IP of secondary server
            - "2001:db8::2"  # IPv6 of secondary server
```

**Secondary server TSIG configuration:**
```yaml
zones:
  - name: "example.com."
    # ... other configuration
    tsig:
      keys:
        - name: "transfer-key."
          algorithm: "hmac-sha256"
          secret: "base64encodedTSIGsecret=="  # Must match primary
```

## Setting Up Replication

### Step 1: Configure the Primary Server

1. Define your zone with local records (A, AAAA, etc.)
2. Optionally configure TSIG for secure transfers
3. Ensure the server is listening on port 53

### Step 2: Configure the Secondary Server

1. Define the same zone name but with `serve: "secondary"`
2. Specify the primary server(s) in the `masters` list
3. Configure matching TSIG settings if security is enabled
4. Ensure the server can reach the primary on port 53

### Step 3: Verify Replication

Monitor the logs on both servers to ensure successful transfers:

**Primary server logs:**
```
INFO: Zone transfer initiated for example.com. to 192.0.2.2
INFO: Zone transfer completed for example.com. to 192.0.2.2
```

**Secondary server logs:**
```
INFO: Zone transfer initiated from 192.0.2.1 for example.com.
INFO: Zone transfer completed from 192.0.2.1 for example.com.
INFO: SOA serial updated from 2023010101 to 2023010102
```

## Best Practices

### Network Configuration

1. Ensure both servers can communicate on port 53 (TCP/UDP)
2. Configure firewall rules to allow zone transfers between servers
3. Consider using VPN or private networks for secure communication

### Security

1. Always use TSIG for production environments
2. Restrict zone transfers to specific IP addresses
3. Regularly rotate TSIG keys
4. Monitor transfer logs for unauthorized attempts

### Monitoring

1. Monitor zone serial numbers on both servers
2. Set up alerts for transfer failures
3. Regularly verify record consistency between servers

## Troubleshooting

### Common Issues

1. **Transfer refused errors**
   - Check TSIG configuration
   - Verify IP restrictions in `allow_xfr_from`
   - Ensure the zone name matches exactly

2. **Connection timeouts**
   - Check network connectivity between servers
   - Verify firewall rules
   - Check if the primary server is listening on port 53

3. **Empty zone transfers**
   - Verify the primary server has records for the zone
   - Check zone configuration on the primary server

### Diagnostic Commands

Use dig to test zone transfers:

```bash
# Test AXFR transfer
dig @ns1.example.com example.com AXFR

# Test IXFR transfer (requires known serial)
dig @ns1.example.com example.com IXFR=2023010101
```

## Advanced Configuration

### Multiple Secondary Servers

You can configure multiple secondary servers for redundancy:

```yaml
zones:
  - name: "example.com."
    serve: "secondary"
    masters:
      - "192.0.2.1"  # Primary server 1
      - "192.0.2.2"  # Primary server 2 (failover)
    # ...
```

### Notification Mechanisms

BreathGSLB supports DNS NOTIFY for immediate zone updates:

1. Configure the primary server to send NOTIFY to secondaries
2. Secondaries will initiate transfers upon receiving NOTIFY
3. This reduces propagation delay compared to polling

## Conclusion

Zone replication in BreathGSLB provides robust redundancy and high availability for your DNS infrastructure. By following the configuration guidelines and best practices outlined in this document, you can establish a reliable primary-secondary relationship between your BreathGSLB servers.