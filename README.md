# SessionHound

Active Directory Session Collector for BloodHound - A professional security assessment tool for enumerating user sessions across domain computers to identify lateral movement opportunities and privileged session exposure.

## Overview

SessionHound is a companion tool to pyldapsearch designed for BloodHound data collection. It focuses specifically on enumerating user sessions via Windows RPC protocols (SRVSVC and WKSTA) to build comprehensive session maps for Active Directory environments.

**Author:** Security Tools Development
**Version:** 1.0.0
**License:** MIT

## Features

- **Multiple Session Enumeration Methods**
  - NetSessionEnum (SRVSVC) - Detailed session information with client names
  - NetWkstaUserEnum (WKSTA) - Logged-on user enumeration

- **Flexible Target Discovery**
  - LDAP automatic computer discovery
  - Manual target file input
  - Filters for enabled computers only

- **Privileged User Detection**
  - Automatic identification of privileged group memberships
  - Support for standard privileged groups (Domain Admins, Enterprise Admins, etc.)
  - AdminCount attribute detection

- **Authentication Options**
  - Password authentication
  - Pass-the-hash (NTLM)
  - Flexible credential formats

- **Enterprise-Grade Design**
  - Multi-threaded concurrent scanning
  - Progress tracking and reporting
  - BloodHound CE compatible JSON output
  - Robust error handling
  - Thread-safe operations

## Installation

### Requirements

- Python 3.7+
- impacket >= 0.11.0
- ldap3 (optional, for LDAP features)

### Install Dependencies

```bash
# Basic installation (session collection only)
pip install impacket

# Full installation (with LDAP features)
pip install impacket ldap3
```

## Usage

### Basic Examples

**1. Basic session collection with password authentication:**
```bash
python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 --ldap-query
```

**2. Pass-the-hash with manual target file:**
```bash
python3 sessionhound.py -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
    -d contoso.local --dc-ip 10.0.0.1 --target-file computers.txt --threads 20
```

**3. Collect only privileged sessions (stealthier):**
```bash
python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \
    --ldap-query --privileged --threads 15 -o privileged_sessions.json
```

**4. Stealth mode with delays and jitter:**
```bash
python3 sessionhound.py -u lowpriv -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \
    --ldap-query --threads 5 --delay 2 --jitter 30 -v
```

### Command-Line Options

#### Authentication
- `-u, --username` - Domain username (required)
- `-p, --password` - Password for authentication
- `-H, --hash` - NT hash for pass-the-hash (format: LMHASH:NTHASH or NTHASH)
- `-d, --domain` - Target domain, e.g., contoso.local (required)
- `--dc-ip` - Domain Controller IP address (required)

#### Target Specification
- `--target-file` - File containing computer names/IPs (one per line)
- `--ldap-query` - Automatically query LDAP for enabled computers

#### Operational Parameters
- `-t, --threads` - Number of concurrent threads (default: 10)
- `--privileged` - Only collect sessions for privileged users
- `-o, --output` - Output file path (default: sessions.json)
- `--timeout` - Connection timeout per host in seconds (default: 5)

#### Advanced Options
- `--delay` - Delay between queries in seconds (default: 0)
- `--jitter` - Random jitter percentage for delays, 0-100 (default: 0)
- `-v, --verbose` - Enable verbose logging

## Workflow Integration

SessionHound is designed to work alongside other BloodHound collection tools:

```bash
# Step 1: Collect LDAP data with pyldapsearch
venv/bin/pyldapsearch -dc-ip 10.0.0.1 -attributes '*,ntsecuritydescriptor' \
    contoso.local/administrator:'Password123' '(objectClass=*)' >> ldap.json

# Step 2: Collect sessions with SessionHound
python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local \
    --dc-ip 10.0.0.1 --ldap-query --threads 20 -o sessions.json

# Step 3: (Optional) Process with bofhound for BloodHound import
bofhound -o bloodhound_data.zip ldap.json sessions.json

# Step 4: Import to BloodHound CE
# Upload bloodhound_data.zip or sessions.json directly to BloodHound CE
```

## Output Format

SessionHound generates BloodHound-compatible JSON:

```json
{
  "data": [
    {
      "ComputerName": "WS001.CONTOSO.LOCAL",
      "UserName": "jdoe@CONTOSO.LOCAL",
      "IsPrivileged": false
    },
    {
      "ComputerName": "DC01.CONTOSO.LOCAL",
      "UserName": "administrator@CONTOSO.LOCAL",
      "IsPrivileged": true
    }
  ],
  "meta": {
    "type": "sessions",
    "count": 2,
    "version": 5,
    "collected": "2025-10-29T12:34:56Z"
  }
}
```

## Technical Details

### Session Collection Methods

**NetSessionEnum (SRVSVC)**
- Enumerates active SMB sessions on remote hosts
- Provides username and originating client information
- Requires standard user permissions
- More detailed than NetWkstaUserEnum

**NetWkstaUserEnum (WKSTA)**
- Enumerates currently logged-on users
- Less detailed but often returns additional results
- Standard workstation service access
- Complements NetSessionEnum data

### Privileged User Detection

When `--privileged` is enabled, SessionHound queries LDAP to identify users in:

- Domain Admins
- Enterprise Admins
- Schema Admins
- Administrators (built-in)
- Account Operators
- Server Operators
- Backup Operators
- Print Operators
- Group Policy Creator Owners
- Key Admins / Enterprise Key Admins
- Any user with adminCount=1

This reduces collection volume by filtering out standard user sessions.

### Architecture

SessionHound follows modular design principles:

1. **SessionCollector** - RPC connection and session enumeration
2. **LDAPQuerier** - LDAP-based computer discovery
3. **PrivilegedUserDetector** - Privileged group membership identification
4. **BloodHoundFormatter** - Output formatting for BloodHound
5. **SessionHoundOrchestrator** - Multi-threaded execution coordination

## Troubleshooting

### Common Issues

**1. "Access is denied" errors**
- Verify credentials are correct
- Ensure account has permissions to enumerate sessions
- Check if target hosts allow remote RPC access
- Verify firewall rules permit SMB/RPC (TCP 445)

**2. No sessions returned**
- Some environments disable NetSessionEnum/NetWkstaUserEnum
- Try different authentication methods (password vs. hash)
- Verify targets are online and accessible
- Check if SMB signing is required

**3. LDAP connection failures**
- Verify DC IP is correct and accessible
- Check DNS resolution for domain name
- Ensure credentials work for LDAP binding
- Try with verbose mode (-v) for details

**4. Performance issues**
- Reduce thread count if network is saturated
- Increase timeout for slow networks
- Add delays to spread load

### Debug Mode

Enable verbose logging for detailed troubleshooting:

```bash
python3 sessionhound.py -u user -p pass -d domain --dc-ip 10.0.0.1 \
    --ldap-query -v 2>&1 | tee sessionhound_debug.log
```

## Security Considerations

This tool is designed for authorized security assessments only. Usage requires:

- Written authorization from network/system owners
- Clear scope definition and rules of engagement
- Compliance with applicable laws and regulations
- Professional security assessment context

**Unauthorized use of this tool may be illegal.**

## Contributing

Contributions are welcome. Please ensure:
- Code follows existing style and structure
- Error handling is comprehensive
- Documentation is updated

## Credits

- Uses [Impacket](https://github.com/ThePorgs/impacket) for protocol implementation
- Companion to [pyldapsearch](https://github.com/Tw1sm/pyldapsearch)
- Designed for [BloodHound CE](https://github.com/SpecterOps/BloodHound)

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions:
- Review documentation thoroughly
- Check troubleshooting section
- Enable verbose mode for debugging
- Review impacket documentation for RPC details

## Version History

### v1.0.0 (2025-10-29)
- Initial release
- NetSessionEnum and NetWkstaUserEnum support
- LDAP computer discovery
- Privileged user filtering
- Multi-threaded collection
- BloodHound CE JSON output
- Query delays with jitter support
- Pass-the-hash support

## Future Enhancements

Potential features for future versions:
- Additional session enumeration methods
- Custom privileged group definitions
- Resume capability for large environments
- Alternative output formats (CSV, XML)
- Integration with other collection tools
- Kerberos-only authentication mode
