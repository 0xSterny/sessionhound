#!/usr/bin/env python3
"""
SessionHound - Active Directory Session Collector for BloodHound CE

This tool enumerates user sessions on domain computers using Windows RPC protocols
(SRVSVC and SAMR) to identify lateral movement opportunities and privileged session
exposure. Outputs data in BloodHound CE JSON format with proper SID resolution.

Author: Security Tools Development
License: MIT
Version: 3.0.0

Dependencies:
    - impacket >= 0.11.0
    - ldap3 (for LDAP queries and SID resolution)
    - dnspython (for custom DNS resolution with --dc-ip)

Usage Examples:
    # Basic session collection with password authentication
    python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1

    # Pass-the-hash with target file
    python3 sessionhound.py -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \\
        -d contoso.local --dc-ip 10.0.0.1 --target-file computers.txt --threads 20

    # Privileged sessions only with LDAP auto-discovery
    python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --privileged --threads 15 -o privileged_sessions.json

    # Loud mode with all collection methods (requires admin)
    python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --loud -o sessions_loud.json

    # Custom DNS server (different from DC)
    python3 sessionhound.py -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --dns 10.0.0.2 --ldap-query --threads 10

    # Stealth mode with delays and jitter
    python3 sessionhound.py -u lowpriv -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --threads 5 --delay 2 --jitter 30

Operational Security:
    - Use --threads carefully (lower = stealthier)
    - Enable --delay and --jitter to avoid detection
    - Consider --privileged to reduce query volume
    - Monitor for authentication failures
    - SID resolution requires LDAP queries (pre-caches all SIDs for efficiency)

Output Format:
    BloodHound CE JSON format with per-computer objects:
    - data: Array of computer objects with full LDAP properties
    - Each computer includes Sessions/PrivilegedSessions/RegistrySessions
    - meta: Collection metadata (type: "computers", count, version, timestamp)

    All sessions include ComputerSID and UserSID for direct import to BloodHound CE.
    Computer objects include full LDAP attributes matching BloodHound CE schema.

Integration:
    Output can be imported directly into BloodHound CE via the UI or API.
    The JSON structure matches the expected schema for session data ingestion.
"""

import argparse
import json
import logging
import random
import sys
import time
import threading
from datetime import datetime
from pathlib import Path
from queue import Queue
from typing import List, Dict, Set, Optional, Tuple

# Impacket imports
try:
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.dcerpc.v5 import transport, srvs, samr, wkst, rrp, tsch
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
except ImportError:
    print("[!] Error: impacket library not found. Install with: pip install impacket")
    sys.exit(1)

# LDAP3 imports (optional, for LDAP query functionality)
try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False

# DNS imports for custom DNS resolution
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

# BloodHound output version
BLOODHOUND_VERSION = 5

# Well-known privileged group SIDs
PRIVILEGED_SIDS = {
    'S-1-5-32-544',  # Administrators
    'S-1-5-32-548',  # Account Operators
    'S-1-5-32-549',  # Server Operators
    'S-1-5-32-550',  # Print Operators
    'S-1-5-32-551',  # Backup Operators
}

# Domain-relative privileged RIDs
PRIVILEGED_RIDS = {
    '512',  # Domain Admins
    '513',  # Domain Users (included for reference, typically not privileged)
    '514',  # Domain Guests
    '515',  # Domain Computers
    '516',  # Domain Controllers
    '517',  # Cert Publishers
    '518',  # Schema Admins
    '519',  # Enterprise Admins
    '520',  # Group Policy Creator Owners
    '521',  # Read-only Domain Controllers
    '522',  # Cloneable Domain Controllers
    '526',  # Key Admins
    '527',  # Enterprise Key Admins
}

# Privileged group names (case-insensitive matching)
PRIVILEGED_GROUPS = {
    'domain admins',
    'enterprise admins',
    'schema admins',
    'administrators',
    'account operators',
    'server operators',
    'backup operators',
    'print operators',
    'group policy creator owners',
    'key admins',
    'enterprise key admins',
}


# ============================================================================
# DNS RESOLUTION MODULE
# ============================================================================

class DNSResolver:
    """
    Handles DNS resolution using a specified DNS server (typically the DC).
    Falls back to system DNS if custom DNS is not configured.
    """

    def __init__(self, dns_server: Optional[str] = None, timeout: int = 5):
        """
        Initialize DNS resolver.

        Args:
            dns_server: DNS server IP to use for queries (typically DC IP)
            timeout: DNS query timeout in seconds
        """
        self.dns_server = dns_server
        self.timeout = timeout
        self.logger = logging.getLogger('DNSResolver')

        # Create custom resolver if DNS server specified
        if self.dns_server and DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver(configure=False)
            self.resolver.nameservers = [self.dns_server]
            self.resolver.timeout = timeout
            self.resolver.lifetime = timeout
            self.logger.debug(f"Configured DNS resolver to use {self.dns_server}")
        else:
            # Use default system resolver
            if DNS_AVAILABLE:
                self.resolver = dns.resolver.Resolver()
                self.resolver.timeout = timeout
                self.resolver.lifetime = timeout
            else:
                self.resolver = None
            self.logger.debug("Using system DNS resolver")

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """
        Resolve a hostname to an IP address.

        Args:
            hostname: Hostname or FQDN to resolve

        Returns:
            IP address as string, or None if resolution fails
        """
        # If it's already an IP address, return as-is
        if self._is_ip_address(hostname):
            return hostname

        # Strip leading backslashes and whitespace
        hostname = hostname.lstrip('\\').strip()

        # Try DNS resolution
        if self.resolver:
            try:
                answers = self.resolver.resolve(hostname, 'A')
                if answers:
                    ip = str(answers[0])
                    self.logger.debug(f"Resolved {hostname} -> {ip}")
                    return ip
            except dns.exception.Timeout:
                self.logger.debug(f"DNS timeout resolving {hostname}")
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"DNS NXDOMAIN for {hostname}")
            except dns.resolver.NoAnswer:
                self.logger.debug(f"DNS no answer for {hostname}")
            except Exception as e:
                self.logger.debug(f"DNS resolution error for {hostname}: {e}")
        else:
            # dnspython not available, use socket as fallback
            try:
                import socket
                ip = socket.gethostbyname(hostname)
                self.logger.debug(f"Resolved {hostname} -> {ip} (socket fallback)")
                return ip
            except Exception as e:
                self.logger.debug(f"Socket resolution error for {hostname}: {e}")

        # If resolution fails, return the original hostname
        # Impacket will try to resolve it on its own
        self.logger.debug(f"Failed to resolve {hostname}, returning original")
        return hostname

    def _is_ip_address(self, value: str) -> bool:
        """
        Check if a string is an IPv4 address.

        Args:
            value: String to check

        Returns:
            True if value is an IP address
        """
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, AttributeError):
            return False


# ============================================================================
# SESSION COLLECTION MODULE
# ============================================================================

class SessionCollector:
    """
    Handles RPC connections and session enumeration for individual hosts.
    Uses Impacket's SRVSVC and WKSTA interfaces for session collection.
    Supports loud mode with WMI, Remote Registry, and Terminal Services enumeration.
    """

    def __init__(self, username: str, password: str, domain: str,
                 lmhash: str = '', nthash: str = '', timeout: int = 5,
                 dns_resolver: Optional[DNSResolver] = None, loud_mode: bool = False):
        """
        Initialize the session collector with credentials.

        Args:
            username: Domain username
            password: Password (can be empty if using hash)
            domain: Target domain
            lmhash: LM hash for pass-the-hash
            nthash: NT hash for pass-the-hash
            timeout: Connection timeout in seconds
            dns_resolver: Optional DNS resolver for hostname resolution
            loud_mode: Enable aggressive multi-method enumeration (requires admin)
        """
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.timeout = timeout
        self.dns_resolver = dns_resolver
        self.loud_mode = loud_mode
        self.logger = logging.getLogger('SessionCollector')

    def collect_sessions_netsessionenum(self, target: str) -> List[Dict[str, str]]:
        """
        Collect sessions using NetSessionEnum (SRVSVC RPC).

        Args:
            target: Target hostname or IP

        Returns:
            List of session dictionaries with username and computer information
        """
        sessions = []

        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return sessions

        try:
            # Establish SMB connection
            smb_string = f'ncacn_np:{resolved_target}[\\pipe\\srvsvc]'
            rpctransport = transport.DCERPCTransportFactory(smb_string)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash
            )
            rpctransport.set_connect_timeout(self.timeout)

            # Connect and bind to SRVSVC
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            # Call NetSessionEnum
            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

            # Parse response
            for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                username = session['sesi10_username'][:-1]  # Remove null terminator
                client = session['sesi10_cname'][:-1]

                # Filter out empty or system sessions
                if username and username != '' and not username.endswith('$'):
                    sessions.append({
                        'username': username,
                        'client': client,
                        'target': target,
                        'method': 'NetSessionEnum'
                    })

            dce.disconnect()

        except SessionError as e:
            self.logger.debug(f"SMB Session error on {target}: {e}")
        except DCERPCException as e:
            self.logger.debug(f"RPC error on {target}: {e}")
        except Exception as e:
            self.logger.debug(f"Unexpected error on {target}: {e}")

        return sessions

    def collect_sessions_netwkstauserenum(self, target: str) -> List[Dict[str, str]]:
        """
        Collect sessions using NetWkstaUserEnum (WKSTA RPC).

        Args:
            target: Target hostname or IP

        Returns:
            List of session dictionaries with username and computer information
        """
        sessions = []

        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return sessions

        try:
            # Establish SMB connection
            smb_string = f'ncacn_np:{resolved_target}[\\pipe\\wkssvc]'
            rpctransport = transport.DCERPCTransportFactory(smb_string)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash
            )
            rpctransport.set_connect_timeout(self.timeout)

            # Connect and bind to WKSTA
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)

            # Call NetWkstaUserEnum
            resp = wkst.hNetrWkstaUserEnum(dce, 1)

            # Parse response
            for user in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
                username = user['wkui1_username'][:-1]  # Remove null terminator

                # Filter out empty or system sessions
                if username and username != '' and not username.endswith('$'):
                    sessions.append({
                        'username': username,
                        'client': '',  # NetWkstaUserEnum doesn't provide client info
                        'target': target,
                        'method': 'NetWkstaUserEnum'
                    })

            dce.disconnect()

        except SessionError as e:
            self.logger.debug(f"SMB Session error on {target}: {e}")
        except DCERPCException as e:
            self.logger.debug(f"RPC error on {target}: {e}")
        except Exception as e:
            self.logger.debug(f"Unexpected error on {target}: {e}")

        return sessions

    def check_admin_access(self, target: str) -> bool:
        """
        Check if the authenticating user has admin rights on the target.

        Args:
            target: Target hostname or IP

        Returns:
            True if admin access is available, False otherwise
        """
        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return False

        try:
            # Try to connect to ADMIN$ share
            smb = SMBConnection(resolved_target, resolved_target, timeout=self.timeout)

            if self.nthash:
                smb.login(self.username, '', self.domain, self.lmhash, self.nthash)
            else:
                smb.login(self.username, self.password, self.domain, self.lmhash, self.nthash)

            # Try to list ADMIN$ share
            smb.listPath('ADMIN$', '/*')
            smb.logoff()

            self.logger.debug(f"Admin access confirmed on {target}")
            return True

        except Exception as e:
            self.logger.debug(f"No admin access on {target}: {e}")
            return False

    def collect_sessions_wmi(self, target: str) -> List[Dict[str, str]]:
        """
        Collect sessions using WMI (Win32_LoggedOnUser and Win32_LogonSession).
        Requires admin access.

        Args:
            target: Target hostname or IP

        Returns:
            List of session dictionaries with username and logon type information
        """
        sessions = []

        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return sessions

        try:
            # Establish DCOM connection
            dcom = DCOMConnection(
                resolved_target,
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                oxidResolver=True,
                doKerberos=False
            )

            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Query Win32_LoggedOnUser
            iEnumWbemClassObject = iWbemServices.ExecQuery('SELECT * FROM Win32_LoggedOnUser')

            logged_users = set()
            while True:
                try:
                    wbemClassObject = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

                    # Get the Antecedent property (user reference)
                    antecedent = wbemClassObject.getProperties().get('Antecedent', {}).get('value', '')

                    # Parse username from WMI object reference
                    # Format: \\COMPUTER\root\cimv2:Win32_Account.Domain="DOMAIN",Name="username"
                    if antecedent and 'Name=' in antecedent:
                        try:
                            name_part = antecedent.split('Name=')[1].strip('"')
                            domain_part = antecedent.split('Domain=')[1].split(',')[0].strip('"')

                            username = name_part
                            if domain_part:
                                username = f"{domain_part}\\{name_part}"

                            # Filter out system accounts
                            if username and not username.upper().endswith('$'):
                                logged_users.add(username)

                        except Exception as e:
                            self.logger.debug(f"Error parsing WMI user reference: {e}")

                except Exception:
                    break

            # Convert to session format
            for username in logged_users:
                sessions.append({
                    'username': username,
                    'client': '',
                    'target': target,
                    'method': 'WMI'
                })

            # Cleanup
            iEnumWbemClassObject.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()

        except Exception as e:
            self.logger.debug(f"WMI enumeration error on {target}: {e}")

        return sessions

    def collect_sessions_registry(self, target: str) -> List[Dict[str, str]]:
        """
        Collect sessions using Remote Registry (HKEY_USERS enumeration).
        Requires admin access.

        Args:
            target: Target hostname or IP

        Returns:
            List of session dictionaries with username information from loaded profiles
        """
        sessions = []

        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return sessions

        try:
            # Establish SMB connection for RRP
            smb_string = f'ncacn_np:{resolved_target}[\\pipe\\winreg]'
            rpctransport = transport.DCERPCTransportFactory(smb_string)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash
            )
            rpctransport.set_connect_timeout(self.timeout)

            # Connect and bind to RRP (Remote Registry Protocol)
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)

            # Open HKEY_USERS
            ans = rrp.hOpenUsers(dce)
            reg_handle = ans['phKey']

            # Enumerate subkeys (loaded user profiles)
            i = 0
            user_sids = []
            while True:
                try:
                    ans2 = rrp.hBaseRegEnumKey(dce, reg_handle, i)
                    sid = ans2['lpNameOut'][:-1]  # Remove null terminator

                    # Filter for user SIDs (starts with S-1-5-21)
                    # Exclude built-in accounts and service SIDs
                    if sid.startswith('S-1-5-21-') and not sid.endswith('_Classes'):
                        user_sids.append(sid)

                    i += 1
                except DCERPCException:
                    break

            # Close registry handle
            rrp.hBaseRegCloseKey(dce, reg_handle)
            dce.disconnect()

            # Resolve SIDs to usernames using SAMR
            for sid in user_sids:
                username = self._resolve_sid_to_username(resolved_target, sid)
                if username and not username.endswith('$'):
                    sessions.append({
                        'username': username,
                        'client': '',
                        'target': target,
                        'method': 'Registry'
                    })

        except Exception as e:
            self.logger.debug(f"Registry enumeration error on {target}: {e}")

        return sessions

    def _resolve_sid_to_username(self, target: str, sid: str) -> Optional[str]:
        """
        Resolve a SID to a username using SAMR.

        Args:
            target: Target hostname or IP
            sid: Security Identifier to resolve

        Returns:
            Username if resolved, None otherwise
        """
        try:
            # Connect to SAMR
            smb_string = f'ncacn_np:{target}[\\pipe\\samr]'
            rpctransport = transport.DCERPCTransportFactory(smb_string)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash
            )
            rpctransport.set_connect_timeout(self.timeout)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Open domain
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            # Lookup SID
            resp = samr.hSamrLookupIdsInDomain(dce, server_handle, [sid])

            if resp['Names']:
                username = resp['Names'][0]['Name']
                dce.disconnect()
                return username

            dce.disconnect()

        except Exception as e:
            self.logger.debug(f"SID resolution error for {sid}: {e}")

        return None

    def collect_sessions_rdp(self, target: str) -> List[Dict[str, str]]:
        """
        Collect RDP/Terminal Services sessions.
        Requires admin access. Uses WMI to query Terminal Services information.

        Args:
            target: Target hostname or IP

        Returns:
            List of session dictionaries with RDP session information
        """
        sessions = []

        # Resolve hostname if DNS resolver is configured
        resolved_target = target
        if self.dns_resolver:
            resolved_target = self.dns_resolver.resolve_hostname(target)
            if not resolved_target:
                self.logger.debug(f"Failed to resolve {target}")
                return sessions

        try:
            # Establish DCOM connection
            dcom = DCOMConnection(
                resolved_target,
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                oxidResolver=True,
                doKerberos=False
            )

            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Query Win32_Process for RDP-related processes
            # This helps identify active RDP sessions
            iEnumWbemClassObject = iWbemServices.ExecQuery(
                'SELECT * FROM Win32_Process WHERE Name="rdpclip.exe" OR Name="tstheme.exe"'
            )

            rdp_users = set()
            while True:
                try:
                    wbemClassObject = iEnumWbemClassObject.Next(0xffffffff, 1)[0]

                    # Get process owner
                    try:
                        getowner_result = wbemClassObject.Methods('GetOwner')
                        if getowner_result:
                            username = getowner_result.get('User', '')
                            domain = getowner_result.get('Domain', '')

                            if username and not username.endswith('$'):
                                full_username = f"{domain}\\{username}" if domain else username
                                rdp_users.add(full_username)
                    except Exception:
                        pass

                except Exception:
                    break

            # Convert to session format
            for username in rdp_users:
                sessions.append({
                    'username': username,
                    'client': '',
                    'target': target,
                    'method': 'TerminalServices'
                })

            # Cleanup
            iEnumWbemClassObject.RemRelease()
            iWbemServices.RemRelease()
            dcom.disconnect()

        except Exception as e:
            self.logger.debug(f"RDP enumeration error on {target}: {e}")

        return sessions

    def collect_all_sessions(self, target: str) -> List[Dict[str, str]]:
        """
        Collect sessions from a target using all available methods.
        In loud mode, performs admin check and additional enumeration.

        Args:
            target: Target hostname or IP

        Returns:
            Combined list of sessions from all enumeration methods
        """
        all_sessions = []

        # Step 1: Standard collection (always runs)
        # Try NetSessionEnum first (provides more information)
        sessions = self.collect_sessions_netsessionenum(target)
        if sessions:
            all_sessions.extend(sessions)
            self.logger.debug(f"NetSessionEnum on {target}: {len(sessions)} sessions")

        # Try NetWkstaUserEnum as backup/additional source
        sessions = self.collect_sessions_netwkstauserenum(target)
        if sessions:
            all_sessions.extend(sessions)
            self.logger.debug(f"NetWkstaUserEnum on {target}: {len(sessions)} sessions")

        # Step 2: Loud mode - additional enumeration methods
        if self.loud_mode:
            # Check for admin access
            has_admin = self.check_admin_access(target)

            if has_admin:
                self.logger.debug(f"[LOUD] Admin access confirmed on {target}, running additional methods")

                # Method 3: WMI enumeration
                sessions = self.collect_sessions_wmi(target)
                if sessions:
                    all_sessions.extend(sessions)
                    self.logger.debug(f"[LOUD] WMI on {target}: {len(sessions)} sessions")

                # Method 4: Remote Registry enumeration
                sessions = self.collect_sessions_registry(target)
                if sessions:
                    all_sessions.extend(sessions)
                    self.logger.debug(f"[LOUD] Registry on {target}: {len(sessions)} sessions")

                # Method 5: Terminal Services/RDP enumeration
                sessions = self.collect_sessions_rdp(target)
                if sessions:
                    all_sessions.extend(sessions)
                    self.logger.debug(f"[LOUD] TerminalServices on {target}: {len(sessions)} sessions")

            else:
                self.logger.debug(f"[LOUD] No admin access on {target}, skipping additional methods")

        return all_sessions


# ============================================================================
# LDAP HELPER FUNCTIONS
# ============================================================================

# UAC (User Account Control) flags
UAC_ACCOUNTDISABLE = 0x00000002
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000


def windows_timestamp_to_unix(windows_timestamp):
    """
    Convert Windows FILETIME to Unix epoch timestamp.

    Args:
        windows_timestamp: Windows FILETIME (100-nanosecond intervals since 1601-01-01)

    Returns:
        Unix epoch timestamp (seconds since 1970-01-01), or 0 if invalid
    """
    if not windows_timestamp or windows_timestamp == 0:
        return 0
    try:
        # Windows FILETIME is 100-nanosecond intervals since 1601-01-01
        # Unix epoch is seconds since 1970-01-01
        EPOCH_DIFF = 116444736000000000  # 100-ns intervals between 1601 and 1970
        unix_timestamp = (int(windows_timestamp) - EPOCH_DIFF) // 10000000
        return max(0, unix_timestamp)  # Ensure non-negative
    except (ValueError, TypeError):
        return 0


def parse_uac_flags(uac_value):
    """
    Parse User Account Control flags.

    Args:
        uac_value: UAC integer value from LDAP

    Returns:
        Dictionary with parsed UAC flags
    """
    try:
        uac = int(uac_value)
        return {
            'enabled': not (uac & UAC_ACCOUNTDISABLE),
            'unconstraineddelegation': bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            'trustedtoauth': bool(uac & UAC_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)
        }
    except (ValueError, TypeError):
        return {
            'enabled': True,
            'unconstraineddelegation': False,
            'trustedtoauth': False
        }


def extract_domain_sid(sid):
    """
    Extract domain SID from computer/user SID.

    Args:
        sid: Full SID (e.g., S-1-5-21-XXXX-YYYY-ZZZZ-RID)

    Returns:
        Domain SID (e.g., S-1-5-21-XXXX-YYYY-ZZZZ)
    """
    if not sid:
        return None
    parts = sid.rsplit('-', 1)
    return parts[0] if len(parts) == 2 else sid


def build_primary_group_sid(domain_sid, primary_group_id):
    """
    Build primary group SID from domain SID and primary group RID.

    Args:
        domain_sid: Domain SID (S-1-5-21-...)
        primary_group_id: Primary group RID (e.g., 515)

    Returns:
        Full primary group SID
    """
    if not domain_sid or not primary_group_id:
        return None
    try:
        return f"{domain_sid}-{int(primary_group_id)}"
    except (ValueError, TypeError):
        return None


# ============================================================================
# LDAP QUERY MODULE
# ============================================================================

class LDAPQuerier:
    """
    Handles LDAP queries to automatically discover computer objects in the domain.
    """

    def __init__(self, dc_ip: str, domain: str, username: str, password: str,
                 lmhash: str = '', nthash: str = '', loud_mode: bool = False):
        """
        Initialize LDAP querier with connection parameters.

        Args:
            dc_ip: Domain Controller IP address
            domain: Target domain
            username: Domain username
            password: Password
            lmhash: LM hash for pass-the-hash
            nthash: NT hash for pass-the-hash
            loud_mode: Enable full LDAP attribute retrieval (default: False for minimal queries)
        """
        if not LDAP3_AVAILABLE:
            raise ImportError("ldap3 library is required for LDAP queries. Install with: pip install ldap3")

        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.loud_mode = loud_mode
        self.logger = logging.getLogger('LDAPQuerier')

    def get_computers(self) -> Dict[str, Dict]:
        """
        Query LDAP for all enabled computer objects with full properties.
        Implements LDAP paging to retrieve all results beyond the 1000 limit.

        Returns:
            Dictionary mapping computer SID to computer properties dict:
            {
                'S-1-5-21-...-1234': {
                    'dns_name': 'COMPUTER.DOMAIN.COM',
                    'object_identifier': 'S-1-5-21-...-1234',
                    'primary_group_sid': 'S-1-5-21-...-515',
                    'allowed_to_delegate': [],
                    'properties': {...},
                    'sid_history': []
                }
            }
        """
        computers = {}

        try:
            # Build base DN from domain
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])

            # Create server and connection
            server = Server(self.dc_ip, get_info=ALL)

            # Determine authentication method
            if self.nthash:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM, auto_bind=True
                )
            else:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )

            # Query for computer objects with paging
            # Filter: computers that are enabled (not disabled via UAC)
            ldap_filter = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'

            # Define attribute sets based on mode
            if self.loud_mode:
                # Full attribute set for detailed analysis
                # Note: ms-MCS-AdmPwd (LAPS) removed to avoid compatibility issues with
                # domains that don't have LAPS deployed. LDAP queries will fail if this
                # attribute is requested but not present in the schema.
                attributes = [
                    'objectSid', 'dNSHostName', 'sAMAccountName', 'distinguishedName',
                    'primaryGroupID', 'userAccountControl', 'msDS-AllowedToDelegateTo',
                    'lastLogon', 'lastLogonTimestamp', 'pwdLastSet', 'whenCreated',
                    'servicePrincipalName', 'description', 'operatingSystem', 'sIDHistory',
                    'name'
                ]
                self.logger.info("Loud mode: querying LDAP for full computer properties (16 attributes)...")
            else:
                # Minimal attribute set for session collection only
                attributes = [
                    'objectSid',
                    'dNSHostName',
                    'sAMAccountName',
                    'primaryGroupID'
                ]
                self.logger.info("Standard mode: querying LDAP for minimal computer properties (4 attributes)...")

            # Use paged search to retrieve all results (AD default page limit is 1000)
            page_size = 1000
            page_count = 0
            total_entries = 0

            # Perform paged search using ldap3's paged_search generator
            entry_generator = conn.extend.standard.paged_search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                paged_size=page_size,
                generator=True
            )

            # Process all pages
            for entry in entry_generator:
                if entry['type'] != 'searchResEntry':
                    continue

                total_entries += 1

                # Track page counts for logging (approximate)
                current_page = (total_entries - 1) // page_size + 1
                if current_page > page_count:
                    page_count = current_page
                    self.logger.debug(f"LDAP page {page_count}: processing results...")

                # Extract attributes
                attrs = entry.get('attributes', {})

                # Get SID (required)
                object_sid = self._extract_attr(attrs, 'objectSid')
                if not object_sid:
                    continue

                # Extract domain SID from computer SID
                domain_sid = extract_domain_sid(object_sid)

                # Get DNS hostname (prefer dNSHostName, fall back to name)
                dns_name = self._extract_attr(attrs, 'dNSHostName')
                if not dns_name:
                    dns_name = self._extract_attr(attrs, 'name')
                if dns_name:
                    dns_name = dns_name.upper()  # BloodHound expects uppercase FQDN

                # Get primary group SID
                primary_group_id = self._extract_attr(attrs, 'primaryGroupID')
                primary_group_sid = build_primary_group_sid(domain_sid, primary_group_id) if primary_group_id else None

                # Get sAMAccountName
                sam_account = self._extract_attr(attrs, 'sAMAccountName') or ''

                # Build properties based on mode
                if self.loud_mode:
                    # Full properties object with all attributes

                    # Get UAC flags
                    uac_value = self._extract_attr(attrs, 'userAccountControl')
                    uac_flags = parse_uac_flags(uac_value) if uac_value else {
                        'enabled': True, 'unconstraineddelegation': False, 'trustedtoauth': False
                    }

                    # Get allowed to delegate SPNs
                    allowed_to_delegate = self._extract_attr(attrs, 'msDS-AllowedToDelegateTo')
                    if allowed_to_delegate and not isinstance(allowed_to_delegate, list):
                        allowed_to_delegate = [allowed_to_delegate]
                    elif not allowed_to_delegate:
                        allowed_to_delegate = []

                    # Get SPN list
                    spns = self._extract_attr(attrs, 'servicePrincipalName')
                    if spns and not isinstance(spns, list):
                        spns = [spns]
                    elif not spns:
                        spns = []

                    # Get SID history
                    sid_history = self._extract_attr(attrs, 'sIDHistory')
                    if sid_history and not isinstance(sid_history, list):
                        sid_history = [sid_history]
                    elif not sid_history:
                        sid_history = []

                    # Note: LAPS detection disabled to avoid LDAP query errors
                    has_laps = False

                    properties = {
                        'name': dns_name or 'UNKNOWN',
                        'domainsid': domain_sid,
                        'domain': self.domain.upper(),
                        'distinguishedname': self._extract_attr(attrs, 'distinguishedName') or '',
                        'unconstraineddelegation': uac_flags['unconstraineddelegation'],
                        'enabled': uac_flags['enabled'],
                        'trustedtoauth': uac_flags['trustedtoauth'],
                        'samaccountname': sam_account,
                        'haslaps': has_laps,
                        'lastlogon': windows_timestamp_to_unix(self._extract_attr(attrs, 'lastLogon')),
                        'lastlogontimestamp': windows_timestamp_to_unix(self._extract_attr(attrs, 'lastLogonTimestamp')),
                        'pwdlastset': windows_timestamp_to_unix(self._extract_attr(attrs, 'pwdLastSet')),
                        'whencreated': windows_timestamp_to_unix(self._extract_attr(attrs, 'whenCreated')),
                        'serviceprincipalnames': spns,
                        'description': self._extract_attr(attrs, 'description') or None,
                        'operatingsystem': self._extract_attr(attrs, 'operatingSystem') or None,
                        'sidhistory': sid_history
                    }
                else:
                    # Minimal properties object - only what's needed for session collection
                    allowed_to_delegate = []
                    sid_history = []

                    properties = {
                        'name': dns_name or sam_account.upper() if sam_account else 'UNKNOWN',
                        'domainsid': domain_sid,
                        'domain': self.domain.upper(),
                        'distinguishedname': None,
                        'unconstraineddelegation': False,
                        'enabled': True,  # Assume enabled since we filter disabled in LDAP query
                        'trustedtoauth': False,
                        'samaccountname': sam_account,
                        'haslaps': False,
                        'lastlogon': 0,
                        'lastlogontimestamp': 0,
                        'pwdlastset': 0,
                        'whencreated': 0,
                        'serviceprincipalnames': [],
                        'description': None,
                        'operatingsystem': None,
                        'sidhistory': []
                    }

                # Store computer info indexed by SID
                computers[object_sid] = {
                    'dns_name': dns_name,
                    'object_identifier': object_sid,
                    'primary_group_sid': primary_group_sid,
                    'allowed_to_delegate': allowed_to_delegate,
                    'properties': properties,
                    'sid_history': sid_history
                }

            conn.unbind()

            # Log completion with page count
            if page_count > 1:
                self.logger.info(f"LDAP paging complete. Retrieved {len(computers)} enabled computers across {page_count} pages")
            else:
                self.logger.info(f"LDAP query returned {len(computers)} enabled computers")

        except Exception as e:
            self.logger.error(f"LDAP query failed: {e}")
            raise

        return computers

    def _extract_attr(self, attrs, attr_name):
        """
        Extract a single attribute value from LDAP attributes dict.

        Args:
            attrs: LDAP attributes dictionary
            attr_name: Attribute name to extract

        Returns:
            Attribute value (unwrapped from list if single value), or None
        """
        value = attrs.get(attr_name, None)
        if value is None:
            return None

        # ldap3 returns lists for multi-valued attributes
        if isinstance(value, list):
            if len(value) == 0:
                return None
            elif len(value) == 1:
                return value[0]
            else:
                return value  # Return list for multi-valued

        return value

    def get_computer_targets(self) -> List[str]:
        """
        Get list of computer DNS names for session collection.

        Returns:
            List of computer DNS hostnames
        """
        computers = self.get_computers()
        return [info['dns_name'] for sid, info in computers.items() if info['dns_name']]


# ============================================================================
# PRIVILEGED USER DETECTION MODULE
# ============================================================================

class PrivilegedUserDetector:
    """
    Determines if users are members of privileged groups.
    Uses LDAP queries to check group membership.
    """

    def __init__(self, dc_ip: str, domain: str, username: str, password: str,
                 lmhash: str = '', nthash: str = ''):
        """
        Initialize privileged user detector.

        Args:
            dc_ip: Domain Controller IP address
            domain: Target domain
            username: Domain username
            password: Password
            lmhash: LM hash
            nthash: NT hash
        """
        if not LDAP3_AVAILABLE:
            raise ImportError("ldap3 library is required for privileged user detection. Install with: pip install ldap3")

        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.logger = logging.getLogger('PrivilegedUserDetector')
        self.privileged_users: Set[str] = set()
        self._load_privileged_users()

    def _load_privileged_users(self):
        """
        Query LDAP to identify all users in privileged groups.
        Caches results for efficient filtering.
        """
        try:
            # Build base DN
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])

            # Create server and connection
            server = Server(self.dc_ip, get_info=ALL)

            if self.nthash:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM, auto_bind=True
                )
            else:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )

            # Query for privileged groups
            for group_name in PRIVILEGED_GROUPS:
                ldap_filter = f'(&(objectClass=group)(name={group_name}))'
                conn.search(
                    search_base=base_dn,
                    search_filter=ldap_filter,
                    search_scope=SUBTREE,
                    attributes=['member', 'cn']
                )

                for entry in conn.entries:
                    if hasattr(entry, 'member'):
                        # Get all members
                        members = entry.member.values if hasattr(entry.member, 'values') else [entry.member.value]

                        for member_dn in members:
                            # Extract username from DN
                            # DN format: CN=John Doe,OU=Users,DC=contoso,DC=local
                            if isinstance(member_dn, str):
                                cn_part = member_dn.split(',')[0]
                                if cn_part.startswith('CN='):
                                    user_cn = cn_part[3:].lower()
                                    self.privileged_users.add(user_cn)

            # Also query for users with adminCount=1 (privileged users flag)
            ldap_filter = '(&(objectClass=user)(adminCount=1))'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName']
            )

            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName'):
                    username = str(entry.sAMAccountName.value).lower()
                    self.privileged_users.add(username)

            conn.unbind()
            self.logger.info(f"Identified {len(self.privileged_users)} privileged users")

        except Exception as e:
            self.logger.warning(f"Failed to load privileged users from LDAP: {e}")
            # Continue with empty set - better to collect all than fail

    def is_privileged(self, username: str) -> bool:
        """
        Check if a username is privileged.

        Args:
            username: Username to check (case-insensitive)

        Returns:
            True if user is privileged, False otherwise
        """
        return username.lower() in self.privileged_users


# ============================================================================
# SID RESOLUTION MODULE
# ============================================================================

class SIDResolver:
    """
    Handles SID resolution for both users and computers via LDAP and SAMR.
    Implements caching to minimize redundant queries.
    """

    def __init__(self, dc_ip: str, domain: str, username: str, password: str,
                 lmhash: str = '', nthash: str = '', timeout: int = 5):
        """
        Initialize SID resolver with connection parameters.

        Args:
            dc_ip: Domain Controller IP address
            domain: Target domain
            username: Domain username for authentication
            password: Password
            lmhash: LM hash
            nthash: NT hash
            timeout: Connection timeout
        """
        self.dc_ip = dc_ip
        self.domain = domain
        self.username = username
        self.password = password
        self.lmhash = lmhash
        self.nthash = nthash
        self.timeout = timeout
        self.logger = logging.getLogger('SIDResolver')

        # SID caches: {name: sid}
        self.user_sid_cache = {}
        self.computer_sid_cache = {}

        # Try to pre-populate caches via LDAP if available
        if LDAP3_AVAILABLE:
            self._prepopulate_caches_ldap()

    def _prepopulate_caches_ldap(self):
        """
        Pre-populate SID caches by querying all users and computers via LDAP.
        This significantly reduces the number of individual lookups needed.
        """
        try:
            # Build base DN
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])

            # Create server and connection
            server = Server(self.dc_ip, get_info=ALL)

            if self.nthash:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM, auto_bind=True
                )
            else:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )

            # Query all users
            self.logger.debug("Pre-populating user SID cache via LDAP...")
            ldap_filter = '(&(objectClass=user)(objectCategory=person))'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'objectSid']
            )

            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName') and hasattr(entry, 'objectSid'):
                    sam_name = str(entry.sAMAccountName.value).lower()
                    sid = str(entry.objectSid.value)
                    self.user_sid_cache[sam_name] = sid

            self.logger.info(f"Pre-populated user SID cache with {len(self.user_sid_cache)} entries")

            # Query all computers
            self.logger.debug("Pre-populating computer SID cache via LDAP...")
            ldap_filter = '(objectCategory=computer)'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['sAMAccountName', 'dNSHostName', 'name', 'objectSid']
            )

            for entry in conn.entries:
                if hasattr(entry, 'objectSid'):
                    sid = str(entry.objectSid.value)

                    # Cache by sAMAccountName (without trailing $)
                    if hasattr(entry, 'sAMAccountName'):
                        sam_name = str(entry.sAMAccountName.value).lower()
                        if sam_name.endswith('$'):
                            sam_name = sam_name[:-1]
                        self.computer_sid_cache[sam_name] = sid

                    # Also cache by dNSHostName
                    if hasattr(entry, 'dNSHostName'):
                        dns_name = str(entry.dNSHostName.value).lower()
                        self.computer_sid_cache[dns_name] = sid

                        # Cache short name (before first dot)
                        if '.' in dns_name:
                            short_name = dns_name.split('.')[0]
                            self.computer_sid_cache[short_name] = sid

                    # Cache by name attribute
                    if hasattr(entry, 'name'):
                        name = str(entry.name.value).lower()
                        self.computer_sid_cache[name] = sid

            self.logger.info(f"Pre-populated computer SID cache with {len(self.computer_sid_cache)} entries")

            conn.unbind()

        except Exception as e:
            self.logger.warning(f"Failed to pre-populate SID caches via LDAP: {e}")
            self.logger.warning("Will fall back to individual SAMR lookups")

    def resolve_user_sid(self, username: str) -> Optional[str]:
        """
        Resolve a username to its SID.

        Args:
            username: Username to resolve (can include domain prefix)

        Returns:
            SID string (S-1-5-...) or None if resolution fails
        """
        # Extract username without domain prefix
        if '\\' in username:
            username = username.split('\\')[1]
        if '@' in username:
            username = username.split('@')[0]

        username_lower = username.lower()

        # Check cache first
        if username_lower in self.user_sid_cache:
            return self.user_sid_cache[username_lower]

        # Try LDAP lookup if available
        if LDAP3_AVAILABLE:
            sid = self._resolve_user_sid_ldap(username)
            if sid:
                self.user_sid_cache[username_lower] = sid
                return sid

        # Fall back to SAMR
        sid = self._resolve_sid_samr(username, is_computer=False)
        if sid:
            self.user_sid_cache[username_lower] = sid
            return sid

        self.logger.debug(f"Failed to resolve user SID for: {username}")
        return None

    def resolve_computer_sid(self, computername: str) -> Optional[str]:
        """
        Resolve a computer name to its SID.

        Args:
            computername: Computer name (can be FQDN, short name, or IP)

        Returns:
            SID string (S-1-5-...) or None if resolution fails
        """
        # Skip IP addresses - we can't resolve them to SIDs
        if computername.replace('.', '').replace(':', '').replace('[', '').replace(']', '').replace('0', '').replace('1', '').replace('2', '').replace('3', '').replace('4', '').replace('5', '').replace('6', '').replace('7', '').replace('8', '').replace('9', ''):
            # It's not just numbers and dots/colons - it's a hostname
            pass
        else:
            # Looks like an IP address
            self.logger.debug(f"Skipping SID resolution for IP address: {computername}")
            return None

        # Clean computer name
        computername = computername.lstrip('\\').strip()
        computername_lower = computername.lower()

        # Try short name (before first dot)
        short_name = computername_lower.split('.')[0]

        # Check cache with various name formats
        for name_variant in [computername_lower, short_name, short_name + '$']:
            if name_variant in self.computer_sid_cache:
                return self.computer_sid_cache[name_variant]

        # Try LDAP lookup if available
        if LDAP3_AVAILABLE:
            sid = self._resolve_computer_sid_ldap(computername)
            if sid:
                self.computer_sid_cache[computername_lower] = sid
                self.computer_sid_cache[short_name] = sid
                return sid

        # Fall back to SAMR (need to add $ for computer accounts)
        sid = self._resolve_sid_samr(short_name + '$', is_computer=True)
        if sid:
            self.computer_sid_cache[computername_lower] = sid
            self.computer_sid_cache[short_name] = sid
            return sid

        self.logger.debug(f"Failed to resolve computer SID for: {computername}")
        return None

    def _resolve_user_sid_ldap(self, username: str) -> Optional[str]:
        """
        Resolve user SID via LDAP query.

        Args:
            username: sAMAccountName of user

        Returns:
            SID string or None
        """
        try:
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
            server = Server(self.dc_ip, get_info=ALL)

            if self.nthash:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM, auto_bind=True
                )
            else:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )

            ldap_filter = f'(&(objectClass=user)(sAMAccountName={username}))'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if conn.entries and len(conn.entries) > 0:
                entry = conn.entries[0]
                if hasattr(entry, 'objectSid'):
                    sid = str(entry.objectSid.value)
                    conn.unbind()
                    return sid

            conn.unbind()

        except Exception as e:
            self.logger.debug(f"LDAP user SID resolution failed for {username}: {e}")

        return None

    def _resolve_computer_sid_ldap(self, computername: str) -> Optional[str]:
        """
        Resolve computer SID via LDAP query.

        Args:
            computername: Computer name (FQDN or short name)

        Returns:
            SID string or None
        """
        try:
            base_dn = ','.join([f'DC={part}' for part in self.domain.split('.')])
            server = Server(self.dc_ip, get_info=ALL)

            if self.nthash:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.lmhash + ':' + self.nthash,
                    authentication=NTLM, auto_bind=True
                )
            else:
                user = f'{self.domain}\\{self.username}'
                conn = Connection(
                    server, user=user, password=self.password,
                    authentication=NTLM, auto_bind=True
                )

            # Try by dNSHostName first
            ldap_filter = f'(&(objectCategory=computer)(dNSHostName={computername}))'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if conn.entries and len(conn.entries) > 0:
                entry = conn.entries[0]
                if hasattr(entry, 'objectSid'):
                    sid = str(entry.objectSid.value)
                    conn.unbind()
                    return sid

            # Try by sAMAccountName (short name + $)
            short_name = computername.split('.')[0]
            ldap_filter = f'(&(objectCategory=computer)(sAMAccountName={short_name}$))'
            conn.search(
                search_base=base_dn,
                search_filter=ldap_filter,
                search_scope=SUBTREE,
                attributes=['objectSid']
            )

            if conn.entries and len(conn.entries) > 0:
                entry = conn.entries[0]
                if hasattr(entry, 'objectSid'):
                    sid = str(entry.objectSid.value)
                    conn.unbind()
                    return sid

            conn.unbind()

        except Exception as e:
            self.logger.debug(f"LDAP computer SID resolution failed for {computername}: {e}")

        return None

    def _resolve_sid_samr(self, name: str, is_computer: bool = False) -> Optional[str]:
        """
        Resolve a name to SID using SAMR protocol.

        Args:
            name: Account name to resolve
            is_computer: Whether this is a computer account

        Returns:
            SID string or None
        """
        try:
            # Connect to SAMR
            smb_string = f'ncacn_np:{self.dc_ip}[\\pipe\\samr]'
            rpctransport = transport.DCERPCTransportFactory(smb_string)
            rpctransport.set_credentials(
                self.username, self.password, self.domain,
                self.lmhash, self.nthash
            )
            rpctransport.set_connect_timeout(self.timeout)

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            # Connect to server
            resp = samr.hSamrConnect(dce)
            server_handle = resp['ServerHandle']

            # Get domain SID
            resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)
            domain_sid = resp['DomainId']

            # Open domain
            resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
            domain_handle = resp['DomainHandle']

            # Lookup name
            try:
                resp = samr.hSamrLookupNamesInDomain(dce, domain_handle, [name])

                if resp['RelativeIds'] and len(resp['RelativeIds']) > 0:
                    rid = resp['RelativeIds'][0]
                    # Construct full SID from domain SID + RID
                    sid = f"{domain_sid.formatCanonical()}-{rid}"
                    dce.disconnect()
                    return sid

            except Exception as e:
                self.logger.debug(f"SAMR name lookup failed for {name}: {e}")

            dce.disconnect()

        except Exception as e:
            self.logger.debug(f"SAMR SID resolution failed for {name}: {e}")

        return None


# ============================================================================
# OUTPUT FORMATTING MODULE
# ============================================================================

class BloodHoundFormatter:
    """
    Formats collected session data into BloodHound CE-compatible JSON.
    Outputs per-computer objects with full LDAP properties and session data.
    """

    def __init__(self, sid_resolver: Optional[SIDResolver] = None):
        """
        Initialize the formatter with a SID resolver.

        Args:
            sid_resolver: SIDResolver instance for name-to-SID conversion
        """
        self.sid_resolver = sid_resolver
        self.logger = logging.getLogger('BloodHoundFormatter')

    def generate_output(self, all_sessions: List[Dict], computer_properties: Dict[str, Dict],
                       collection_config: Dict) -> Dict:
        """
        Generate BloodHound CE format JSON output with per-computer objects.

        Args:
            all_sessions: List of all collected sessions with metadata
            computer_properties: Dictionary mapping computer SID to properties from LDAP
            collection_config: Dictionary with collection configuration
                - loud_mode: bool
                - privileged_mode: bool
                - ldap_available: bool
                - collection_errors: dict of method -> error message

        Returns:
            Dictionary in BloodHound CE per-computer format ready for JSON serialization
        """
        loud_mode = collection_config.get('loud_mode', False)
        privileged_mode = collection_config.get('privileged_mode', False)
        collection_errors = collection_config.get('collection_errors', {})

        # Group sessions by computer SID
        sessions_by_computer = self._group_sessions_by_computer(all_sessions)

        # Build computer objects
        data = []
        for comp_sid, comp_info in computer_properties.items():
            # Get sessions for this computer
            comp_sessions = sessions_by_computer.get(comp_sid, {
                'standard': [],
                'loud': [],
                'registry': []
            })

            # Build session sections based on mode
            if privileged_mode:
                sessions_section = {
                    "Collected": False,
                    "FailureReason": None,
                    "Results": []
                }
                privileged_sessions_section = self._build_session_section(
                    comp_sessions['standard'] + comp_sessions['loud'],
                    collected=True,
                    failure_reason=collection_errors.get('privileged', None)
                )
            else:
                sessions_section = self._build_session_section(
                    comp_sessions['standard'] + comp_sessions['loud'],
                    collected=True,
                    failure_reason=collection_errors.get('sessions', None)
                )
                privileged_sessions_section = {
                    "Collected": False,
                    "FailureReason": None,
                    "Results": []
                }

            # Registry sessions (only in loud mode)
            if loud_mode:
                registry_sessions_section = self._build_session_section(
                    comp_sessions['registry'],
                    collected=True,
                    failure_reason=collection_errors.get('registry', None)
                )
            else:
                registry_sessions_section = {
                    "Collected": False,
                    "FailureReason": None,
                    "Results": []
                }

            # Build computer object
            computer_obj = {
                "ObjectIdentifier": comp_info['object_identifier'],
                "AllowedToAct": [],
                "PrimaryGroupSID": comp_info['primary_group_sid'],
                "LocalAdmins": {"Collected": False, "FailureReason": None, "Results": []},
                "PSRemoteUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "Properties": comp_info['properties'],
                "RemoteDesktopUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "DcomUsers": {"Collected": False, "FailureReason": None, "Results": []},
                "AllowedToDelegate": comp_info['allowed_to_delegate'],
                "Sessions": sessions_section,
                "PrivilegedSessions": privileged_sessions_section,
                "RegistrySessions": registry_sessions_section,
                "Aces": [],
                "HasSIDHistory": comp_info['sid_history'],
                "IsDeleted": False,
                "Status": None,
                "IsACLProtected": False
            }

            data.append(computer_obj)

        # Generate timestamp in ISO format with Z suffix
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # Construct final output
        output = {
            "data": data,
            "meta": {
                "type": "computers",
                "count": len(data),
                "version": 5,
                "collected": timestamp
            }
        }

        return output

    def _group_sessions_by_computer(self, all_sessions: List[Dict]) -> Dict[str, Dict]:
        """
        Group sessions by computer SID and session type.

        Args:
            all_sessions: List of all collected sessions with metadata

        Returns:
            Dictionary mapping computer SID to categorized sessions:
            {
                'S-1-5-21-...-1234': {
                    'standard': [session_obj1, session_obj2],
                    'loud': [session_obj3],
                    'registry': []
                }
            }
        """
        sessions_by_computer = {}

        # Separate sessions by collection method
        standard_methods = ['NetSessionEnum', 'NetWkstaUserEnum']
        loud_methods = ['WMI', 'TerminalServices']
        registry_methods = ['Registry']

        for session in all_sessions:
            username = session.get('username', '')
            target = session.get('target', '')
            method = session.get('method', 'Unknown')

            if not username or not target:
                continue

            # Resolve SIDs
            user_sid = None
            computer_sid = None

            if self.sid_resolver:
                user_sid = self.sid_resolver.resolve_user_sid(username)
                computer_sid = self.sid_resolver.resolve_computer_sid(target)

            # Skip entries where SID resolution failed
            if not user_sid or not computer_sid:
                self.logger.debug(f"Skipping session - SID resolution failed: "
                                f"User={username} (SID={user_sid}), "
                                f"Computer={target} (SID={computer_sid})")
                continue

            # Initialize computer entry if needed
            if computer_sid not in sessions_by_computer:
                sessions_by_computer[computer_sid] = {
                    'standard': [],
                    'loud': [],
                    'registry': []
                }

            # Build session object
            session_obj = {
                "ComputerSID": computer_sid,
                "UserSID": user_sid
            }

            # Categorize by method
            if method in standard_methods or method == 'Unknown':
                sessions_by_computer[computer_sid]['standard'].append(session_obj)
            if method in loud_methods:
                sessions_by_computer[computer_sid]['loud'].append(session_obj)
            if method in registry_methods:
                sessions_by_computer[computer_sid]['registry'].append(session_obj)

        return sessions_by_computer

    def _build_session_section(self, sessions: List[Dict], collected: bool = False,
                              failure_reason: Optional[str] = None) -> Dict:
        """
        Build a session section with deduplication.

        Args:
            sessions: List of session objects with ComputerSID and UserSID
            collected: Whether collection was attempted
            failure_reason: Error message if collection failed

        Returns:
            Session section dict with Collected, FailureReason, and Results
        """
        # Deduplicate sessions by (ComputerSID, UserSID) pair
        seen = set()
        unique_sessions = []

        for session in sessions:
            session_key = f"{session['ComputerSID']}|{session['UserSID']}"
            if session_key not in seen:
                seen.add(session_key)
                unique_sessions.append(session)

        # Determine if collection was successful
        actual_collected = collected and len(unique_sessions) > 0

        return {
            "Collected": actual_collected,
            "FailureReason": failure_reason,
            "Results": unique_sessions
        }


# ============================================================================
# THREADING AND ORCHESTRATION MODULE
# ============================================================================

class SessionHoundOrchestrator:
    """
    Orchestrates multi-threaded session collection across multiple targets.
    Handles progress tracking, rate limiting, and result aggregation.
    """

    def __init__(self, collector: SessionCollector, targets: List[str],
                 threads: int = 10, delay: float = 0, jitter: int = 0):
        """
        Initialize the orchestrator.

        Args:
            collector: SessionCollector instance
            targets: List of target hostnames/IPs
            threads: Number of concurrent threads
            delay: Delay between queries in seconds
            jitter: Jitter percentage (0-100)
        """
        self.collector = collector
        self.targets = targets
        self.threads = min(threads, len(targets))  # Don't create more threads than targets
        self.delay = delay
        self.jitter = jitter
        self.logger = logging.getLogger('Orchestrator')

        # Thread-safe data structures
        self.target_queue = Queue()
        self.results = []
        self.results_lock = threading.Lock()
        self.progress_lock = threading.Lock()
        self.completed = 0
        self.total = len(targets)

    def _calculate_delay(self) -> float:
        """
        Calculate delay with jitter applied.

        Returns:
            Delay time in seconds
        """
        if self.delay == 0:
            return 0

        if self.jitter > 0:
            jitter_amount = self.delay * (self.jitter / 100.0)
            jitter_value = random.uniform(-jitter_amount, jitter_amount)
            return max(0, self.delay + jitter_value)

        return self.delay

    def _worker(self):
        """
        Worker thread function that processes targets from the queue.
        """
        while True:
            try:
                target = self.target_queue.get(timeout=1)
            except:
                break

            try:
                # Apply delay with jitter
                if self.delay > 0:
                    time.sleep(self._calculate_delay())

                # Collect sessions
                sessions = self.collector.collect_all_sessions(target)

                # Store results
                with self.results_lock:
                    self.results.extend(sessions)

                # Update progress
                with self.progress_lock:
                    self.completed += 1
                    if self.completed % 10 == 0 or self.completed == self.total:
                        print(f"[*] Progress: {self.completed}/{self.total} hosts processed, "
                              f"{len(self.results)} sessions found", end='\r')

            except Exception as e:
                self.logger.debug(f"Worker error processing {target}: {e}")
            finally:
                self.target_queue.task_done()

    def run(self) -> List[Dict[str, str]]:
        """
        Execute session collection across all targets using thread pool.

        Returns:
            List of all collected sessions
        """
        # Populate queue
        for target in self.targets:
            self.target_queue.put(target)

        # Start worker threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        # Wait for completion
        self.target_queue.join()

        # Ensure clean output after progress indicator
        print()

        return self.results


# ============================================================================
# MAIN APPLICATION MODULE
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description='SessionHound - Active Directory Session Collector for BloodHound',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic session collection (LDAP required):
    %(prog)s -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 --ldap-query

  Pass-the-hash with target file filtering:
    %(prog)s -u administrator -H aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \\
        -d contoso.local --dc-ip 10.0.0.1 --ldap-query --target-file computers.txt --threads 20

  Privileged sessions only:
    %(prog)s -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --privileged --threads 15 -o privileged_sessions.json

  Loud mode - aggressive multi-method enumeration (requires admin):
    %(prog)s -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --loud

  Custom DNS server (different from DC):
    %(prog)s -u administrator -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --dns 10.0.0.2 --ldap-query --threads 10

  Stealth mode with delays:
    %(prog)s -u lowpriv -p 'Password123' -d contoso.local --dc-ip 10.0.0.1 \\
        --ldap-query --threads 5 --delay 2 --jitter 30
        """
    )

    # Authentication arguments
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-u', '--username', required=True,
                           help='Domain username')
    auth_group.add_argument('-p', '--password', default='',
                           help='Password for authentication')
    auth_group.add_argument('-H', '--hash', dest='nthash',
                           help='NT hash for pass-the-hash (format: LMHASH:NTHASH or just NTHASH)')
    auth_group.add_argument('-d', '--domain', required=True,
                           help='Target domain (e.g., contoso.local)')
    auth_group.add_argument('--dc-ip', required=True,
                           help='Domain Controller IP address')
    auth_group.add_argument('--dns', '-ns', dest='dns_server',
                           help='DNS server IP address for hostname resolution (overrides --dc-ip for DNS queries). '
                                'Use this when you want to query a different DNS server than the DC you are authenticating against. '
                                'If not specified, --dc-ip will be used for DNS resolution.')

    # Target specification
    target_group = parser.add_argument_group('Target Specification')
    target_group.add_argument('--ldap-query', action='store_true', required=True,
                             help='Query LDAP for computer list with full properties (REQUIRED for v3.0+ format)')
    target_group.add_argument('--target-file',
                             help='Optional: File to filter LDAP results (one computer name per line)')

    # Operational parameters
    ops_group = parser.add_argument_group('Operational Parameters')
    ops_group.add_argument('-t', '--threads', type=int, default=10,
                          help='Number of concurrent threads (default: 10)')
    ops_group.add_argument('--privileged', action='store_true',
                          help='Only collect sessions for privileged users')
    ops_group.add_argument('-o', '--output', default='sessions.json',
                          help='Output file path (default: sessions.json)')
    ops_group.add_argument('--timeout', type=int, default=5,
                          help='Connection timeout per host in seconds (default: 5)')
    ops_group.add_argument('-l', '--loud', action='store_true',
                          help='Enable aggressive multi-method enumeration (WMI, Registry, RDP) and full LDAP queries. '
                               'Requires admin access. WARNING: Generates significant detection noise. '
                               'Without this flag, only minimal LDAP queries are performed (4 attributes vs 16). '
                               'Methods: NetSessionEnum, NetWkstaUserEnum, WMI (Win32_LoggedOnUser), '
                               'Remote Registry (HKEY_USERS), Terminal Services (RDP sessions)')

    # Advanced options
    adv_group = parser.add_argument_group('Advanced Options')
    adv_group.add_argument('--delay', type=float, default=0,
                          help='Delay between queries in seconds (default: 0)')
    adv_group.add_argument('--jitter', type=int, default=0,
                          help='Add random jitter to delays, percentage 0-100 (default: 0)')
    adv_group.add_argument('-v', '--verbose', action='store_true',
                          help='Enable verbose logging')

    args = parser.parse_args()

    # Validation
    if not args.password and not args.nthash:
        parser.error("Either --password or --hash must be provided")

    # LDAP query is now required for BloodHound CE per-computer format
    if not args.ldap_query:
        parser.error("--ldap-query is required to retrieve computer properties for BloodHound CE format")

    if args.jitter < 0 or args.jitter > 100:
        parser.error("Jitter must be between 0 and 100")

    if args.privileged and not LDAP3_AVAILABLE:
        parser.error("--privileged requires ldap3 library. Install with: pip install ldap3")

    if args.ldap_query and not LDAP3_AVAILABLE:
        parser.error("--ldap-query requires ldap3 library. Install with: pip install ldap3")

    # Validate DNS server IP if provided
    if args.dns_server and not validate_ip_address(args.dns_server):
        parser.error(f"Invalid IP address format for --dns: {args.dns_server}")

    return args


def setup_logging(verbose: bool):
    """
    Configure logging based on verbosity level.

    Args:
        verbose: Enable verbose logging
    """
    level = logging.DEBUG if verbose else logging.INFO

    # Configure root logger
    logging.basicConfig(
        level=level,
        format='[%(levelname)s] %(message)s',
        handlers=[logging.StreamHandler(sys.stderr)]
    )

    # Reduce impacket verbosity
    logging.getLogger('impacket').setLevel(logging.WARNING)


def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load target hosts from a file.

    Args:
        file_path: Path to file containing targets (one per line)

    Returns:
        List of target hostnames/IPs
    """
    targets = []

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except Exception as e:
        print(f"[!] Error loading targets from file: {e}")
        sys.exit(1)

    return targets


def parse_hash(hash_str: str) -> Tuple[str, str]:
    """
    Parse hash string into LM and NT components.

    Args:
        hash_str: Hash string in format LMHASH:NTHASH or just NTHASH

    Returns:
        Tuple of (lmhash, nthash)
    """
    if ':' in hash_str:
        lmhash, nthash = hash_str.split(':', 1)
    else:
        lmhash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash
        nthash = hash_str

    return lmhash, nthash


def validate_ip_address(ip_string: str) -> bool:
    """
    Validate that a string is a valid IPv4 address.

    Args:
        ip_string: String to validate

    Returns:
        True if valid IP address, False otherwise
    """
    parts = ip_string.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def main():
    """
    Main application entry point.
    """
    # Parse arguments
    args = parse_arguments()

    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger('SessionHound')

    # Display banner
    print(r"""
   _____               _             _    _                       _
  / ____|             (_)           | |  | |                     | |
 | (___   ___  ___ ___ _  ___  _ __ | |__| | ___  _   _ _ __   __| |
  \___ \ / _ \/ __/ __| |/ _ \| '_ \|  __  |/ _ \| | | | '_ \ / _` |
  ____) |  __/\__ \__ \ | (_) | | | | |  | | (_) | |_| | | | | (_| |
 |_____/ \___||___/___/_|\___/|_| |_|_|  |_|\___/ \__,_|_| |_|\__,_|

    Active Directory Session Collector for BloodHound CE v3.0.0
    Per-Computer Object Format with Full LDAP Properties

    """)

    # Parse hash if provided
    lmhash = ''
    nthash = ''
    if args.nthash:
        lmhash, nthash = parse_hash(args.nthash)

    # Initialize DNS resolver with priority: --dns > --dc-ip > system default
    dns_resolver = None
    dns_server_to_use = None

    if args.dns_server:
        # Highest priority: explicit --dns flag
        dns_server_to_use = args.dns_server
        logger.info(f"Configuring DNS resolution to use custom DNS server: {dns_server_to_use}")
    elif args.dc_ip:
        # Fallback: use DC IP for DNS
        dns_server_to_use = args.dc_ip
        logger.info(f"Configuring DNS resolution to use DC: {dns_server_to_use}")

    if dns_server_to_use:
        dns_resolver = DNSResolver(dns_server=dns_server_to_use, timeout=args.timeout)
        if not DNS_AVAILABLE:
            logger.warning("dnspython library not found. DNS resolution will use system resolver.")
            logger.warning("For optimal DNS resolution, install with: pip install dnspython")

    # Warn about loud mode
    if args.loud:
        logger.warning("LOUD MODE ENABLED: This will generate significant network traffic and detection signatures!")
        logger.warning("LOUD MODE requires admin access on target systems for WMI, Registry, and RDP enumeration")

    # Initialize session collector
    logger.info("Initializing session collector...")
    collector = SessionCollector(
        username=args.username,
        password=args.password,
        domain=args.domain,
        lmhash=lmhash,
        nthash=nthash,
        timeout=args.timeout,
        dns_resolver=dns_resolver,
        loud_mode=args.loud
    )

    # Get target list and computer properties from LDAP (required)
    logger.info("Querying LDAP for computer objects with properties...")
    try:
        ldap_querier = LDAPQuerier(
            dc_ip=args.dc_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            lmhash=lmhash,
            nthash=nthash,
            loud_mode=args.loud
        )
        # Get full computer properties (returns dict: SID -> properties)
        computer_properties = ldap_querier.get_computers()
        # Extract target DNS names for session collection
        targets = ldap_querier.get_computer_targets()
        logger.info(f"LDAP query returned {len(computer_properties)} computers with properties")
    except Exception as e:
        logger.error(f"LDAP query failed: {e}")
        sys.exit(1)

    # Optionally filter targets using a target file
    if args.target_file:
        logger.info(f"Loading target filter from file: {args.target_file}")
        file_targets = load_targets_from_file(args.target_file)
        logger.info(f"Loaded {len(file_targets)} targets from file")

        # Filter LDAP targets to only those in the file
        original_target_count = len(targets)
        file_targets_lower = [t.lower() for t in file_targets]
        targets = [t for t in targets if t.lower() in file_targets_lower or
                   t.split('.')[0].lower() in file_targets_lower]

        logger.info(f"Filtered to {len(targets)} targets (from {original_target_count} LDAP computers)")

    if not targets:
        logger.error("No targets to process after filtering")
        sys.exit(1)

    logger.info(f"Total targets for session collection: {len(targets)}")

    # Initialize privileged user detector if needed
    privileged_detector = None
    if args.privileged:
        logger.info("Initializing privileged user detection...")
        try:
            privileged_detector = PrivilegedUserDetector(
                dc_ip=args.dc_ip,
                domain=args.domain,
                username=args.username,
                password=args.password,
                lmhash=lmhash,
                nthash=nthash
            )
        except Exception as e:
            logger.error(f"Failed to initialize privileged user detector: {e}")
            sys.exit(1)

    # Start session collection
    logger.info(f"Starting session collection with {args.threads} threads...")
    if args.delay > 0:
        logger.info(f"Using delay: {args.delay}s with {args.jitter}% jitter")

    orchestrator = SessionHoundOrchestrator(
        collector=collector,
        targets=targets,
        threads=args.threads,
        delay=args.delay,
        jitter=args.jitter
    )

    start_time = time.time()
    sessions = orchestrator.run()
    elapsed = time.time() - start_time

    logger.info(f"Collection completed in {elapsed:.2f} seconds")
    logger.info(f"Raw sessions collected: {len(sessions)}")

    # Filter for privileged users if requested
    if args.privileged and privileged_detector:
        original_count = len(sessions)
        sessions = [s for s in sessions if privileged_detector.is_privileged(s['username'])]
        logger.info(f"Filtered to {len(sessions)} privileged sessions (from {original_count})")

    # Initialize SID resolver
    logger.info("Initializing SID resolver...")
    sid_resolver = None
    try:
        sid_resolver = SIDResolver(
            dc_ip=args.dc_ip,
            domain=args.domain,
            username=args.username,
            password=args.password,
            lmhash=lmhash,
            nthash=nthash,
            timeout=args.timeout
        )
        logger.info("SID resolver initialized successfully")
    except Exception as e:
        logger.warning(f"Failed to initialize SID resolver: {e}")
        logger.warning("Output will not include SID resolution")

    # Format output with new BloodHound CE per-computer structure
    logger.info("Formatting output for BloodHound CE per-computer format...")
    formatter = BloodHoundFormatter(sid_resolver=sid_resolver)

    collection_config = {
        'loud_mode': args.loud,
        'privileged_mode': args.privileged,
        'ldap_available': LDAP3_AVAILABLE,
        'collection_errors': {}
    }

    output = formatter.generate_output(
        all_sessions=sessions,
        computer_properties=computer_properties,
        collection_config=collection_config
    )

    # Write output file
    try:
        output_path = Path(args.output)
        with output_path.open('w') as f:
            json.dump(output, f, indent=2)

        logger.info(f"Output written to: {output_path.absolute()}")

        # Count total computers and sessions
        total_computers = len(output['data'])
        total_sessions = 0

        for computer in output['data']:
            total_sessions += len(computer['Sessions']['Results'])
            total_sessions += len(computer['PrivilegedSessions']['Results'])
            total_sessions += len(computer['RegistrySessions']['Results'])

        logger.info(f"Total computers with properties: {total_computers}")
        logger.info(f"Total unique sessions with SIDs: {total_sessions}")

        print(f"\n[+] Success! Generated {total_computers} computer objects with {total_sessions} sessions")
        print(f"[+] Output file: {output_path.absolute()}")
        print(f"[+] Format: BloodHound CE Per-Computer JSON (ready for import)")
        print(f"[+] Meta: type=computers, count={total_computers}, version=5")

        if total_sessions == 0 and len(sessions) > 0:
            print(f"[!] Warning: {len(sessions)} sessions collected but SID resolution failed")
            print(f"[!] Check that LDAP is accessible and credentials are valid")

    except Exception as e:
        logger.error(f"Failed to write output file: {e}")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)
