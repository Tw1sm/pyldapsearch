#!/usr/bin/env python3

from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.formatters.formatters import format_uuid_le
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.examples.utils import parse_credentials
from impacket.examples import logger
from impacket import version
from pyldapsearch import __version__
from binascii import unhexlify
from ldap3 import ANONYMOUS
from enum import Enum
import base64
import logging
import time
import ldap3
import json
import ssl
import os
import typer

class SearchScope(str, Enum):
    BASE = 'BASE'
    LEVEL = 'LEVEL'
    SUBTREE = 'SUBTREE'


def get_dn(domain):
    components = domain.split('.')
    base = ''
    for comp in components:
        base += f',DC={comp}'
    
    return base[1:]


def get_machine_name(domain_controller, domain):
    if domain_controller is not None:
        s = SMBConnection(domain_controller, domain_controller)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login('', '')
    except Exception:
        if s.getServerName() == '':
            raise Exception('Error while anonymous logging into %s' % domain)
    else:
        s.logoff()
    return s.getServerName()


def init_ldap_connection(target, tls_version, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey, use_channel_binding):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    logging.info(f'Binding to {target}')
    ldap_server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    
    channel_binding = dict()
    if use_channel_binding:
        logging.debug('Enabling channel binding')
        channel_binding = dict(channel_binding=ldap3.TLS_CHANNEL_BINDING)
    
    if kerberos:
        ldap_session = ldap3.Connection(ldap_server)
        ldap_session.bind()
        ldap3_kerberos_login(ldap_session, target, username, password, domain, lmhash, nthash, aesKey, kdcHost=domain_controller)
    elif hashes is not None:
        if lmhash == "":
            lmhash = "aad3b435b51404eeaad3b435b51404ee"
        ldap_session = ldap3.Connection(ldap_server, user=user, password=lmhash + ":" + nthash, authentication=ldap3.NTLM, auto_bind=True, **channel_binding)
    elif username == '' and password == '':
        logging.debug('Performing anonymous bind')
        ldap_session = ldap3.Connection(ldap_server, authentication=ANONYMOUS, auto_bind=True, **channel_binding)
    else:
        ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True, **channel_binding)

    return ldap_server, ldap_session


def init_ldap_session(domain, username, password, lmhash, nthash, kerberos, domain_controller, ldaps, hashes, aesKey, no_smb, channel_binding):
    if kerberos:
        if no_smb:
            logging.debug(f'Setting connection target to {domain_controller} without SMB connection')
            target = domain_controller
        else:
            target = get_machine_name(domain_controller, domain)
    else:
        if domain_controller is not None:
            target = domain_controller
        else:
            target = domain

    if ldaps is True:
        logging.debug('Targeting LDAPS')
        try:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1_2, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey, channel_binding)
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return init_ldap_connection(target, ssl.PROTOCOL_TLSv1, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey, channel_binding)
    else:
        return init_ldap_connection(target, None, domain, username, password, lmhash, nthash, domain_controller, kerberos, hashes, aesKey, channel_binding)


def ldap3_kerberos_login(connection, target, user, password, domain='', lmhash='', nthash='', aesKey='', kdcHost=None, TGT=None, TGS=None, useCache=True):
    from pyasn1.codec.ber import encoder, decoder
    from pyasn1.type.univ import noValue
    """
    logins into the target system explicitly using Kerberos. Hashes are used if RC4_HMAC is supported.
    :param string user: username
    :param string password: password for the user
    :param string domain: domain where the account is valid for (required)
    :param string lmhash: LMHASH used to authenticate using hashes (password is not used)
    :param string nthash: NTHASH used to authenticate using hashes (password is not used)
    :param string aesKey: aes256-cts-hmac-sha1-96 or aes128-cts-hmac-sha1-96 used for Kerberos authentication
    :param string kdcHost: hostname or IP Address for the KDC. If None, the domain will be used (it needs to resolve tho)
    :param struct TGT: If there's a TGT available, send the structure here and it will be used
    :param struct TGS: same for TGS. See smb3.py for the format
    :param bool useCache: whether or not we should use the ccache for credentials lookup. If TGT or TGS are specified this is False
    :return: True, raises an Exception if error.
    """

    if lmhash != '' or nthash != '':
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # Importing down here so pyasn1 is not required if kerberos is not used.
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    import datetime

    if TGT is not None or TGS is not None:
        useCache = False

    if useCache:
        try:
            ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
        except Exception as e:
            # No cache present
            print(e)
            pass
        else:
            # retrieve domain information from CCache file if needed
            if domain == '':
                domain = ccache.principal.realm['data'].decode('utf-8')
                logging.debug('Domain retrieved from CCache: %s' % domain)

            logging.debug('Using Kerberos Cache: %s' % os.getenv('KRB5CCNAME'))
            principal = 'ldap/%s@%s' % (target.upper(), domain.upper())

            creds = ccache.getCredential(principal)
            if creds is None:
                # Let's try for the TGT and go from there
                principal = 'krbtgt/%s@%s' % (domain.upper(), domain.upper())
                creds = ccache.getCredential(principal)
                if creds is not None:
                    TGT = creds.toTGT()
                    logging.debug('Using TGT from cache')
                else:
                    logging.debug('No valid credentials found in cache')
            else:
                TGS = creds.toTGS(principal)
                logging.debug('Using TGS from cache')

            # retrieve user information from CCache file if needed
            if user == '' and creds is not None:
                user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)
            elif user == '' and len(ccache.principal.components) > 0:
                user = ccache.principal.components[0]['data'].decode('utf-8')
                logging.debug('Username retrieved from CCache: %s' % user)

    # First of all, we need to get a TGT for the user
    userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        sessionKey = TGT['sessionKey']

    if TGS is None:
        serverName = Principal('ldap/%s' % target, type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        sessionKey = TGS['sessionKey']

        # Let's build a NegTokenInit with a Kerberos REQ_AP

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', userName.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 11, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    blob['MechToken'] = encoder.encode(apReq)

    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(response)

    connection.bound = True

    return True


class Ldapsearch:
    _separator = '--------------------'
    # bofhound expects some attributes in a certain format
    _base64_attributes = ['nTSecurityDescriptor', 'msDS-GenerationId', 'auditingPolicy', 'dSASignature', 'mS-DS-CreatorSID',
        'logonHours', 'cACertificate', 'pKIExpirationPeriod', 'pKIOverlapPeriod', 'pKIKeyUsage', 'authorityRevocationList',
        'certificateRevocationList', 'dnsRecord' ]
    _raw_attributes = ['whenCreated', 'whenChanged', 'dSCorePropagationData', 'accountExpires', 'badPasswordTime', 'pwdLastSet',
        'lastLogonTimestamp', 'lastLogon', 'lastLogoff', 'maxPwdAge', 'minPwdAge', 'creationTime', 'lockOutObservationWindow',
        'lockoutDuration']
    _uuid_attributes = ['objectGUID', 'schemaIDGUID']
    _ignore_attributes = ['userCertificate']


    def __init__(self, ldap_server, ldap_session, scope, query_string, attributes, result_count, search_base, no_query_sd, logs_dir, silent, output):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.scope = scope
        self.query_string = query_string
        self.result_count = result_count
        self.search_base = search_base
        self.no_query_sd = no_query_sd
        self.logs_dir = logs_dir
        self.silent = silent
        self.output = output

        logging.info(f'Distinguished name: {self.search_base}')
        logging.info(f'Filter: {self.query_string}')

        if attributes == '':
            if no_query_sd:
                self.attributes = ['*']
            else:
                self.attributes = ['*', 'ntsecuritydescriptor']
        else:
            self.attributes = [attr.lower() for attr in attributes.split(',')]
            logging.info(f'Returning specific attributes(s): {attributes}')

        self._prep_log()


    def _prep_log(self):
        ts = time.strftime('%Y%m%d')
        self.filename = f'{self.logs_dir}/pyldapsearch_{ts}.log'


    def _printlog(self, line, log=False):
        # write to -output file if specified
        if self.output is not None:
            with open(self.output, 'a') as o :
                o.write(f'{line}\n')

        with open(self.filename, 'a') as f:
            f.write(f'{line}\n')
        if log:
            logging.info(line)
        else:
            if not self.silent:
                print(line)        
        

    def query(self):
        try:
            if 'ntsecuritydescriptor' in self.attributes:
                controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
                self.ldap_session.extend.standard.paged_search(self.search_base, self.query_string, search_scope=self.scope, attributes=self.attributes, size_limit=self.result_count, controls=controls, paged_size=500, generator=False)
            else:
                self.ldap_session.extend.standard.paged_search(self.search_base, self.query_string, search_scope=self.scope, attributes=self.attributes, size_limit=self.result_count, paged_size=500, generator=False)
        except (ldap3.core.exceptions.LDAPAttributeError, ldap3.core.exceptions.LDAPInvalidFilterError) as e:
            print()
            logging.critical(f'Error: {str(e)}')
            exit()

        for entry in self.ldap_session.entries:
            self._printlog(self._separator)
            json_entry = json.loads(entry.entry_to_json())
            attributes = json_entry['attributes'].keys()
            for attr in attributes:
                try:
                    value = self._get_formatted_value(entry, attr)
                except:
                    value = None
                    logging.debug(f'Error formatting value of attribute {attr}: {entry[attr].value}')
                if value is not None:
                    self._printlog(f'{attr}: {value}')
        print()
        self._printlog(f'Retrieved {len(self.ldap_session.entries)} results total', log=True)
        logging.debug(f'Results written to {self.filename}')


    def _get_formatted_value(self, entry, attr):
        if attr in self._ignore_attributes:
            return None
        
        # sid encoding can be funny, use ldap3 func to handle and return
        if attr in ['objectSid', 'securityIdentifier']:
            return format_sid(entry[attr][0])

        if attr in self._raw_attributes:
            val = entry[attr].raw_values[0].decode('utf-8')
        elif type(entry[attr].value) is list:
            #
            # if more than 1 cert is in the cACertificate prop, it will be a list of bytes and hit this block before the base64 block 
            #
            if attr in self._base64_attributes:
                values = [base64.b64encode(val).decode('utf-8') for val in entry[attr].value]
                val = ', '.join(values)
            elif type(entry[attr].value[0]) is bytes:
                strings = [val.decode('utf-8') for val in entry[attr].value]
                val = ', '.join(strings)
            else:
                val = ', '.join(entry[attr].value)
        elif attr in self._base64_attributes:
            val = base64.b64encode(entry[attr].value).decode('utf-8')
        elif attr in self._uuid_attributes:
            val = format_uuid_le(entry[attr].value)[1:-1]
        else:
            val = entry[attr].value

        if type(val) is bytes:
            try:
                val = val.decode('utf-8')
            except UnicodeDecodeError as e:
                logging.debug(f'Unable to decode {attr} as utf-8')
                raise(UnicodeDecodeError)


        return val

app = typer.Typer(
    add_completion=False,
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_enable=False
)


@app.command(no_args_is_help=True)
def main(
    target: str = typer.Argument(..., help='[[domain/]username[:password]'),
    filter: str = typer.Argument(..., help='LDAP filter string'),
    attributes: str = typer.Option('', '-attributes', help='Comma separated list of attributes', rich_help_panel='Search Options'),
    result_count: int = typer.Option(0, '-limit', help='Limit the number of results to return', rich_help_panel='Search Options'),
    domain_controller: str = typer.Option('', '-dc-ip', help='Domain controller IP or hostname to query', rich_help_panel='Connection Options'),
    distinguished_name: str = typer.Option('', '-base-dn', help='Search base distinguished name to use. Default is base domain level', rich_help_panel='Search Options'),
    scope: SearchScope = typer.Option(SearchScope.SUBTREE, '-scope', help='Scope the query has to be performed', case_sensitive=False, rich_help_panel='Search Options'),
    no_sd: bool = typer.Option(False, '-no-sd', help='Do not add nTSecurityDescriptor as an attribute queried by default. Reduces console output significantly', rich_help_panel='Search Options'),
    debug: bool = typer.Option(False, '-debug', help='Turn DEBUG output ON'),
    hashes: str = typer.Option(None, '-hashes', metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH', rich_help_panel='Connection Options'),
    no_pass: bool = typer.Option(False, '-no-pass', help='Don\'t ask for password (useful for -k)', rich_help_panel='Connection Options',),
    kerberos: bool = typer.Option(False, '-k', help='Use Kerberos authentication. Grabs credentials from ccache file '
                                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                                        'cannot be found, it will use the ones specified in the command '
                                        'line',
                                        rich_help_panel='Connection Options'),
    aesKey: str = typer.Option(None, '-aesKey', help='AES key to use for Kerberos Authentication (128 or 256 bits)', rich_help_panel='Connection Options'),
    ldaps: bool = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP', rich_help_panel='Connection Options',),
    channel_binding: bool = typer.Option(False, '-channel-binding', help='Enable LDAPS channel binding', rich_help_panel='Connection Options',),
    no_smb: bool = typer.Option(False, '-no-smb', help='Do not make a SMB connection to the DC to get its hostname (useful for -k). '
                                        'Requires a hostname to be provided with -dc-ip',
                                        rich_help_panel='Connection Options'),
    output : str = typer.Option(None, '-output', help='Result output file for this specific search (logging is still enabled)'),
    silent: bool = typer.Option(False, '-silent', help='Do not print query results to console (results will still be logged)', rich_help_panel='Search Options')):
    '''
    Tool for issuing manual LDAP queries which offers bofhound compatible output
    '''

    print(version.BANNER)
    logger.init()

    logging.info(f'pyldapsearch v{__version__} - Tw1sm\n')

    domain, username, password = parse_credentials(target)
    
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    # check for first time usage
    home = os.path.expanduser('~')
    pyldapsearch_dir = f'{home}/.pyldapsearch'
    logs_dir = f'{pyldapsearch_dir}/logs'

    if not os.path.isdir(pyldapsearch_dir):
        logging.info('First time usage detected')
        logging.info(f'pyldapsearch output will be logged to {logs_dir}')
        os.mkdir(pyldapsearch_dir)
        print()

    if not os.path.isdir(logs_dir):
        os.mkdir(logs_dir)

    if password == '' and username != '' and hashes is None and no_pass is False and aesKey is None:
        from getpass import getpass
        password = getpass('Password:')
    
    lm_hash = ""
    nt_hash = ""
    if hashes is not None:
        if ":" in hashes:
            lm_hash = hashes.split(":")[0]
            nt_hash = hashes.split(":")[1]
        else:
            nt_hash = hashes

    if distinguished_name == '':
        search_base = get_dn(domain)
    else:
        search_base = distinguished_name.upper()

    if domain_controller == "":
        domain_controller = domain
    
    ldap_server = ''
    ldap_session = ''
    ldapsearch = ''
    try:
        ldap_server, ldap_session = init_ldap_session(domain=domain, username=username, password=password, lmhash=lm_hash, 
                                                        nthash=nt_hash, kerberos=kerberos, domain_controller=domain_controller, 
                                                        ldaps=ldaps, hashes=hashes, aesKey=aesKey, no_smb=no_smb, channel_binding=channel_binding)
        ldapsearch = Ldapsearch(ldap_server, ldap_session, scope.value, filter, attributes, result_count, search_base, no_sd, logs_dir, silent, output)
        logging.debug('LDAP bind successful')
    except ldap3.core.exceptions.LDAPSocketOpenError as e: 
        if 'invalid server address' in str(e):
            logging.critical(f'Invalid server address - {domain_controller}')
        else:
            logging.critical('Error connecting to LDAP server')
            print()
            print(e)
        exit()
    except ldap3.core.exceptions.LDAPBindError as e:
        logging.critical(f'Error: {str(e)}')
        exit()

    ldapsearch.query()

if __name__ == '__main__':
    app(prog_name='pyldapsearch')
