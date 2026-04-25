#!/usr/bin/env python3

import asyncio
import base64
import binascii
import datetime
import logging
import os
import time
from enum import Enum
from urllib.parse import quote

import typer
from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials
from impacket.smbconnection import SMBConnection
from msldap.commons.factory import LDAPConnectionFactory
from msldap.protocol.constants import BASE, LEVEL, SUBTREE
from msldap.wintypes.asn1.sdflagsrequest import SDFlagsRequest, SDFlagsRequestValue

from pyldapsearch import __version__


class SearchScope(str, Enum):
    BASE = "BASE"
    LEVEL = "LEVEL"
    SUBTREE = "SUBTREE"


def get_dn(domain):
    components = domain.split(".")
    base = ""
    for comp in components:
        base += f",DC={comp}"

    return base[1:]


def _get_kerberos_target(domain_controller, domain):
    if domain_controller is not None:
        s = SMBConnection(domain_controller, domain_controller)
    else:
        s = SMBConnection(domain, domain)
    try:
        s.login("", "")
    except Exception:
        if s.getServerName() == "":
            raise Exception("Error while anonymous logging into %s" % domain)
    else:
        s.logoff()

    dns_hostname = s.getServerDNSHostName()
    if dns_hostname:
        return dns_hostname

    hostname = s.getServerName()
    if "." not in hostname and domain:
        return f"{hostname}.{domain.lower()}"
    return hostname


def _quote_user(domain, username):
    if username == "":
        return ""
    if domain:
        return quote(f"{domain}\\{username}", safe="\\")
    return quote(username, safe="")


def _normalize_kerberos_service_realm(hostname, fallback_domain):
    if hostname and "." in hostname:
        return hostname.split(".", 1)[1].upper()
    if fallback_domain:
        return fallback_domain.upper()
    return fallback_domain


def _build_msldap_urls(target, domain, username, password, nthash, domain_controller, kerberos, hashes, aesKey, ldaps):
    protocol = "ldaps" if ldaps else "ldap"
    urls = []
    user = _quote_user(domain, username)

    if kerberos:
        ccache_path = os.getenv("KRB5CCNAME")
        query_params = [f"dc={quote(domain_controller, safe='')}"]
        if domain_controller and target.lower() != domain_controller.lower():
            query_params.append(f"serverip={quote(domain_controller, safe='')}")
        query = "?" + "&".join(query_params)
        if ccache_path:
            urls.append(f"{protocol}+kerberos-ccache://{user}:{quote(ccache_path, safe='')}@{target}/{query}")
        if aesKey is not None:
            urls.append(f"{protocol}+kerberos-aes://{user}:{quote(aesKey, safe='')}@{target}/{query}")
        elif hashes is not None:
            urls.append(f"{protocol}+kerberos-rc4://{user}:{quote(nthash, safe='')}@{target}/{query}")
        elif password != "":
            urls.append(f"{protocol}+kerberos-password://{user}:{quote(password, safe='')}@{target}/{query}")
        if not urls:
            raise Exception("Kerberos requested but no credentials or KRB5CCNAME cache are available")
        return urls

    if username == "" and password == "":
        logging.debug("Performing anonymous bind")
        return [f"{protocol}://{target}"]

    if hashes is not None:
        return [f"{protocol}+sicily-nt://{user}:{quote(nthash, safe='')}@{target}"]

    return [f"{protocol}+sicily-password://{user}:{quote(password, safe='')}@{target}"]


async def _connect_client(url):
    client = LDAPConnectionFactory.from_url(url).get_client()
    if client.creds.protocol.name == "KERBEROS":
        client.target.domain = _normalize_kerberos_service_realm(client.target.hostname, client.target.domain)
    _, err = await client.connect()
    if err is not None:
        raise err
    return client


def init_ldap_connection(target, domain, username, password, nthash, domain_controller, kerberos, hashes, aesKey, ldaps):
    logging.info(f"Binding to {target}")
    errors = []
    for url in _build_msldap_urls(target, domain, username, password, nthash, domain_controller, kerberos, hashes, aesKey, ldaps):
        try:
            client = asyncio.run(_connect_client(url))
            asyncio.run(client.disconnect())
            return target, url
        except Exception as e:
            errors.append(e)

    raise errors[-1]


def init_ldap_session(domain, username, password, lmhash, nthash, kerberos, domain_controller, ldaps, hashes, aesKey, no_smb):
    del lmhash
    if kerberos:
        if no_smb:
            logging.debug(f"Setting connection target to {domain_controller} without SMB connection")
            target = domain_controller
        else:
            target = _get_kerberos_target(domain_controller, domain)
    else:
        if domain_controller is not None:
            target = domain_controller
        else:
            target = domain

    return init_ldap_connection(target, domain, username, password, nthash, domain_controller, kerberos, hashes, aesKey, ldaps)


class Ldapsearch:
    _separator = "--------------------"
    _base64_attributes = {
        "ntsecuritydescriptor",
        "msds-generationid",
        "auditingpolicy",
        "dsasignature",
        "ms-ds-creatorsid",
        "logonhours",
        "cacertificate",
        "pkiexpirationperiod",
        "pkioverlapperiod",
        "pkikeyusage",
        "authorityrevocationlist",
        "certificaterevocationlist",
        "dnsrecord",
    }
    _raw_attributes = {
        "whencreated",
        "whenchanged",
        "dscorepropagationdata",
        "accountexpires",
        "badpasswordtime",
        "pwdlastset",
        "lastlogontimestamp",
        "lastlogon",
        "lastlogoff",
        "maxpwdage",
        "minpwdage",
        "creationtime",
        "lockoutobservationwindow",
        "lockoutduration",
    }
    _filetime_attributes = {
        "accountexpires",
        "badpasswordtime",
        "pwdlastset",
        "lastlogontimestamp",
        "lastlogon",
        "lastlogoff",
        "maxpwdage",
        "minpwdage",
        "lockoutobservationwindow",
        "lockoutduration",
    }
    _ignore_attributes = {"usercertificate"}
    _scope_map = {"BASE": BASE, "LEVEL": LEVEL, "SUBTREE": SUBTREE}

    def __init__(self, ldap_server, ldap_session, scope, query_string, attributes, result_count, search_base, no_query_sd, logs_dir, silent, output):
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.scope = self._scope_map[scope]
        self.query_string = query_string
        self.result_count = result_count
        self.search_base = search_base
        self.no_query_sd = no_query_sd
        self.logs_dir = logs_dir
        self.silent = silent
        self.output = output

        logging.info(f"Distinguished name: {self.search_base}")
        logging.info(f"Filter: {self.query_string}")

        if attributes == "":
            if no_query_sd:
                self.attributes = ["*"]
            else:
                self.attributes = ["*", "ntsecuritydescriptor"]
        else:
            self.attributes = [attr.lower() for attr in attributes.split(",")]
            logging.info(f"Returning specific attributes(s): {attributes}")

        self._prep_log()

    def _prep_log(self):
        ts = time.strftime("%Y%m%d")
        self.filename = f"{self.logs_dir}/pyldapsearch_{ts}.log"

    def _printlog(self, line, log=False):
        if self.output is not None:
            with open(self.output, "a") as o:
                o.write(f"{line}\n")

        with open(self.filename, "a") as f:
            f.write(f"{line}\n")
        if log:
            logging.info(line)
        else:
            if not self.silent:
                print(line)

    async def _run_query(self):
        client = LDAPConnectionFactory.from_url(self.ldap_session).get_client()
        if client.creds.protocol.name == "KERBEROS":
            client.target.domain = _normalize_kerberos_service_realm(client.target.hostname, client.target.domain)
        _, err = await client.connect()
        if err is not None:
            raise err

        controls = None
        if "ntsecuritydescriptor" in self.attributes:
            flags = SDFlagsRequest.OWNER_SECURITY_INFORMATION | SDFlagsRequest.GROUP_SECURITY_INFORMATION | SDFlagsRequest.DACL_SECURITY_INFORMATION
            controls = [("1.2.840.113556.1.4.801", True, SDFlagsRequestValue({"Flags": flags}).dump())]

        entries = []
        try:
            async for entry, err in client.pagedsearch(
                self.query_string,
                self.attributes,
                controls=controls,
                tree=self.search_base,
                search_scope=self.scope,
            ):
                if err is not None:
                    raise err
                entries.append(entry)
                if self.result_count and len(entries) >= self.result_count:
                    break
        finally:
            await client.disconnect()
        return entries

    def query(self):
        try:
            entries = asyncio.run(self._run_query())
        except Exception as e:
            print()
            logging.critical(f"Error: {str(e)}")
            raise typer.Exit(code=1)

        for entry in entries:
            self._printlog(self._separator)
            attributes = entry["attributes"].keys()
            for attr in attributes:
                try:
                    value = self._get_formatted_value(entry, attr)
                except Exception:
                    value = None
                    logging.debug(f"Error formatting value of attribute {attr}: {entry['attributes'].get(attr)}")
                if value is not None:
                    self._printlog(f"{attr}: {value}")
        print()
        self._printlog(f"Retrieved {len(entries)} results total", log=True)
        logging.debug(f"Results written to {self.filename}")

    def _get_formatted_value(self, entry, attr):
        attr_l = attr.lower()
        if attr_l in self._ignore_attributes:
            return None

        value = entry["attributes"][attr]

        if attr_l in self._raw_attributes:
            if isinstance(value, list):
                value = value[0]
            if isinstance(value, datetime.datetime):
                if attr_l in self._filetime_attributes:
                    val = str(self._datetime_to_filetime(value))
                else:
                    val = value.astimezone(datetime.timezone.utc).strftime("%Y%m%d%H%M%S.0Z")
            elif isinstance(value, bytes):
                val = value.decode("utf-8")
            else:
                val = str(value)
        elif isinstance(value, list):
            if attr_l in self._base64_attributes:
                values = [base64.b64encode(val).decode("utf-8") if isinstance(val, bytes) else base64.b64encode(str(val).encode("utf-8")).decode("utf-8") for val in value]
                val = ", ".join(values)
            elif len(value) > 0 and isinstance(value[0], bytes):
                strings = [val.decode("utf-8") for val in value]
                val = ", ".join(strings)
            else:
                val = ", ".join(str(item) for item in value)
        elif attr_l in self._base64_attributes:
            if isinstance(value, bytes):
                val = base64.b64encode(value).decode("utf-8")
            else:
                val = base64.b64encode(str(value).encode("utf-8")).decode("utf-8")
        else:
            val = value

        if isinstance(val, bytes):
            try:
                val = val.decode("utf-8")
            except UnicodeDecodeError as e:
                logging.debug(f"Unable to decode {attr} as utf-8")
                raise e

        return val

    @staticmethod
    def _datetime_to_filetime(value):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        delta = value.astimezone(datetime.timezone.utc) - epoch
        return ((delta.days * 86400) + delta.seconds) * 10_000_000 + (delta.microseconds * 10)


app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    pretty_exceptions_enable=False,
)


@app.command(no_args_is_help=True)
def main(
    target: str = typer.Argument(..., help="[[domain/]username[:password]"),
    filter: str = typer.Argument(..., help="LDAP filter string"),
    attributes: str = typer.Option("", "-attributes", help="Comma separated list of attributes", rich_help_panel="Search Options"),
    result_count: int = typer.Option(0, "-limit", help="Limit the number of results to return", rich_help_panel="Search Options"),
    domain_controller: str = typer.Option("", "-dc-ip", help="Domain controller IP or hostname to query", rich_help_panel="Connection Options"),
    distinguished_name: str = typer.Option("", "-base-dn", help="Search base distinguished name to use. Default is base domain level", rich_help_panel="Search Options"),
    scope: SearchScope = typer.Option(SearchScope.SUBTREE, "-scope", help="Scope the query has to be performed", case_sensitive=False, rich_help_panel="Search Options"),
    no_sd: bool = typer.Option(False, "-no-sd", help="Do not add nTSecurityDescriptor as an attribute queried by default. Reduces console output significantly", rich_help_panel="Search Options"),
    debug: bool = typer.Option(False, "-debug", help="Turn DEBUG output ON"),
    hashes: str = typer.Option(None, "-hashes", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH", rich_help_panel="Connection Options"),
    no_pass: bool = typer.Option(False, "-no-pass", help="Don't ask for password (useful for -k)", rich_help_panel="Connection Options"),
    kerberos: bool = typer.Option(
        False,
        "-k",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
        rich_help_panel="Connection Options",
    ),
    aesKey: str = typer.Option(None, "-aesKey", help="AES key to use for Kerberos Authentication (128 or 256 bits)", rich_help_panel="Connection Options"),
    ldaps: bool = typer.Option(False, "-ldaps", help="Use LDAPS instead of LDAP", rich_help_panel="Connection Options"),
    no_smb: bool = typer.Option(
        False,
        "-no-smb",
        help="Do not make a SMB connection to the DC to get its hostname (useful for -k). "
        "Requires a hostname to be provided with -dc-ip",
        rich_help_panel="Connection Options",
    ),
    output: str = typer.Option(None, "-output", help="Result output file for this specific search (logging is still enabled)"),
    silent: bool = typer.Option(False, "-silent", help="Do not print query results to console (results will still be logged)", rich_help_panel="Search Options"),
):
    """
    Tool for issuing manual LDAP queries which offers bofhound compatible output
    """

    print(version.BANNER)
    logger.init()

    logging.info(f"pyldapsearch v{__version__} - Tw1sm\n")

    domain, username, password = parse_credentials(target)

    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    home = os.path.expanduser("~")
    pyldapsearch_dir = f"{home}/.pyldapsearch"
    logs_dir = f"{pyldapsearch_dir}/logs"

    if not os.path.isdir(pyldapsearch_dir):
        logging.info("First time usage detected")
        logging.info(f"pyldapsearch output will be logged to {logs_dir}")
        os.mkdir(pyldapsearch_dir)
        print()

    if not os.path.isdir(logs_dir):
        os.mkdir(logs_dir)

    if password == "" and username != "" and hashes is None and no_pass is False and aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    lm_hash = ""
    nt_hash = ""
    if hashes is not None:
        if ":" in hashes:
            lm_hash = hashes.split(":")[0]
            nt_hash = hashes.split(":")[1]
        else:
            nt_hash = hashes

    if nt_hash:
        try:
            nt_hash = binascii.unhexlify(nt_hash).hex()
        except (binascii.Error, ValueError):
            pass

    if distinguished_name == "":
        search_base = get_dn(domain)
    else:
        search_base = distinguished_name.upper()

    if domain_controller == "":
        domain_controller = domain

    ldap_server = ""
    ldap_session = ""
    ldapsearch = ""
    try:
        ldap_server, ldap_session = init_ldap_session(
            domain=domain,
            username=username,
            password=password,
            lmhash=lm_hash,
            nthash=nt_hash,
            kerberos=kerberos,
            domain_controller=domain_controller,
            ldaps=ldaps,
            hashes=hashes,
            aesKey=aesKey,
            no_smb=no_smb,
        )
        ldapsearch = Ldapsearch(ldap_server, ldap_session, scope.value, filter, attributes, result_count, search_base, no_sd, logs_dir, silent, output)
        logging.debug("LDAP bind successful")
    except Exception as e:
        if "invalid server address" in str(e).lower():
            logging.critical(f"Invalid server address - {domain_controller}")
        else:
            logging.critical(f"Error: {str(e)}")
        raise typer.Exit(code=1)

    ldapsearch.query()


if __name__ == "__main__":
    app(prog_name="pyldapsearch")
