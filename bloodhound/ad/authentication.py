####################
#
# Copyright (c) 2018 Fox-IT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

import logging
from ldap3 import Server, Connection, NTLM, ALL, SASL, DIGEST_MD5
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED

"""
Active Directory authentication helper
"""
class ADAuthentication(object):
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aes_key='', kdc=None, digest=False):
        self.username = username
        self.domain = domain
        if '@' in self.username:
            self.username, self.domain = self.username.rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aes_key = aes_key
        self.digest = digest
        self.kdc = kdc


    def getLDAPConnection(self, hostname='', baseDN='', protocol='ldaps', gc=False):
        if gc:
            # Global Catalog connection
            if protocol == 'ldaps':
                # Ldap SSL
                server = Server("%s://%s:3269" % (protocol, hostname), get_info=ALL)
            else:
                # Plain LDAP
                server = Server("%s://%s:3268" % (protocol, hostname), get_info=ALL)
        else:
            server = Server("%s://%s" % (protocol, hostname), get_info=ALL)
        # ldap3 supports auth with the NT hash. LM hash is actually ignored since only NTLMv2 is used.
        if self.nt_hash != '':
            ldappass = self.lm_hash + ':' + self.nt_hash
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.domain, self.username)
        if self.digest is False:
            conn = Connection(server, user=ldaplogin, auto_referrals=False, password=ldappass, authentication=NTLM, receive_timeout=60, auto_range=True)
        else:
            conn = Connection(server, auto_bind = True, version = 3, authentication=SASL, sasl_mechanism = DIGEST_MD5, receive_timeout=60, sasl_credentials = (None, self.username, self.password, None, 'sign'))
            #Connection(server, auto_bind = True, version = 3, client_strategy = test_strategy, authentication = SASL,
                         #sasl_mechanism = DIGEST_MD5, sasl_credentials = (None, 'username', 'password', None, 'sign'))

        # TODO: Kerberos auth for ldap
        if self.kdc is not None:
            logging.error('Kerberos login is not yet supported!')
            # try:
            #     logging.debug('Authenticating to LDAP server using Kerberos')
            #     conn.kerberosLogin(self.username, self.password, self.domain,
            #                        self.lm_hash, self.nt_hash, self.aes_key,
            #                        self.kdc)
            # except KerberosError as e:
            #     logging.warning('Kerberos login failed: %s' % e)
            #     return None
        else:
            logging.debug('Authenticating to LDAP server')
            if not conn.bind():
                result = conn.result
                if result['result'] == RESULT_STRONGER_AUTH_REQUIRED and protocol == 'ldap':
                    logging.warning('LDAP Authentication is refused because LDAP signing is enabled. '
                                    'Trying to connect over LDAPS instead...')
                    return self.getLDAPConnection(hostname, baseDN, 'ldaps')
                else:
                    logging.error('Failure to authenticate with LDAP! Error %s' % result['message'])
                    return None
        return conn
