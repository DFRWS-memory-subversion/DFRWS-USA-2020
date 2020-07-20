# Rekall Memory Forensics
# Copyright 2015 Google Inc. All Rights Reserved.
#
# This file is part of Rekall Memory Forensics.
#
# Rekall Memory Forensics is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General Public
# License.
#
# Rekall Memory Forensics is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Rekall Memory Forensics.  If not, see <http://www.gnu.org/licenses/>.
#

"""Partial emulation of the Mimikatz tool.

This code replicates the algorithm first implemented in the mimikatz tool,
which can be found here:

https://github.com/gentilkiwi/mimikatz
"""

# pylint: disable=protected-access

from builtins import str
__author__ = ("Michael Cohen <scudette@google.com> and "
              "Francesco Picasso <francesco.picasso@gmail.com>")

import binascii
import logging

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Cipher import ARC4

from rekall import addrspace
from rekall import obj

from rekall.plugins.overlays.windows import pe_vtypes
from rekall.plugins.windows import common
from rekall.plugins.windows import lsadecryptxp


mimikatz_common_overlays = {
    '_LSA_UNICODE_STRING': [None, {
        'Value': lambda x: x.Buffer.dereference_as(
            'UnicodeString', target_args=dict(length=x.Length)),
        'Raw': lambda x: x.Buffer.dereference_as(
            'String', target_args=dict(length=x.Length, term=None)).v(),
        'RawMax': lambda x: x.Buffer.dereference_as(
            'String', target_args=dict(length=x.MaximumLength, term=None)).v(),
    }],
    '_LSA_STRING': [None, {
        'Value': lambda x: x.Buffer.dereference_as(
            'String', target_args=dict(length=x.Length)),
        'Raw': lambda x: x.Buffer.dereference_as(
            'String', target_args=dict(length=x.Length, term=None)).v(),
        'RawMax': lambda x: x.Buffer.dereference_as(
            'String', target_args=dict(length=x.MaximumLength, term=None)).v(),
    }],
    '_LUID': [None, {
        'Text': lambda x: '{:08x}:{:08x}'.format(x.HighPart, x.LowPart)
        }],
    '_SID': [None, {
        'IdentifierAuthority': [None, ['Enumeration', dict(
            choices={
                '\x00\x00\x00\x00\x00\x00': 'Null Authority',
                '\x00\x00\x00\x00\x00\x01': 'World Authority',
                '\x00\x00\x00\x00\x00\x02': 'Local Authority',
                '\x00\x00\x00\x00\x00\x03': 'Creator Authority',
                '\x00\x00\x00\x00\x00\x04': 'NonUnique Authority',
                '\x00\x00\x00\x00\x00\x05': 'NT Authority',
                },
            target='String',
            target_args=dict(length=6, term=None)
            )]],
        'NumericIdentifier': [0x4, ['unsigned be int']],
        'SubAuthority': [None, ['Array', dict(
            target='unsigned long',
            count=lambda x: x.SubAuthorityCount)]],
        }],
}


class _SID(obj.Struct):
    """A Pretty printing implementation of sids.

    Reference:
    http://www.sekchek.com/downloads/white-papers/windows-about-sids.pdf
    """
    def __str__(self):
        """Format the Sid using SDDL Notation."""
        components = [self.Revision, self.NumericIdentifier]
        components.extend(self.SubAuthority)

        return u"S-" + u"-".join([str(x) for x in components])


class Lsasrv(pe_vtypes.BasicPEProfile):
    """A profile for lsasrv.dll"""

    mimikatz_vtypes = [
        '_LIST_ENTRY', '_LSA_UNICODE_STRING', '_LUID',
        '_LSA_STRING', '_MSV1_0_PRIMARY_CREDENTIAL',
        '_KIWI_BCRYPT_HANDLE_KEY', '_KIWI_HARD_KEY',
        '_KIWI_MSV1_0_CREDENTIALS', '_KIWI_MSV1_0_PRIMARY_CREDENTIALS',
        '_KIWI_GENERIC_PRIMARY_CREDENTIAL',
        '_KIWI_MASTERKEY_CACHE_ENTRY', '_FILETIME']

    windows_vtypes = ['_SID', '_SID_IDENTIFIER_AUTHORITY', '_GUID']

    # TODO: should be special cases (1or2) addressed?
    mimikatz_msv_versioned = {
        5.1: '_KIWI_MSV1_0_LIST_51',
        5.2: '_KIWI_MSV1_0_LIST_52',
        6.0: '_KIWI_MSV1_0_LIST_60',
        6.1: '_KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ',
        6.2: '_KIWI_MSV1_0_LIST_62',
        6.3: '_KIWI_MSV1_0_LIST_63',
    }

    mimikatz_key_versioned = {
        5.1: '_KIWI_BCRYPT_KEY',
        5.2: '_KIWI_BCRYPT_KEY',
        6.0: '_KIWI_BCRYPT_KEY',
        6.1: '_KIWI_BCRYPT_KEY',
        6.2: '_KIWI_BCRYPT_KEY8',
        6.3: '_KIWI_BCRYPT_KEY81',
    }

    @classmethod
    def Initialize(cls, profile):
        super(cls, Lsasrv).Initialize(profile)

        arch = profile.session.profile.metadata('arch')

        mimikatz_profile = profile.session.LoadProfile('mimikatz/%s' % arch)
        if not mimikatz_profile:
            raise IOError('Unable to load mimikatz profile from repository!')

        kwargs = {}
        for name in cls.mimikatz_vtypes:
            kwargs[name] = mimikatz_profile.vtypes[name]

        for name in cls.windows_vtypes:
            kwargs[name] = profile.session.profile.vtypes[name]

        profile.add_types(kwargs)

        profile.add_types({
            'SIZED_DATA': [lambda x: x.size + 4, {
                'size': [0, ['unsigned long', {}]],
                'data': [4, ['String', dict(length=lambda x: x.size)]],
            }]
        })

        version = profile.session.profile.metadata('version')
        if version not in cls.mimikatz_msv_versioned:
            raise IOError('OS version not supported.')

        profile.add_types({
            'MSV1_0_LIST': mimikatz_profile.vtypes[
                cls.mimikatz_msv_versioned[version]]
        })

        profile.add_types({
            '_KIWI_BCRYPT_KEY': mimikatz_profile.vtypes[
                cls.mimikatz_key_versioned[version]]
        })

        profile.add_classes(_SID=_SID)

        profile.add_overlay(mimikatz_common_overlays)

        profile.add_overlay({
            '_KIWI_HARD_KEY': [None, {
                'data': lambda x: x.m('data').cast(
                    'String', term=None, length=x.cbSecret)
            }],
            'MSV1_0_LIST': [None, {
                'List': [0, ['_LIST_ENTRY']],
                'pSid': [None, ['Pointer', dict(target='_SID')]],
                'LogonType': [None, ['Enumeration', dict(
                    target='unsigned int',
                    choices={
                        2: 'Interactive',
                        3: 'Network',
                        4: 'Batch',
                        5: 'Service',
                        6: 'Proxy',
                        7: 'Unlock',
                        8: 'NetworkCleartext',
                        9: 'NewCredentials',
                        10: 'RemoteInteractive',
                        11: 'CachedInteractive',
                        12: 'CachedRemoteInteractive',
                        13: 'CachedUnlock',
                    },
                )]],
            }],
            '_MSV1_0_PRIMARY_CREDENTIAL': [None, {
                'NtOwfPassword': [None, ['String', dict(length=16)]],
                'LmOwfPassword': [None, ['String', dict(length=16)]],
                'ShaOwPassword': [None, ['String', dict(length=20)]],
            }],
            '_KIWI_MASTERKEY_CACHE_ENTRY': [None, {
                'List': [0, ['_LIST_ENTRY']],
                'key': [None, ['String', dict(length=lambda x: x.keySize)]],
            }],
        })

    def init_crypto(self):
        if self.session.profile.metadata('version') < 6.0:
            self.decryption_enabled = self.init_crypto_nt5()
        else:
            self.decryption_enabled = self.init_crypto_nt6()
        if not self.decryption_enabled:
            logging.warning('AES:     {}'.format(self.aes_key.encode('hex')))
            logging.warning('IV:      {}'.format(self.iv.encode('hex')))
            logging.warning('DES key: {}'.format(self.des_key.encode('hex')))
            logging.error('Unable to initialize decryption keys!')

    def decrypt(self, encrypted):
        if self.session.profile.metadata('version') < 6.0:
            return self.decrypt_nt5(encrypted)
        else:
            return self.decrypt_nt6(encrypted)

    def init_crypto_nt6(self):
        self.iv = self.get_constant_object(
            'InitializationVector', 'String', length=16, term=None).v()

        aes_handle = self.get_constant_object(
            'hAesKey', target='Pointer',
            target_args=dict(target='_KIWI_BCRYPT_HANDLE_KEY'))

        self.aes_key = aes_handle.key.hardkey.data.v()

        des_handle = self.get_constant_object(
            'h3DesKey', target='Pointer',
            target_args=dict(target='_KIWI_BCRYPT_HANDLE_KEY'))

        self.des_key = des_handle.key.hardkey.data.v()

        try:
            cipher = AES.new(self.aes_key, AES.MODE_CFB, self.iv)
            cipher = DES3.new(self.des_key, DES3.MODE_CBC, self.iv[:8])
            cipher = None
            decryption_enabled = True
        except ValueError as e_ve:
            decryption_enabled = False
            logging.warning('init_crypto_nt6 exception {}'.format(e_ve))
        finally:
            return decryption_enabled

    def decrypt_nt6(self, encrypted):
        if not self.decryption_enabled:
            return obj.NoneObject()

        cipher = None
        if self.iv:
            if len(encrypted) % 8:
                cipher = AES.new(self.aes_key, AES.MODE_CFB, self.iv)
            else:
                if self.des_key:
                    cipher = DES3.new(self.des_key, DES3.MODE_CBC, self.iv[:8])
        if cipher and encrypted:
            return cipher.decrypt(encrypted)
        return obj.NoneObject()

    def init_crypto_nt5(self):
        rc4_key_len = self.get_constant_object(
            'g_cbRandomKey', 'unsigned long').v()

        rc4_key_ptr = self.get_constant_object(
            'g_pRandomKey', target='Pointer')

        self.rc4_key = rc4_key_ptr.dereference_as(
            'String', target_args=dict(length=rc4_key_len, term=None)).v()

        desx_key_ptr = self.get_constant_object(
            'g_pDESXKey', target='Pointer')

        self.desx_key = desx_key_ptr.dereference_as(
            'String', target_args=dict(length=144, term=None)).v()

        self.feedback = self.get_constant_object(
            'g_Feedback', target='String',
            target_args=dict(length=8)).v()

        try:
            cipher = ARC4.new(self.rc4_key)
            decryption_enabled = True
        except ValueError as e_ve:
            decryption_enabled = False
            logging.warning('init_crypto_nt5 exception {}'.format(e_ve))
        finally:
            return decryption_enabled

    def decrypt_nt5(self, encrypted):
        if not self.decryption_enabled:
            return obj.NoneObject()

        cipher = None
        if len(encrypted) % 8:
            if self.rc4_key:
                cipher = ARC4.new(self.rc4_key)
        else:
            if self.desx_key and self.feedback:
                cipher = lsadecryptxp.XP_LsaDecryptMemory(
                    self.desx_key, self.feedback)
        if cipher and encrypted:
            return cipher.decrypt(encrypted)
        return obj.NoneObject()

    def get_lsass_logons(self):
        logons = {}
        lsass_logons = self.get_constant_object(
            'LogonSessionList', target='_LIST_ENTRY')
        for entry in lsass_logons.list_of_type('MSV1_0_LIST', 'List'):
            logons[entry.LocallyUniqueIdentifier.Text] = entry
        return logons

    def _msv_primary_credentials(self, data):
        vm = addrspace.BufferAddressSpace(data=data, session=self.session)
        cred_obj = self.Object('_MSV1_0_PRIMARY_CREDENTIAL',
                               profile=self, vm=vm)

        # TODO: check NULL Pointer dereference with this VM.
        domain = ''
        if cred_obj.LogonDomainName.Buffer.is_valid():
            domain = cred_obj.LogonDomainName.Value

        user_name = ''
        if cred_obj.UserName.Buffer.is_valid():
            user_name = cred_obj.UserName.Value

        if cred_obj.isLmOwfPassword.v() == 1:
            yield (domain, user_name, 'LM',
                   binascii.hexlify(cred_obj.LmOwfPassword.v()))

        if cred_obj.isNtOwfPassword.v() == 1:
            yield (domain, user_name, 'NTLM',
                   binascii.hexlify(cred_obj.NtOwfPassword.v()))

        if cred_obj.isShaOwPassword.v() == 1:
            yield (domain, user_name, 'SHA1',
                   binascii.hexlify(cred_obj.ShaOwPassword.v()))

    def logons(self, lsass_logons):
        for luid, lsass_logon in lsass_logons.items():
            for cred in lsass_logon.Credentials.walk_list('next'):
                for primary_cred in cred.PrimaryCredentials.walk_list('next'):

                    dec_cred = self.decrypt(primary_cred.Credentials.Raw)
                    if not dec_cred:
                        continue

                    cur_cred_type = primary_cred.Primary.Value

                    if cur_cred_type == u'Primary':
                        for (domain, user_name, secret_type,
                        secret) in self._msv_primary_credentials(dec_cred):
                            yield (luid, cur_cred_type, domain, user_name,
                                   secret_type, secret)
                    else:
                        pass

    def master_keys(self):
        keys = self.get_constant_object(
            'g_MasterKeyCacheList', target='_LIST_ENTRY')
        for entry in keys.list_of_type('_KIWI_MASTERKEY_CACHE_ENTRY', 'List'):
            logonId = entry.LogonId
            if logonId.HighPart.v() == 0 and logonId.LowPart.v() == 0:
                continue
            yield (logonId.Text, '',
                   '', '', 'masterkey',
                   binascii.hexlify(self.decrypt(entry.key.v())))


class Wdigest(pe_vtypes.BasicPEProfile):
    """A profile for wdigest.dll"""

    mimikatz_vtypes = [
        '_LIST_ENTRY', '_LSA_UNICODE_STRING', '_LUID',
        '_KIWI_WDIGEST_LIST_ENTRY', '_KIWI_GENERIC_PRIMARY_CREDENTIAL',
        '_KIWI_HARD_KEY']

    @classmethod
    def Initialize(cls, profile):
        super(cls, Wdigest).Initialize(profile)

        arch = profile.session.profile.metadata('arch')
        mimikatz_profile = profile.session.LoadProfile('mimikatz/%s' % arch)

        kwargs = {}
        for name in cls.mimikatz_vtypes:
            kwargs[name] = mimikatz_profile.vtypes[name]

        profile.add_types(kwargs)

        profile.add_overlay(mimikatz_common_overlays)

        kiwi_cred_offset = 8
        if profile.session.profile.metadata('version') < 6.0:
            kiwi_cred_offset = 12

        profile.add_overlay({
            '_KIWI_WDIGEST_LIST_ENTRY': [None, {
                'List': [0, ['_LIST_ENTRY']],
                'Cred': [lambda x: (x.LocallyUniqueIdentifier.obj_end +
                                    kiwi_cred_offset),
                         ['_KIWI_GENERIC_PRIMARY_CREDENTIAL']]
            }],
            '_KIWI_HARD_KEY': [None, {
                'data': lambda x: x.m('data').cast(
                    'String', term=None, length=x.cbSecret)
            }],
        })

    def logons(self):
        # TODO: if the symbols are wrong? Add a check for the LIST validity.
        logons = self.get_constant_object(
            'l_LogSessList', target='_LIST_ENTRY')
        for entry in logons.list_of_type('_KIWI_WDIGEST_LIST_ENTRY', 'List'):
            yield entry


class Livessp(pe_vtypes.BasicPEProfile):
    """A profile for livessp.dll"""

    mimikatz_vtypes = [
        '_LIST_ENTRY', '_LSA_UNICODE_STRING', '_LUID',
        '_KIWI_LIVESSP_LIST_ENTRY', '_KIWI_LIVESSP_PRIMARY_CREDENTIAL',
        '_KIWI_GENERIC_PRIMARY_CREDENTIAL']

    @classmethod
    def Initialize(cls, profile):
        super(cls, Livessp).Initialize(profile)

        arch = profile.session.profile.metadata('arch')
        mimikatz_profile = profile.session.LoadProfile('mimikatz/%s' % arch)

        kwargs = {}
        for name in cls.mimikatz_vtypes:
            kwargs[name] = mimikatz_profile.vtypes[name]

        profile.add_types(kwargs)

        profile.add_overlay(mimikatz_common_overlays)

        profile.add_overlay({
            '_KIWI_LIVESSP_LIST_ENTRY': [None, {
                'List': [0, ['_LIST_ENTRY']],
            }]
        })

    def logons(self):
        logons = self.get_constant_object(
            'LiveGlobalLogonSessionList', target='_LIST_ENTRY')
        for entry in logons.list_of_type('_KIWI_LIVESSP_LIST_ENTRY', 'List'):
            yield (entry.LocallyUniqueIdentifier.Text,
                   '',
                   entry.suppCreds.dereference().credentials.Domaine.Value,
                   entry.suppCreds.dereference().credentials.UserName.Value,
                   'password',
                   entry.suppCreds.dereference().credentials.Password)


class Mimikatz(common.WindowsCommandPlugin):
    """Extract and decrypt passwords from the LSA Security Service."""

    name = 'mimikatz'

    table_header = [
        dict(name='LUID', width=20),
        dict(name='Type', width=16),
        dict(name='Sess', width=2),
        dict(name='SID', width=20),
        dict(name='Module', width=7),
        dict(name='Info', width=7),
        dict(name='Domain', width=16),
        dict(name='User', width=16),
        dict(name='SType', width=9),
        dict(name='Secret', width=32)
    ]

    def __init__(self, *args, **kwargs):
        super(Mimikatz, self).__init__(*args, **kwargs)

        # Track the following modules. If we do not have them in the profile
        # repository then try to get them directly from Microsoft.
        tracked = self.session.GetParameter(
            'autodetect_build_local_tracked') or []

        needed = set(['lsasrv', 'wdigest', 'livessp'])
        if not needed.issubset(tracked):
            needed.update(tracked)
            with self.session as session:
                session.SetParameter('autodetect_build_local_tracked', needed)

    def collect(self):
        cc = self.session.plugins.cc()
        for task in self.session.plugins.pslist(
                proc_regex='lsass.exe').filter_processes():
            cc.SwitchProcessContext(task)

            lsasrv = None
            lsasrv_module = self.session.address_resolver.GetModuleByName(
                'lsasrv')

            if lsasrv_module:
                lsasrv = lsasrv_module.profile
                if not isinstance(lsasrv, Lsasrv):
                    logging.warning('Unable to properly initialize lsasrv!')
                    lsasrv = None

            if lsasrv:
                lsasrv.init_crypto()
                lsass_logons = lsasrv.get_lsass_logons()

                for (luid, info, domain, user_name, secret_type,
                     secret) in lsasrv.logons(lsass_logons):

                    lsass_entry = lsass_logons.get(luid, obj.NoneObject())
                    yield (luid,
                           lsass_entry.LogonType,
                           lsass_entry.Session,
                           lsass_entry.pSid.deref(),
                           'msv',
                           info,
                           domain,
                           user_name,
                           secret_type,
                           secret)

            wdigest = None
            wdigest_module = self.session.address_resolver.GetModuleByName(
                'wdigest')

            if wdigest_module:
                wdigest = wdigest_module.profile
                if not isinstance(wdigest, Wdigest):
                    logging.warning('Unable to properly initialize wdigest.')
                    wdigest = None
                else:
                    if not wdigest.get_constant('l_LogSessList'):
                        logging.warning('wdigest not initialized, KO.')
                        wdigest = None

            if wdigest:
                for entry in wdigest.logons():
                    luid = entry.LocallyUniqueIdentifier.Text
                    lsass_entry = lsass_logons.get(luid, obj.NoneObject())

                    yield (luid,
                           lsass_entry.LogonType,
                           lsass_entry.Session,
                           lsass_entry.pSid.deref(),
                           'wdigest',
                           '',
                           entry.Cred.Domaine.Value,
                           entry.Cred.UserName.Value,
                           'password',
                           lsasrv.decrypt(entry.Cred.Password.RawMax))

            livessp = None
            livessp_module = self.session.address_resolver.GetModuleByName(
                'livessp')

            if livessp_module:
                livessp = livessp_module.profile
                if not isinstance(livessp, Livessp):
                    logging.warning('Unable to properly initialize livessp.')
                    livessp = None
                else:
                    if not livessp.get_constant('LiveGlobalLogonSessionList'):
                        logging.warning('livessp not initialized, KO.')
                        livessp = None

            if livessp:
                for (luid, info, domain, user_name, secret_type,
                     enc_secret) in livessp.logons():
                    lsass_entry = lsass_logons.get(luid, obj.NoneObject())

                    yield (luid,
                           lsass_entry.LogonType,
                           lsass_entry.Session,
                           lsass_entry.pSid.deref(),
                           'livessp',
                           info,
                           domain,
                           user_name,
                           secret_type,
                           lsasrv.decrypt(enc_secret))

            if lsasrv:
                for (luid, info, domain, user_name, secret_type,
                     secret) in lsasrv.master_keys():
                    lsass_entry = lsass_logons.get(luid, obj.NoneObject())

                    yield (luid,
                           lsass_entry.LogonType,
                           lsass_entry.Session,
                           lsass_entry.pSid.deref(),
                           'lsasrv',
                           info,
                           domain,
                           user_name,
                           secret_type,
                           secret)
