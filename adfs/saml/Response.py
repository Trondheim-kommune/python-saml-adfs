import base64

from lxml import etree
from datetime import datetime, timedelta
import platform
import subprocess
import tempfile

from adfs.saml import SignatureVerifier

namespaces=dict(
    samlp='urn:oasis:names:tc:SAML:2.0:protocol',
    saml='urn:oasis:names:tc:SAML:2.0:assertion',
    )

class ResponseValidationError(Exception):
    """There was a problem validating the response"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class ResponseNameIDError(Exception):
    """There was a problem getting the name ID"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class ResponseConditionError(Exception):
    """There was a problem validating a condition"""
    def __init__(self, msg):
        self._msg = msg

    def __str__(self):
        return '%s: %s' % (self.__doc__, self._msg)

class Response(object):
    def __init__(
        self,
        response,
        signature,
        _base64=None,
        _etree=None,
        ):
        """
        Extract information from an samlp:Response
        Arguments:
        response -- The base64 encoded, XML string containing the samlp:Response
        signature -- The fingerprint to check the samlp:Response against
        """
        if _base64 is None:
            _base64 = base64
        if _etree is None:
            _etree = etree

        self._was_encrypted = False

        decoded_response = _base64.b64decode(response)
        self._document = _etree.fromstring(decoded_response)
        self._signature = signature

    def _parse_datetime(self, dt):
        # ADFS will provide milliseconds (handled by %f)
        return datetime.strptime(dt, '%Y-%m-%dT%H:%M:%S.%fZ')

    def get_assertion_root(self):
        if self._was_encrypted:
            return '/samlp:Response/saml:EncryptedAssertion/saml:Assertion'
        else:
            return '/samlp:Response/saml:Assertion'


    def _get_name_id(self):
        result = self._document.xpath(
            self.get_assertion_root() + '/saml:Subject/saml:NameID',
            namespaces=namespaces,
            )
        length = len(result)
        if length > 1:
            raise ResponseNameIDError(
                'Found more than one name ID'
                )
        if length == 0:
            raise ResponseNameIDError(
                'Did not find a name ID'
                )

        node = result.pop()

        return node.text.strip()

    name_id = property(
        fget=_get_name_id,
        doc="The value requested in the name_identifier_format, e.g., the user's email address",
        )

    def get_assertion_attribute_value(self,attribute_name):
        """
        Get the value of an AssertionAttribute, located in an Assertion/AttributeStatement/Attribute[@Name=attribute_name/AttributeValue tag
        """
        result = self._document.xpath(self.get_assertion_root() + '/saml:AttributeStatement/saml:Attribute[@Name="%s"]/saml:AttributeValue'%attribute_name,namespaces=namespaces)
        return [n.text.strip() for n in result]

    def decrypt(self, private_key_file):
        with tempfile.NamedTemporaryFile() as xml_fp:
            self.write_xml_to_file(self._document, xml_fp)
            xmlsec_bin = self._get_xmlsec_bin()
            decrypted_response = self.decrypt_xml(xml_fp.name, xmlsec_bin, private_key_file)
            self._document = etree.fromstring(decrypted_response)
            self._was_encrypted = True


    @staticmethod
    def _get_xmlsec_bin():
        xmlsec_bin = 'xmlsec1'
        if platform.system() == 'Windows':
            xmlsec_bin = 'xmlsec.exe'

        return xmlsec_bin

    @staticmethod
    def write_xml_to_file(document, xml_fp):
        doc_str = etree.tostring(document)
        xml_fp.write('<?xml version="1.0" encoding="utf-8"?>')
        xml_fp.write(doc_str)
        xml_fp.seek(0)

    @staticmethod
    def decrypt_xml(xml_filename, xmlsec_bin, private_key_file):
        cmds = [
            xmlsec_bin,
            '--decrypt',
            '--privkey-pem',
            private_key_file,
            xml_filename
            ]

        proc = subprocess.Popen(
            cmds,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            )
        out, err = proc.communicate()
        return out


    def is_valid(
        self,
        _clock=None,
        _verifier=None,
        ):
        """
        Verify that the samlp:Response is valid.
        Return True if valid, otherwise False.
        """
        if _clock is None:
            _clock = datetime.utcnow
        if _verifier is None:
            _verifier = SignatureVerifier.verify

        conditions = self._document.xpath(
            self.get_assertion_root() + '/saml:Conditions',
            namespaces=namespaces,
            )

        now = _clock()

        not_before = None
        not_on_or_after = None
        for condition in conditions:
            not_on_or_after = condition.attrib.get('NotOnOrAfter', None)
            not_before = condition.attrib.get('NotBefore', None)

        if not_before is None:
            raise ResponseConditionError('Did not find NotBefore condition')
        if not_on_or_after is None:
            raise ResponseConditionError('Did not find NotOnOrAfter condition')

        not_before = self._parse_datetime(not_before)
        not_on_or_after = self._parse_datetime(not_on_or_after)

        # Allow five seconds wiggle room here since adfs server and client clocks drift
        if now + timedelta(seconds=5) < not_before:
            raise ResponseValidationError(
                'Current time is earlier than NotBefore condition'
                )
        if now >= not_on_or_after:
            raise ResponseValidationError(
                'Current time is on or after NotOnOrAfter condition'
                )

        return _verifier(
            self._document,
            self._signature,
            )
