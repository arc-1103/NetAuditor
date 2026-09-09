from enum import Enum


class HashAlgorithm(str, Enum):
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class EncryptionAlgorithm(str, Enum):
    DES = "DES"
    _3DES = "3DES"
    AES128 = "AES128"
    AES256 = "AES256"
    CHACHA20 = "CHACHA20"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ProtocolStatus(str, Enum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class ACLAction(str, Enum):
    PERMIT = "permit"
    DENY = "deny"


class ComplianceFramework(str, Enum):
    CIS = "CIS"
    NIST = "NIST"
    STIG = "STIG"


class SNMPVersion(str, Enum):
    V1 = "v1"
    V2C = "v2c"
    V3 = "v3"
    NONE = "none"


class SSHVersion(str, Enum):
    V1 = "1"
    V2 = "2"
    V1_2 = "1-2"
    NONE = "none"
