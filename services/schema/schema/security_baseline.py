from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .enums import (
    ACLAction,
    EncryptionAlgorithm,
    HashAlgorithm,
    ProtocolStatus,
    SNMPVersion,
    SSHVersion,
)

SCHEMA_VERSION = "1.0.0"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=True)


class DeviceMetadata(StrictModel):
    raw_hostname: str | None = None
    detected_vendor: str
    detected_os: str | None = None
    detected_os_version: str | None = None
    detected_hardware_model: str | None = None
    config_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    parsing_confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    unknown_blocks_count: Annotated[int, Field(ge=0)] = 0


class AAAConfig(StrictModel):
    authentication_method: list[str] = Field(default_factory=list)
    authorization_enabled: bool = False
    accounting_enabled: bool = False
    local_user_privilege_levels: list[int] = Field(default_factory=list)
    password_encryption: ProtocolStatus = ProtocolStatus.UNKNOWN
    password_min_length: int | None = None
    password_complexity_enabled: bool = False


class SSHConfig(StrictModel):
    enabled: bool = False
    version: SSHVersion = SSHVersion.NONE
    idle_timeout_seconds: int | None = None
    authentication_retries: int | None = None
    allowed_ciphers: list[str] = Field(default_factory=list)
    allowed_macs: list[str] = Field(default_factory=list)
    allowed_kex: list[str] = Field(default_factory=list)
    management_acl: str | None = None


class TelnetConfig(StrictModel):
    enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    vty_lines_with_telnet: list[str] = Field(default_factory=list)


class SNMPConfig(StrictModel):
    enabled: bool = False
    version: SNMPVersion = SNMPVersion.NONE
    community_strings: list[str] = Field(default_factory=list)
    auth_protocol: HashAlgorithm = HashAlgorithm.UNKNOWN
    priv_protocol: EncryptionAlgorithm = EncryptionAlgorithm.UNKNOWN
    trap_host: str | None = None
    access_acl: str | None = None


class LoggingConfig(StrictModel):
    syslog_enabled: bool = False
    syslog_hosts: list[str] = Field(default_factory=list)
    syslog_severity_level: int | None = Field(default=None, ge=0, le=7)
    local_buffer_enabled: bool = False
    local_buffer_severity: int | None = None
    timestamps_enabled: bool = False
    source_interface: str | None = None


class NTPConfig(StrictModel):
    enabled: bool = False
    servers: list[str] = Field(default_factory=list)
    authentication_enabled: bool = False
    peer_auth_key_hash: HashAlgorithm = HashAlgorithm.UNKNOWN
    source_interface: str | None = None


class ACLEntry(StrictModel):
    sequence: int | None = None
    action: ACLAction
    protocol: str
    source: str
    destination: str
    port: str | None = None


class ACLConfig(StrictModel):
    ingress_acl_name: str | None = None
    ingress_acl_applied: bool = False
    egress_acl_name: str | None = None
    egress_acl_applied: bool = False
    ingress_entries: list[ACLEntry] = Field(default_factory=list)
    egress_entries: list[ACLEntry] = Field(default_factory=list)
    implicit_deny_present: bool = False


class CryptoIKEPolicy(StrictModel):
    policy_id: int | None = None
    encryption: EncryptionAlgorithm = EncryptionAlgorithm.UNKNOWN
    hash_algorithm: HashAlgorithm = HashAlgorithm.UNKNOWN
    dh_group: int | None = None
    lifetime_seconds: int | None = None
    authentication_method: str | None = None


class CryptoConfig(StrictModel):
    ike_policies: list[CryptoIKEPolicy] = Field(default_factory=list)
    pki_enabled: bool = False
    certificate_auth: bool = False
    weak_ciphers_detected: list[str] = Field(default_factory=list)


class BannerConfig(StrictModel):
    login_banner_present: bool = False
    motd_banner_present: bool = False
    banner_text_snippet: str | None = Field(default=None, max_length=200)


class ServiceConfig(StrictModel):
    http_server_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    https_server_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    cdp_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    lldp_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    finger_service_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    ip_source_route_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    proxy_arp_enabled: ProtocolStatus = ProtocolStatus.UNKNOWN
    ip_directed_broadcast: ProtocolStatus = ProtocolStatus.UNKNOWN
    tcp_small_servers: ProtocolStatus = ProtocolStatus.UNKNOWN
    udp_small_servers: ProtocolStatus = ProtocolStatus.UNKNOWN


class SecurityBaseline(StrictModel):
    schema_version: str = SCHEMA_VERSION
    device: DeviceMetadata
    aaa: AAAConfig = Field(default_factory=AAAConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    telnet: TelnetConfig = Field(default_factory=TelnetConfig)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ntp: NTPConfig = Field(default_factory=NTPConfig)
    acl: ACLConfig = Field(default_factory=ACLConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    banners: BannerConfig = Field(default_factory=BannerConfig)
    services: ServiceConfig = Field(default_factory=ServiceConfig)

    @field_validator("schema_version")
    @classmethod
    def schema_version_must_match(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
        return value
