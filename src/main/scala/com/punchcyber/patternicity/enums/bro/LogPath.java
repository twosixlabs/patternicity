package com.punchcyber.patternicity.enums.bro;

@SuppressWarnings("unused")
public enum LogPath {
    // Network Protocols log files
    CONN,
    DCE_RPC,
    DHCP,
    DNP3,
    DNS,
    FTP,
    HTTP,
    IRC,
    KERBEROS,
    MODBUS,
    MODBUS_REGISTER_CHANGE,
    MYSQL,
    NTLM,
    RADIUS,
    RDP,
    RFB,
    SIP,
    SMB_CMD,
    SMB_FILES,
    SMB_MAPPING,
    SMTP,
    SNMP,
    SOCKS,
    SSH,
    SSL,
    SYSLOG,
    TUNNEL,
    
    // Files log files
    FILES,
    OCSP,
    PE,
    X509,
    
    // Netcontrol log files
    NETCONTROL,
    NETCONTROL_DROP,
    NETCONTROL_SHUNT,
    NETCONTROL_CATCH_RELEASE,
    OPENFLOW,
    
    // Detection log files
    INTEL,
    NOTICE,
    NOTICE_ALARM,
    SIGNATURES,
    TRACEROUTE,
    
    // Network Observations log files
    KNOWN_CERTS,
    KNOWN_HOSTS,
    KNOWN_MODBUS,
    KNOWN_SERVICES,
    SOFTWARE,
    
    // Miscellaneous log files
    BARNYARD2,
    DPD,
    UNIFIED2,
    WEIRD,
    WEIRD_STATS,
    
    // Bro Diagnostics log files
    BROKER,
    CAPTURE_LOSS,
    CLUSTER,
    CONFIG,
    LOADED_SCRIPTS,
    PACKET_FILTER,
    PROF,
    REPORTER,
    STATS,
    STDERR,
    STDOUT,
    
    // We use this for error reporting
    UNSUPPORTED
}
