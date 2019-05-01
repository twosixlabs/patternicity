create table KARL.ACAS (
    macAddress VARCHAR NOT NULL,
    protocol VARCHAR NOT NULL,
    vulnPubDate BIGINT,
    family_type VARCHAR,
    family_id INTEGER,
    family_name VARCHAR,
    ip VARCHAR NOT NULL,

    pluginText VARCHAR NOT NULL,
    port INTEGER,
    pluginPubDate BIGINT,
    acceptRisk DOUBLE NOT NULL,
    hasBeenMitigated BOOLEAN NOT NULL,

    severity_type VARCHAR,
    severity_id BIGINT,
    severity_name VARCHAR,
    synopsis VARCHAR NOT NULL,
    baseScore DOUBLE,
    pluginId BIGINT NOT NULL,

    version VARCHAR NOT NULL,
    checkType VARCHAR NOT NULL,
    dnsName VARCHAR NOT NULL,
    riskFactor VARCHAR NOT NULL,

    temporalScore DOUBLE,
    exploitFrameworks VARCHAR NOT NULL,
    description VARCHAR NOT NULL,

    repository_description VARCHAR,
    repository_id INTEGER,
    repository_name VARCHAR,
    bid VARCHAR NOT NULL,
    xref VARCHAR NOT NULL,
    stigSeverity DOUBLE,

    firstSeen BIGINT NOT NULL,
    netbiosName VARCHAR NOT NULL,
    pluginName VARCHAR NOT NULL,
    exploitEase DOUBLE,

    patchPubDate BIGINT,
    cve VARCHAR NOT NULL,
    seeAlso VARCHAR NOT NULL,

    exploitAvailable BOOLEAN NOT NULL,
    cpe VARCHAR NOT NULL,
    recastRisk DOUBLE,
    cvssVector VARCHAR NOT NULL,
    lastSeen BIGINT NOT NULL

    CONSTRAINT PK PRIMARY KEY(ip,pluginId,firstSeen,lastSeen))

IMMUTABLE_ROWS=true,DISABLE_WAL=true,APPEND_ONLY_SCHEMA=true,UPDATE_CACHE_FREQUENCY=30000;

