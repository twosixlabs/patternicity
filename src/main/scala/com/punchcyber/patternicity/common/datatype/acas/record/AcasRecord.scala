package com.punchcyber.patternicity.common.datatype.acas.record

case class AcasFamily(familyType: String, id: Long, name: String)
case class AcasSeverity(description: String, id: Long, name: String)
case class AcasRepository(description: String, id: Long, name: String)

case class AcasRecord(macAddress: String, protocol: String, vulnPubDate: Long, family: AcasFamily, ip: String,
                      exploitAvailable: Boolean, cpe: String, recastRisk: Double, cvssVector: String, lastSeen: Long,
                      pluginText: String, port: Int, pluginPubDate: Long, acceptRisk: Double, hasBeenMitigated: Boolean,
                      severity: AcasSeverity, synopsis: String, baseScore: Option[Double], pluginId: Long,
                      version: String, checkType: String, dnsName: String, riskFactor: String,
                      temporalScore: Option[Double], exploitFrameworks: String, description: String,
                      repository: AcasRepository, bid: String, xref: String, stigSeverity: Option[Double],
                      firstSeen: Long, netbiosName: String, pluginName: String, exploitEase: Option[Double],
                      patchPubDate: Option[Long], cve: String, seeAlso: String)

case class AcasFamilyRaw(`type`: String, id: String, name: String)
case class AcasSeverityRaw(description: String, id: String, name: String)
case class AcasRepositoryRaw(description: String, id: String, name: String)

case class AcasRecordRaw(macAddress: String, protocol: String, vulnPubDate: String, family: AcasFamilyRaw, ip: String,
                      exploitAvailable: String, cpe: String, recastRisk: String, cvssVector: String, lastSeen: String,
                      pluginText: String, port: String, pluginPubDate: String, acceptRisk: String, hasBeenMitigated: String,
                      severity: AcasSeverityRaw, synopsis: String, baseScore: String, pluginID: String,
                      version: String, checkType: String, dnsName: String, riskFactor: String,
                      temporalScore: String, exploitFrameworks: String, description: String,
                      repository: AcasRepositoryRaw, bid: String, xref: String, stigSeverity: String,
                      firstSeen: String, netbiosName: String, pluginName: String, exploitEase: String,
                      patchPubDate: String, cve: String, seeAlso: String)
