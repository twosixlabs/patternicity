package com.punchcyber.patternicity.common.datatype.acas.record

import java.nio.ByteBuffer
import java.time.Instant
import java.util.UUID

import com.punchcyber.patternicity.common.datatype.json.record._
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes

case class AcasFamily(`type`: String, id: Long, name: String)
case class AcasSeverity(description: String, id: Long, name: String)
case class AcasRepository(description: String, id: Long, name: String)

case class AcasRecord(macAddress: String, protocol: String, vulnPubDate: Option[Long], family: AcasFamily, ip: String,
                      exploitAvailable: Boolean, cpe: String, recastRisk: Double, cvssVector: String, lastSeen: Long,
                      pluginText: String, port: Option[Int], pluginPubDate: Long, acceptRisk: Double, hasBeenMitigated: Boolean,
                      severity: AcasSeverity, synopsis: String, baseScore: Option[Double], pluginId: Long,
                      version: String, checkType: String, dnsName: String, riskFactor: String,
                      temporalScore: Option[Double], exploitFrameworks: String, description: String,
                      repository: AcasRepository, bid: String, xref: String, stigSeverity: Option[Double],
                      firstSeen: Long, netbiosName: String, pluginName: String, exploitEase: Option[Double],
                      patchPubDate: Option[Long], cve: String, seeAlso: String) extends JsonRecord {

  val rowKey: String = UUID.randomUUID().toString

  def getHbasePut: Put = {
    val put: Put = new Put(Bytes.toBytes(rowKey),Instant.now().toEpochMilli)

    print(bid)

    put.addColumn(
      Bytes.toBytes("B"),
      "patchPubDate".getBytes,
      ByteBuffer.allocate(4).putInt(1234).array)

    put
  }
}

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
                      patchPubDate: String, cve: String, seeAlso: String) extends JsonRecordRaw

object AcasFamily {
  def apply(raw: AcasFamilyRaw): AcasFamily = {
    new AcasFamily(
      `type` = raw.`type`,
      id = raw.id.toLong,
      name = raw.name
    )
  }
}

object AcasSeverity {
  def apply(raw: AcasSeverityRaw): AcasSeverity = {
    new AcasSeverity(
      description = raw.description,
      id = raw.id.toInt,
      name = raw.name)
  }
}

object AcasRepository {
  def apply(raw: AcasRepositoryRaw): AcasRepository = {
    new AcasRepository(
      description = raw.description,
      id = raw.id.toLong,
      name = raw.name
    )
  }
}

object AcasRecord extends JsonHelperRecord  {
  def convertPubDate(raw: String): Option[Long] = {
    raw match {
      case "-1" => None
      case _ => Some(raw.toLong)
    }
  }

  def convertPort(raw: String): Option[Int] = {
    raw match {
      case "0" => None
      case _ => Some(raw.toInt)
    }
  }

  def apply(raw: AcasRecordRaw): AcasRecord = {
    AcasRecord(
      macAddress=raw.macAddress,
      protocol = raw.protocol,
      vulnPubDate = convertPubDate(raw.vulnPubDate),
      family = AcasFamily(raw.family),
      ip = raw.ip,
      exploitAvailable = raw.exploitAvailable == "Yes",
      cpe = raw.cpe,
      recastRisk = raw.recastRisk.toDouble,
      cvssVector = raw.cvssVector,
      lastSeen = raw.lastSeen.toLong,
      pluginText = raw.pluginText,
      port = convertPort(raw.port),
      pluginPubDate = raw.pluginPubDate.toLong,
      acceptRisk = raw.acceptRisk.toDouble,
      hasBeenMitigated = raw.hasBeenMitigated == "1",
      severity = AcasSeverity(raw.severity),
      synopsis = raw.synopsis,
      baseScore = convertBlankableDouble(raw.baseScore),
      pluginId = raw.pluginID.toLong,
      version = raw.version,
      checkType = raw.checkType,
      dnsName = raw.dnsName,
      riskFactor = raw.riskFactor,
      temporalScore = convertBlankableDouble(raw.temporalScore),
      exploitFrameworks = raw.exploitFrameworks,
      description = raw.description,
      repository = AcasRepository(raw.repository),
      bid = raw.bid,
      xref = raw.xref,
      stigSeverity = convertBlankableDouble(raw.stigSeverity),
      firstSeen = raw.firstSeen.toLong,
      netbiosName = raw.netbiosName,
      pluginName = raw.pluginName,
      exploitEase = convertBlankableDouble(raw.exploitEase),
      patchPubDate = convertPubDate(raw.patchPubDate),
      cve = raw.cve,
      seeAlso = raw.seeAlso
    )
  }


}