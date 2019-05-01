package com.punchcyber.patternicity.common.datatype.json.record

import java.time.{Instant, OffsetDateTime, ZoneOffset}

import org.apache.hadoop.hbase.client.Put

trait JsonRecordRaw
trait JsonRecord {
  def getHbasePut: Put

}

trait JsonHelperRecord {

  def convertBlankableDouble(raw: String): Option[Double] = {
    raw match {
      case "" => None
      case _ => Some(raw.toDouble)
    }
  }
  def stringToInstant(raw: String): Instant = {
    OffsetDateTime.parse(raw).withOffsetSameInstant(ZoneOffset.UTC).toInstant
  }
}