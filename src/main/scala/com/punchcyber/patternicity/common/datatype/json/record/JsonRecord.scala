package com.punchcyber.patternicity.common.datatype.json.record

import java.time.{Instant, OffsetDateTime, ZoneOffset}

trait JsonRecordRaw
trait JsonRecord {
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