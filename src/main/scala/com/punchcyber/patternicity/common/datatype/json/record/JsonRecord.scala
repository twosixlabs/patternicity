package com.punchcyber.patternicity.common.datatype.json.record

trait JsonRecordRaw
trait JsonRecord {
  def convertBlankableDouble(raw: String): Option[Double] = {
    raw match {
      case "" => None
      case _ => Some(raw.toDouble)
    }
  }
}