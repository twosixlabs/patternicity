package com.punchcyber.patternicity.common.datatype.hbss.record

import java.time.Instant

import com.punchcyber.patternicity.common.datatype.json.record._

//Grand scheme here is to match the raw data source as closely as possible with the "Raw" record type, then do more
//specific conversions with the non "Raw" record type. Ideally this more strongly typed non-raw record type will give
//more control over how the data gets imported into the various data-stores. Things to add could be using enums instead
// of strings, use IPV6 and IPV4 types, MAC Address types, etc. The type complexity has to go somewhere, maybe it would
// be good to have the db schemas be built off of these case classes?

case class HbssThreatEventAccessProtectionRecordRaw(`EPOEvents.TargetPort`: Option[Int], `EPOEvents.TargetFileName`: String, `EPOEvents.ThreatName`: String,
                                                    `EPOEvents.ThreatHandled`: Boolean, `EPOEvents.ThreatType`: String, `EPOEvents.AnalyzerHostName`: String,
                                                    `EPOEvents.TargetProtocol`: Option[String], `EPOLeafNode.NodeName`: String, `EPOEvents.SourceURL`: Option[String],
                                                    `EPOEvents.SourceIPV4`: String, `EPOEvents.TargetMAC`: Option[String], `EPOEvents.ReceivedUTC`: String,
                                                    `EPOEvents.ThreatCategory`: String, `EPOEvents.TargetUserName`: String, `EPOEvents.SourceHostName`: String,
                                                    `EPOEvents.TargetIPV4`: String, `EPOEvents.AnalyzerEngineVersion`: Option[String], `EPOEvents.AnalyzerIPV4`: String,
                                                    `EPOEvents.Analyzer`: String, `EPOEvents.AnalyzerIPV6`: String, `EPOEvents.AnalyzerDetectionMethod`: String,
                                                    `EPOEvents.AnalyzerVersion`: String, `EPOEvents.AnalyzerName`: String, `EPOEvents.TargetProcessName`: Option[String],
                                                    `EPOEvents.ServerID`: String, `EPOBranchNode.NodeTextPath`: String, `EPOEvents.AgentGUID`: String,
                                                    `EPOEvents.AnalyzerMAC`: Option[String], `EPOEvents.SourceMAC`: Option[String], `EPOEvents.ThreatEventID`: Int,
                                                    `EPOEvents.TargetHostName`: String, `EPOEvents.TargetIPV6`: String, `EPOEvents.ThreatSeverity`: Int,
                                                    `EPOEvents.AnalyzerDATVersion`: Option[String], `EPOEvents.SourceUserName`: Option[String], `EPOEvents.SourceIPV6`: String,
                                                    `EPOEvents.SourceProcessName`: String, `VSECustomEvent.MD5`: Option[String], `EPOEvents.ThreatActionTaken`: String,
                                                    `EPOEvents.DetectedUTC`: String
                                                   ) extends JsonRecordRaw


case class HbssThreatEventAccessProtectionRecord(EPOEvents_TargetPort: Option[Int], EPOEvents_TargetFileName: String, EPOEvents_ThreatName: String,
                                                 EPOEvents_ThreatHandled: Boolean, EPOEvents_ThreatType: String, EPOEvents_AnalyzerHostName: String,
                                                 EPOEvents_TargetProtocol: Option[String], EPOLeafNode_NodeName: String, EPOEvents_SourceURL: Option[String],
                                                 EPOEvents_SourceIPV4: String, EPOEvents_TargetMAC: Option[String], EPOEvents_ReceivedUTC: Instant,
                                                 EPOEvents_ThreatCategory: String, EPOEvents_TargetUserName: String, EPOEvents_SourceHostName: String,
                                                 EPOEvents_TargetIPV4: String, EPOEvents_AnalyzerEngineVersion: Option[String], EPOEvents_AnalyzerIPV4: String,
                                                 EPOEvents_Analyzer: String, EPOEvents_AnalyzerIPV6: String, EPOEvents_AnalyzerDetectionMethod: String,
                                                 EPOEvents_AnalyzerVersion: String, EPOEvents_AnalyzerName: String, EPOEvents_TargetProcessName: Option[String],
                                                 EPOEvents_ServerID: String, EPOBranchNode_NodeTextPath: String, EPOEvents_AgentGUID: String,
                                                 EPOEvents_AnalyzerMAC: Option[String], EPOEvents_SourceMAC: Option[String], EPOEvents_ThreatEventID: Int,
                                                 EPOEvents_TargetHostName: String, EPOEvents_TargetIPV6: String, EPOEvents_ThreatSeverity: Int,
                                                 EPOEvents_AnalyzerDATVersion: Option[String], EPOEvents_SourceUserName: Option[String], EPOEvents_SourceIPV6: String,
                                                 EPOEvents_SourceProcessName: String, VSECustomEvent_MD5: Option[String], EPOEvents_ThreatActionTaken: String,
                                                 EPOEvents_DetectedUTC: Instant
                                                ) extends JsonRecord


object HbssThreatEventAccessProtectionRecord extends JsonRecord {
  def apply(raw: HbssThreatEventAccessProtectionRecordRaw): HbssThreatEventAccessProtectionRecord = {
    // Pretty verbose for not a lot of value add - might be more useful in the future if we use more stringent types
    // or do other data cleansing.
    HbssThreatEventAccessProtectionRecord(
      EPOEvents_TargetPort = raw.`EPOEvents.TargetPort`,
      EPOEvents_TargetFileName = raw.`EPOEvents.TargetFileName`,
      EPOEvents_ThreatName = raw.`EPOEvents.ThreatName`,
      EPOEvents_ThreatHandled = raw.`EPOEvents.ThreatHandled`,
      EPOEvents_ThreatType = raw.`EPOEvents.ThreatType`,
      EPOEvents_AnalyzerHostName = raw.`EPOEvents.AnalyzerHostName`,
      EPOEvents_TargetProtocol = raw.`EPOEvents.TargetProtocol`,
      EPOLeafNode_NodeName = raw.`EPOLeafNode.NodeName`,
      EPOEvents_SourceURL = raw.`EPOEvents.SourceURL`,
      EPOEvents_SourceIPV4 = raw.`EPOEvents.SourceIPV4`,
      EPOEvents_TargetMAC = raw.`EPOEvents.TargetMAC`,
      EPOEvents_ReceivedUTC = stringToInstant(raw.`EPOEvents.ReceivedUTC`),
      EPOEvents_ThreatCategory = raw.`EPOEvents.ThreatCategory`,
      EPOEvents_TargetUserName = raw.`EPOEvents.TargetUserName`,
      EPOEvents_SourceHostName = raw.`EPOEvents.SourceHostName`,
      EPOEvents_TargetIPV4 = raw.`EPOEvents.TargetIPV4`,
      EPOEvents_AnalyzerEngineVersion = raw.`EPOEvents.AnalyzerEngineVersion`,
      EPOEvents_AnalyzerIPV4 = raw.`EPOEvents.AnalyzerIPV4`,
      EPOEvents_Analyzer = raw.`EPOEvents.Analyzer`,
      EPOEvents_AnalyzerIPV6 = raw.`EPOEvents.AnalyzerIPV6`,
      EPOEvents_AnalyzerDetectionMethod = raw.`EPOEvents.AnalyzerDetectionMethod`,
      EPOEvents_AnalyzerVersion = raw.`EPOEvents.AnalyzerVersion`,
      EPOEvents_AnalyzerName = raw.`EPOEvents.AnalyzerName`,
      EPOEvents_TargetProcessName = raw.`EPOEvents.TargetProcessName`,
      EPOEvents_ServerID = raw.`EPOEvents.ServerID`,
      EPOBranchNode_NodeTextPath = raw.`EPOBranchNode.NodeTextPath`,
      EPOEvents_AgentGUID = raw.`EPOEvents.AgentGUID`,
      EPOEvents_AnalyzerMAC = raw.`EPOEvents.AnalyzerMAC`,
      EPOEvents_SourceMAC = raw.`EPOEvents.SourceMAC`,
      EPOEvents_ThreatEventID = raw.`EPOEvents.ThreatEventID`,
      EPOEvents_TargetHostName = raw.`EPOEvents.TargetHostName`,
      EPOEvents_TargetIPV6 = raw.`EPOEvents.TargetIPV6`,
      EPOEvents_ThreatSeverity = raw.`EPOEvents.ThreatSeverity`,
      EPOEvents_AnalyzerDATVersion = raw.`EPOEvents.AnalyzerDATVersion`,
      EPOEvents_SourceUserName = raw.`EPOEvents.SourceUserName`,
      EPOEvents_SourceIPV6 = raw.`EPOEvents.SourceIPV6`,
      EPOEvents_SourceProcessName = raw.`EPOEvents.SourceProcessName`,
      VSECustomEvent_MD5 = raw.`VSECustomEvent.MD5`,
      EPOEvents_ThreatActionTaken = raw.`EPOEvents.ThreatActionTaken`,
      EPOEvents_DetectedUTC = stringToInstant(raw.`EPOEvents.DetectedUTC`)
    )
  }
}