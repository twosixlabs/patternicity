package com.punchcyber.patternicity.common.datatype.bro

import java.io._
import java.text.SimpleDateFormat
import java.time.Instant

import com.punchcyber.patternicity.enums.bro.LogPath

import scala.collection.mutable.ArrayBuffer
import scala.util.matching.Regex

class BroLogHeader {
    var fileName           : String = ""
    var separatorChar      : Char = 0x09
    var setSeparatorChar   : Char = ','
    var emptyField         : String = "(empty)"
    var unsetField         : String = "-"
    var logType            : LogPath = LogPath.UNSUPPORTED
    var logOpenDate        : Instant = _
    var logCloseDate       : Instant = _
    private var tfieldNames: Array[String] = Array[String]()
    private var tfieldTypes: Array[String] = Array[String]()
    var fields             : Array[(String,String)] = Array[(String,String)]()
    
    private val headerPattern: Regex = """^#(\w++)\s+(.+)$""".r
    
    override def toString: String = {
        s"""
          |File Name    : $fileName
          |Log Type     : $logType
          |Separator    : $separatorChar
          |Set Separator: $setSeparatorChar
          |Empty Field  : $emptyField
          |Unset Field  : $unsetField
          |File Open    : ${logOpenDate.toString}
          |Fields       :
          |
          |${fields.deep.mkString("\n")}
        """.stripMargin
    }
    
    def parseHeader(br: BufferedReader): BroLogHeader = {
        val header: ArrayBuffer[String] = ArrayBuffer[String]()
        
        for(_: Int <- 0 to 7) {
            val line: String = br.readLine()
            
            if(line.startsWith("#")) header += line
        }
    
        if(header.size == 8) {
            for(hl: String <- header) {
                val headerPattern(fieldName,fieldValue) = hl
    
                fieldName match {
                    case "separator" =>
                        separatorChar = fieldValue.replaceAll("""^\\x""","").toInt.toChar
        
                    case "set_separator" =>
                        setSeparatorChar = fieldValue.head
        
                    case "empty_field" =>
                        emptyField = fieldValue
        
                    case "unset_field" =>
                        unsetField = fieldValue
        
                    case "path" =>
                        logType = LogPath.valueOf(fieldValue.toUpperCase)
        
                    case "open" =>
                        // 2018-12-31-20-10-00 and presumably need to add an implied timezone (UTC)
                        logOpenDate = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ssz").parse(fieldValue + "UTC").toInstant
        
                    case "fields" =>
                        tfieldNames = fieldValue.split(separatorChar)
        
                    case "types" =>
                        tfieldTypes = fieldValue.split(separatorChar)
        
                }
            }
    
            // Finally, need to turn our fieldName and fieldType arrays into an array of tuples
            fields = {
                var temp: ArrayBuffer[(String,String)] = ArrayBuffer[(String,String)]()
                var c: Int = 0
        
                while(c < tfieldNames.length) {
                    temp += ((tfieldNames(c),tfieldTypes(c)))
                    c += 1
                }
                temp.toArray
            }
            
            this
        }
        else {
            throw new IOException("File does not have the expected Bro log header")
        }
    }
}
