package com.punchcyber.patternicity.common.datatype.bro

import java.io._
import java.text.SimpleDateFormat
import java.time.Instant

import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics}
import com.punchcyber.patternicity.enums.bro.LogPath
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.CompressorStreamFactory

import scala.collection.mutable.ArrayBuffer
import scala.util.control.Breaks.{break, breakable}
import scala.util.matching.Regex

class BroLogHeader(fileName: String) {
    var separatorChar: Char = 0x09
    var setSeparatorChar: Char = ','
    var emptyField: String = "(empty)"
    var unsetField: String = "-"
    var logType: LogPath = LogPath.UNSUPPORTED
    var logOpenDate: Instant = _
    var logCloseDate: Instant = _
    private var tfieldNames: Array[String] = Array[String]()
    private var tfieldTypes: Array[String] = Array[String]()
    var fields: Array[(String,String)] = Array[(String,String)]()
    
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
    
    // TODO: Need to circle back to this and make sure that we can read a Bro header from an array of strings as well as directly from a file.
    def parseHeader(ia: Array[String]): Unit = {
        for(line <- ia) {
            val headerPattern(fieldName,fieldValue) = line
    
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
    }
    
    private def parseHeader(is: InputStream,originalFileName: String): Unit = {
        val bis: BufferedInputStream = new BufferedInputStream(is)
    
        val fileBytes: Array[Byte] = new Array[Byte](512)
        bis.mark(1024)
        bis.read(fileBytes)
        bis.reset()
    
        var fileType: Option[SupportedFileType] = None
    
        breakable {
            for((magicBytes,name) <- magics) {
                if(comp(magicBytes,fileBytes)) {
                    fileType = Some(name)
                    break()
                }
            }
        }
    
        fileType match {
            case Some(ft) =>
                ft match {
                    case SupportedFileType.BRO =>
                        val bufferedReader: BufferedReader = new BufferedReader(new InputStreamReader(bis))
                        
                        var line: String = bufferedReader.readLine()
                        
                        while(line != null && line.startsWith("#")) {
                            val headerPattern(fieldName,fieldValue) = line
                            
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
                            
                            line = bufferedReader.readLine()
                        }
                        bufferedReader.close()
                        
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
                
                    case compression if Array(SupportedFileType.GZIP,SupportedFileType.BZIP2).contains(compression) =>
                        parseHeader(new CompressorStreamFactory().createCompressorInputStream(bis),originalFileName)
                
                    case archive if Array(SupportedFileType.TAR,SupportedFileType.ZIP).contains(archive) =>
                        val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                        var entry: ArchiveEntry = ais.getNextEntry
                    
                        while(entry != null) {
                            parseHeader(ais,originalFileName)
                        
                            try {
                                entry = ais.getNextEntry
                            } catch {
                                case _: Throwable =>
                                    entry = null
                            }
                        }
                }
        
            case None =>
        }
    }
    
    parseHeader(new FileInputStream(fileName),fileName)
}
