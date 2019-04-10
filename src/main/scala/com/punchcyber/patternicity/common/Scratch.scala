package com.punchcyber.patternicity.common

import java.io.{BufferedReader, FileInputStream, InputStreamReader}

import avro.shaded.com.google.common.collect.ImmutableList
import com.punchcyber.patternicity.common.datatype.bro.BroDataTypeConversions.broTypeToArrowType
import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.common.datatype.bro.record.BroRecord
import org.apache.arrow.vector.types.pojo.{ArrowType, Field, FieldType, Schema}

object Scratch {
    def main(args: Array[String]): Unit = {
        val dataToProc: String = "/shares/data/input/restricted/DARPA/"
        
        
        
        
        
        
        val filename: String = "/Users/mbossert/Downloads/a/5e7a57f2ad08e2753eea74ca46b7b376_20120701/conn.log"
        val broHeader: BroLogHeader = new BroLogHeader(filename)
        
        // create Arrow schema
        val arrowFields: ImmutableList.Builder[Field] = ImmutableList.builder()
        
        for(t <- broHeader.fields) {
            val tp: ArrowType = {
                if(broTypeToArrowType.contains(t._2)) {
                    broTypeToArrowType(t._2)
                }
                else {
                    new ArrowType.Utf8
                }
            }
            arrowFields.add(new Field(t._1,FieldType.nullable(tp),null))
        }
        val arrowSchema: Schema = new Schema(arrowFields.build())
        
        System.out.println(arrowSchema.toJson)
    
        import org.apache.arrow.memory.RootAllocator
        import org.apache.arrow.vector.VectorSchemaRoot
        val rootSchema = VectorSchemaRoot.create(arrowSchema, new RootAllocator(Integer.MAX_VALUE))
        
        
        
        
        
        val fis: BufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filename)))
        
        var line: String = fis.readLine()
        
        while(line != null) {
            if(!line.startsWith("#")) {
                val bro: BroRecord = new BroRecord(line,broHeader)
                
                
            }
            
            line = fis.readLine()
        }
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        /*def parseBro(is: InputStream,originalFileName: String): Unit = {
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
                            val logHeader: BroLogHeader = new BroLogHeader(originalFileName)
                            
                            val bufferedReader: BufferedReader = new BufferedReader(new InputStreamReader(bis))
                            var line: String = bufferedReader.readLine()
                            
                            while(line != null) {
                                if(!line.startsWith("#")) {
                                    System.out.println(line)
                                    val bro: BroRecord = new BroRecord(line, logHeader)
            
                                    for(col <- bro.broFields) {
                
                                        col._2 match {
                                            case None =>
                                                System.out.println(f"${col._1}%-15s ::: NULLY NULLY NULL")
                                            case Some(stuff) =>
                                                if(stuff.isInstanceOf[Array[_ <: Any]]) {
                                                    System.out.println(f"${col._1}%-15s ::: ${stuff.asInstanceOf[Array[_]].mkString("|:|")}")
                                                }
                                                else {
                                                    System.out.println(f"${col._1}%-15s ::: ${stuff}")
                                                }
                                        }
                                    }
                                }
                                line = bufferedReader.readLine()
                                System.out.println()
                            }
                    
                        case compression if Array(SupportedFileType.GZIP,SupportedFileType.BZIP2).contains(compression) =>
                            parseBro(new CompressorStreamFactory().createCompressorInputStream(bis),originalFileName)
                    
                        case archive if Array(SupportedFileType.TAR,SupportedFileType.ZIP).contains(archive) =>
                            val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                            var entry: ArchiveEntry = ais.getNextEntry
                        
                            while(entry != null) {
                                
                                parseBro(ais,originalFileName)
                            
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
        
        val filenames: Array[String] = Array[String]("conn.log", "dhcp.log", "dns.log", "files.log", "http.log", /*"http.log.gz",*/ "loaded_scripts.log","packet_filter.log","weird.log"/*,"stuff.tar.gz"*/)
        
        for(filename <- filenames) {
            val fn: String = "/Users/mbossert/Downloads/a/5e5d3cc6004b69100d26314ce64544a1_20121027/" + filename
            val fis: FileInputStream = new FileInputStream(fn)
            
            parseBro(fis,fn)
            
        }*/
    }
}
