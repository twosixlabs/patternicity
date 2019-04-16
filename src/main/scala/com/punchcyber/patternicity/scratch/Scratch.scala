package com.punchcyber.patternicity.scratch

import java.io._

import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.common.datatype.bro.record.BroRecord
import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics}
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveException, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.{CompressorException, CompressorStreamFactory}
import org.apache.hadoop.hbase.client.Put

object Scratch {
    def main(args: Array[String]): Unit = {
        def process(is: InputStream, filetype: Option[SupportedFileType] = None): Unit = {
            val bis: BufferedInputStream = new BufferedInputStream(is)
            var ft: Option[SupportedFileType] = filetype
    
            try { CompressorStreamFactory.detect(bis); ft = Some(SupportedFileType.COMPRESSED) }
            catch { case _: CompressorException => }
            try { ArchiveStreamFactory.detect(bis); ft = Some(SupportedFileType.ARCHIVED) }
            catch { case _: ArchiveException => }
    
            if(!Array(Some(SupportedFileType.COMPRESSED),Some(SupportedFileType.ARCHIVED)).contains(ft)) {
                val fileBytes: Array[Byte] = new Array[Byte](512)
                bis.mark(1024)
                bis.read(fileBytes)
                bis.reset()
        
                for((magicBytes,name) <- magics) {
                    if(comp(magicBytes,fileBytes)) {
                        ft = Some(name)
                    }
                }
            }
    
            ft match {
                case None =>

                case Some(SupportedFileType.UNSUPPORTED) =>
                    System.out.println("Houston, we have a problem")

                case Some(SupportedFileType.COMPRESSED) =>
                    process(new CompressorStreamFactory().createCompressorInputStream(bis))

                case Some(SupportedFileType.ARCHIVED) =>
                    val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                    var entry: ArchiveEntry = ais.getNextEntry
    
                    while(entry != null) {
                        process(ais)
        
                        try {
                            entry = ais.getNextEntry
                        } catch {
                            case _: Throwable =>
                                entry = null
                        }
                    }

                case Some(SupportedFileType.BRO) =>
                    val br: BufferedReader = new BufferedReader(new InputStreamReader(bis))
    
                    val broHeader: BroLogHeader = new BroLogHeader
                    broHeader.parseHeader(br)
                    System.out.println(broHeader.toString)
    
                    var line: String = br.readLine()
                    while(line != null && !line.startsWith("#")) {
                        val record = BroRecord.apply(line,broHeader)
                        
                        
                        //System.out.println(record.broFieldMap.mkString("\n"))
                        val p: Put = record.getHbasePut
                        System.out.println(p.toString)
                        try { line = br.readLine() }
                        catch { case _: IOException => line = null }
                    }
            }
        }
        
        val filename: String = "src/resources/bro/files.2018-12-01.00%3A05%3A00-00%3A10%3A00.log.gz"
        val is: InputStream = new FileInputStream(filename)
        process(is)
        
        
        /*val dataToProc: String = "/shares/data/input/restricted/DARPA/"
        val filename: String = "/Users/mbossert/Downloads/a/5e7a57f2ad08e2753eea74ca46b7b376_20120701/conn.log"
        val broHeader: BroLogHeader = new BroLogHeader()
        
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
                val bro: GenericBroRecord = new GenericBroRecord(line,broHeader)
                
                
            }
            
            line = fis.readLine()
        }*/
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
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
