package com.punchcyber.patternicity.scratch

import java.io._

import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.common.datatype.bro.record.BroRecord
import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics}
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveException, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.{CompressorException, CompressorStreamFactory}

object BroTest {
    def main(args: Array[String]): Unit = {
        
        val file: BufferedInputStream = new BufferedInputStream(new FileInputStream("src/resources/bro/files.log"))
        
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
                    System.out.println("GOT BRO")
                    val br: BufferedReader = new BufferedReader(new InputStreamReader(bis))
                    val broHeader: BroLogHeader = new BroLogHeader
                    broHeader.parseHeader(br)
                    
                    var line: String = br.readLine()
                    
                    while(line != null && !line.startsWith("#")) {
                        System.out.println(line)
                        
                        val brolog: BroRecord = new BroRecord(line,broHeader)
                        System.out.println(brolog.broFields.deep.mkString("||"))
                        
                        try { line = br.readLine() }
                        catch { case _: IOException => line = null }
                    }
            }
        }
        
        process(file)
    }
}
