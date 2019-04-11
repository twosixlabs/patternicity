package com.punchcyber.patternicity.kafka

import java.io.{BufferedInputStream, IOException, InputStream}

import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics}
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.CompressorStreamFactory
import org.apache.orc.FileFormatException

import scala.util.control.Breaks.{break, breakable}

object RecursiveFileProducer {
    
    
    @throws[FileFormatException]
    def process(is: InputStream, filename: String): Unit = {
        val bis: BufferedInputStream = new BufferedInputStream(is)
        
        // Read in sufficient number of bytes from file to determine file type (looking for archive and compression)
        val fileBytes: Array[Byte] = new Array[Byte](512)
        bis.mark(1024)
        bis.read(fileBytes)
        bis.reset()
        
        var fileType: Option[SupportedFileType] = None
        
        breakable {
            // TODO: [performance optimization] check to see if a while loop would be faster
            for((magicBytes,name) <- magics) {
                if(comp(magicBytes,fileBytes)) {
                    fileType = Some(name)
                    break()
                }
            }
        }
        
        fileType match {
            case Some(fileT) =>
                fileT match {
                    case SupportedFileType.BRO =>
                        processBro(bis,filename)
                    
                    case compression if Array(SupportedFileType.GZIP,SupportedFileType.BZIP2).contains(compression) =>
                        process(new CompressorStreamFactory().createCompressorInputStream(bis),filename)
                    
                    case archive if Array(SupportedFileType.TAR,SupportedFileType.ZIP).contains(archive) =>
                        val ais: ArchiveInputStream =  new ArchiveStreamFactory().createArchiveInputStream(bis)
                        var entry: ArchiveEntry = ais.getNextEntry
                        
                        while(entry != null) {
                            process(ais,entry.getName)
                            
                            try {
                                entry = ais.getNextEntry
                            } catch {
                                // TODO: [error messages] need to see if there is a more specific error to look for here.
                                case _: IOException =>
                                    // TODO: [should have commented more] why am I making the entry null, again?
                                    entry = null
                            }
                        }
                }
            case None =>
                throw new FileFormatException(s"The provided file ($filename) does not contain any supported file types.")
        }
    }
    
    def processBro(inputStream: InputStream, filename: String): Unit = {
    
    }
}
