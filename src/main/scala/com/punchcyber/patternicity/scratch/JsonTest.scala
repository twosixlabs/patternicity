package com.punchcyber.patternicity.scratch

import java.io._
import java.nio.file.{Files, Paths}
import java.time.{Duration, Instant}
import java.util.concurrent.{ArrayBlockingQueue, ConcurrentLinkedQueue}

import com.punchcyber.patternicity.common.datatype.hbss.record.{HbssHipsEventRecord, HbssHipsEventRecordRaw, HbssThreatEventAccessProtectionRecord, HbssThreatEventAccessProtectionRecordRaw, HbssThreatEventRecord, HbssThreatEventRecordRaw}
import com.punchcyber.patternicity.common.datatype.acas.record.{AcasRecord, AcasRecordRaw}
import com.punchcyber.patternicity.common.datatype.json.record.JsonRecord
import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics, recursiveFindFileType}
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveException, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.{CompressorException, CompressorStreamFactory}
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.hbase.client._
import org.apache.hadoop.hbase.{HBaseConfiguration, TableName}
import org.slf4j.LoggerFactory

import scala.io.Source
import io.circe.generic.auto._
import io.circe.parser._

import scala.util.control.Breaks.{break, breakable}

object JsonTest {
    
    val fileQueue: ConcurrentLinkedQueue[String] = new ConcurrentLinkedQueue[String]()
    val jsonLogQueue: ArrayBlockingQueue[JsonRecord] = new ArrayBlockingQueue[JsonRecord](100000)
    
    def main(args: Array[String]): Unit = {
        
        val findFiles: Thread = new Thread(new FindFiles)
        val jsonRecordFileProducer: Thread = new Thread(new JsonRecordParse)
        val hbaseWriter: Thread = new Thread(new Writer)
        
        findFiles.start()
        jsonRecordFileProducer.start()
        hbaseWriter.start()
     }
    
    class FindFiles extends Runnable {
        override def run(): Unit = {
//            val watchedDirectory: String = "/shares/data/input/restricted/DARPA"
            val watchedDirectory: String = "/home/nathan-sanford/code/CHASE/patternicity/src/resources/json"
            System.out.println(s"About to start reading from $watchedDirectory")

            Files.walk(Paths.get(watchedDirectory))
                    .filter(f => Files.isRegularFile(f) && Files.isReadable(f))
                    .sorted((a,b) => Files.getLastModifiedTime(a).compareTo(Files.getLastModifiedTime(b)))
                    .forEach {
                        path => {
                            // First grab all of the JSON files
                            val filename: String = path.toAbsolutePath.toString
                            val is: FileInputStream = new FileInputStream(filename)
                            val found: Option[Boolean] = recursiveFindFileType(SupportedFileType.JSON, is)
                            is.close()
                            found match {
                                case Some(true) =>
                                    // Check that the first line of json matches that of an AcasRecord
                                    val src = Source.fromFile(filename)
                                    val firstRecordString = src.getLines.find(_ => true)
                                    src.close()
                                    breakable {
                                        decode[AcasRecordRaw](firstRecordString.get) match {
                                            case Left(failure) =>
                                            case Right(json) => fileQueue.offer(filename); break
                                        }
                                        decode[HbssThreatEventAccessProtectionRecordRaw](firstRecordString.get) match {
                                            case Left(failure) => println(failure)
                                            case Right(json) => fileQueue.offer(filename); break
                                        }
                                        decode[HbssThreatEventRecordRaw](firstRecordString.get) match {
                                            case Left(failure) => println(failure)
                                            case Right(json) => fileQueue.offer(filename); break
                                        }
                                        decode[HbssHipsEventRecordRaw](firstRecordString.get) match {
                                            case Left(failure) => println(failure)
                                            case Right(json) => fileQueue.offer(filename); break
                                        }
                                    }

                                case Some(false) =>
                                case None =>
                            }
                        }
                    }
            System.out.println(s"Loaded ${fileQueue.size()} files from Watched Directory")
        }
    }
    
    class JsonRecordParse extends Runnable {
        def pushJsonRecordToQueue(line: String, queue: ArrayBlockingQueue[JsonRecord]): Unit = {
            var matchFound = false
            breakable {
                decode[AcasRecordRaw](line) match {
                    case Left(failure) =>
                    case Right(record) => {
                        jsonLogQueue.offer(AcasRecord(record))
                        matchFound = true
                        break
                    }
                }
                decode[HbssThreatEventAccessProtectionRecordRaw](line) match {
                    case Left(failure) =>
                    case Right(record) => {
                        jsonLogQueue.offer(HbssThreatEventAccessProtectionRecord(record))
                        matchFound = true
                        break
                    }
                }
                decode[HbssThreatEventRecordRaw](line) match {
                    case Left(failure) =>
                    case Right(record) => {
                        jsonLogQueue.offer(HbssThreatEventRecord(record))
                        matchFound = true
                        break
                    }
                }
                decode[HbssHipsEventRecordRaw](line) match {
                    case Left(failure) =>
                    case Right(record) => {
                        jsonLogQueue.offer(HbssHipsEventRecord(record))
                        matchFound = true
                        break
                    }
                }
            }
            if (!matchFound) println(s"Couldn't find a JsonRecord type match for line: $line")
        }
        def findFileType(bis: BufferedInputStream): Option[SupportedFileType] = {
            val fileBytes: Array[Byte] = new Array[Byte](512)
            bis.mark(1024)
            bis.read(fileBytes)
            bis.reset()

            var ft: Option[SupportedFileType] = None
            for((magicBytes,name) <- magics) {
                if(comp(magicBytes,fileBytes)) {
                    ft = Some(name)
                }
            }
            ft
        }
        def process(is: InputStream, filetype: Option[SupportedFileType] = None): Unit = {
            val bis: BufferedInputStream = new BufferedInputStream(is)
            var ft: Option[SupportedFileType] = filetype
        
            try { CompressorStreamFactory.detect(bis); ft = Some(SupportedFileType.COMPRESSED) }
            catch { case _: CompressorException => }
            try { ArchiveStreamFactory.detect(bis); ft = Some(SupportedFileType.ARCHIVED) }
            catch { case _: ArchiveException => }
        
            if(!Array(Some(SupportedFileType.COMPRESSED),Some(SupportedFileType.ARCHIVED)).contains(ft)) {
                ft = findFileType(bis)
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
            
                case Some(SupportedFileType.JSON) =>
                    val br: BufferedReader = new BufferedReader(new InputStreamReader(bis))
                    var line: String = br.readLine()
                    
                    while(line != null) {
                        
                        if(jsonLogQueue.remainingCapacity() > 1000) {
                            try {
                                pushJsonRecordToQueue(line, jsonLogQueue)
                            } catch {
                                case e: Exception => System.err.println(e)
                            }
                            
                        }
                        else {
                            Thread.sleep(100)
                            var backoff: Int = 100
                            var tries: Int = 0
                            
                            while(jsonLogQueue.remainingCapacity() <= 1000 && tries < 35) {
                                Thread.sleep(backoff)
                                backoff *= 2
                                tries += 1
                            }
                        }
                    
                        try { line = br.readLine() }
                        catch { case _: IOException => line = null }
                    }
            }
        }
        
        override def run(): Unit = {
            var hack: Instant = Instant.now()
            while(fileQueue.isEmpty && (Duration.between(hack,Instant.now()).toMinutes < 15)) {
                Thread.sleep(10000)
                hack = Instant.now()
            }
            
            val fileQueueIter: java.util.Iterator[String] = fileQueue.iterator()
            while(fileQueueIter.hasNext) {
                val fn: String = fileQueue.poll()

                if (fn != null) {
                    System.out.println(s"Processing file: $fn")
                    val fis: FileInputStream = new FileInputStream(fn)
                    process(fis)
                }
            }
        }
    }
    
    class Writer extends Runnable {
        val hbaseConf: Configuration = HBaseConfiguration.create()
        // Cluster configs
//        hbaseConf.set("hbase.zookeeper.property.clientPort", "2181")
//        hbaseConf.set("hbase.zookeeper.quorum", "master-1.punch.datareservoir.net,master-2.punch.datareservoir.net,master-3.punch.datareservoir.net,master-4.punch.datareservoir.net,master-5.punch.datareservoir.net")
//        hbaseConf.set("zookeeper.znode.parent", "/hbase")

        // local configs
        hbaseConf.set("hbase.zookeeper.property.clientPort", "2181")
        hbaseConf.set("hbase.zookeeper.quorum", "localhost")
        
        private val LOG = LoggerFactory.getLogger(classOf[Nothing])
        
        override def run(): Unit = {
            try {
                var hack: Instant = Instant.now()

                do {
                    val record = jsonLogQueue.take()
                    try {
                        // This is where the record should be added to the database, not just printed out.
                        println(record)
                    }
                    hack = Instant.now()
                } while(jsonLogQueue.size() >= 0 && (Duration.between(hack, Instant.now()).toMinutes < 15))

            } catch {
                case e: IOException =>
                    LOG.info("exception while creating/destroying Connection or BufferedMutator", e)
            }
        }
    }
}