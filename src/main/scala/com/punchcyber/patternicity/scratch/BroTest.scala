package com.punchcyber.patternicity.scratch

import java.io._
import java.nio.file.{Files, Paths}
import java.time.{Duration, Instant}
import java.util.concurrent.{ArrayBlockingQueue, ConcurrentLinkedQueue}

import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.common.datatype.bro.record.BroRecord
import com.punchcyber.patternicity.common.utilities.FileMagic.{comp, magics, recursiveFindFileType}
import com.punchcyber.patternicity.enums.bro.LogPath
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.archivers.{ArchiveEntry, ArchiveException, ArchiveInputStream, ArchiveStreamFactory}
import org.apache.commons.compress.compressors.{CompressorException, CompressorStreamFactory}
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.hbase.client._
import org.apache.hadoop.hbase.{HBaseConfiguration, TableName}
import org.slf4j.LoggerFactory

object BroTest {
    
    val fileQueue: ConcurrentLinkedQueue[String] = new ConcurrentLinkedQueue[String]()
    val broLogQueue: ArrayBlockingQueue[BroRecord] = new ArrayBlockingQueue[BroRecord](100000)
    
    def main(args: Array[String]): Unit = {
        
        val findFiles: Thread = new Thread(new FindFiles)
        val broFileProducer: Thread = new Thread(new BroParse)
        val hbaseWriter: Thread = new Thread(new HbaseWriter)
        
        findFiles.start()
        broFileProducer.start()
        hbaseWriter.start()
     }
    
    class FindFiles extends Runnable {
        override def run(): Unit = {
            val watchedDirectory: String = "/shares/data/input/restricted/DARPA"
            System.out.println(s"About to start reading from $watchedDirectory")
            
            Files.walk(Paths.get(watchedDirectory))
                    .filter(f => Files.isRegularFile(f) && Files.isReadable(f))
                    .sorted((a,b) => Files.getLastModifiedTime(a).compareTo(Files.getLastModifiedTime(b)))
                    .forEach {
                        path => {
                            // Right now, we only care about Bro
                            val filename: String = path.toAbsolutePath.toString
                            val is: FileInputStream = new FileInputStream(filename)
                            val found: Option[Boolean] = recursiveFindFileType(SupportedFileType.BRO,is)
                            found match {
                                case Some(true) =>
                                    if(!filename.contains("sensor-health")) {
                                        fileQueue.offer(filename)
                                    }
                                    
                                case Some(false) =>
                                case None =>
                            }
                            is.close()
                        }
                    }
            System.out.println(s"Loaded ${fileQueue.size()} files from Watched Directory")
        }
    }
    
    class BroParse extends Runnable {
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
                    
                    var line: String = br.readLine()
                    
                    while(line != null && !line.startsWith("#")) {
                        
                        if(broLogQueue.remainingCapacity() > 1000) {
                            try {
                                val record: BroRecord = BroRecord(line,broHeader)
                                broLogQueue.offer(record)
                            } catch {
                                case e: Exception => System.err.println(e)
                            }
                            
                        }
                        else {
                            Thread.sleep(100)
                            var backoff: Int = 100
                            var tries: Int = 0
                            
                            while(broLogQueue.remainingCapacity() <= 1000 && tries < 35) {
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
                
                System.out.println(s"Processing file: $fn")
                val fis: FileInputStream = new FileInputStream(fn)
                process(fis)
            }
        }
    }
    
    class HbaseWriter extends Runnable {
        val hbaseConf: Configuration = HBaseConfiguration.create()
        hbaseConf.set("hbase.zookeeper.property.clientPort", "2181")
        hbaseConf.set("hbase.zookeeper.quorum", "master-1.punch.datareservoir.net,master-2.punch.datareservoir.net,master-3.punch.datareservoir.net,master-4.punch.datareservoir.net,master-5.punch.datareservoir.net")
        hbaseConf.set("zookeeper.znode.parent", "/hbase")
        
        private val LOG = LoggerFactory.getLogger(classOf[Nothing])
    
        private val POOL_SIZE = 10
        private val TABLE = TableName.valueOf("HACKSAW:BRO")
        
        override def run(): Unit = {
            val listener: BufferedMutator.ExceptionListener = (e: RetriesExhaustedWithDetailsException, _: BufferedMutator) => {
                var i = 0
                while ( {
                    i < e.getNumExceptions
                }) {
                    LOG.info("Failed to sent put " + e.getRow(i) + ".")
            
                    {
                        i += 1
                        i - 1
                    }
                }
            }
            
            try {
                val hbaseConnection: Connection = ConnectionFactory.createConnection(hbaseConf)
                
                val tableMutators: Map[LogPath,BufferedMutator] = Map[LogPath,BufferedMutator](
                    LogPath.CONN        -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_CONN")).listener(listener)),
                    LogPath.DNS         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_DNS")).listener(listener)),
                    LogPath.FILES       -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_FILES")).listener(listener)),
                    LogPath.FTP         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_FTP")).listener(listener)),
                    LogPath.HTTP        -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_HTTP")).listener(listener)),
                    LogPath.KERBEROS    -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_KERBEROS")).listener(listener)),
                    LogPath.MYSQL       -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_MYSQL")).listener(listener)),
                    LogPath.NOTICE      -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_NOTICE")).listener(listener)),
                    LogPath.PE          -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_PE")).listener(listener)),
                    LogPath.RADIUS      -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_RADIUS")).listener(listener)),
                    LogPath.RDP         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_RDP")).listener(listener)),
                    LogPath.SIP         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SIP")).listener(listener)),
                    LogPath.SMB_CMD     -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SMB_CMD")).listener(listener)),
                    LogPath.SMB_MAPPING -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SMB_MAPPING")).listener(listener)),
                    LogPath.SMTP        -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SMTP")).listener(listener)),
                    LogPath.SNMP        -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SNMP")).listener(listener)),
                    LogPath.SSH         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SSH")).listener(listener)),
                    LogPath.SSL         -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SSL")).listener(listener)),
                    LogPath.SYSLOG      -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_SYSLOG")).listener(listener)),
                    LogPath.TUNNEL      -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_TUNNEL")).listener(listener)),
                    LogPath.X509        -> hbaseConnection.getBufferedMutator(new BufferedMutatorParams(TableName.valueOf("HACKSAW:BRO_X509")).listener(listener))
                )

                var hack: Instant = Instant.now()

                do {
                    val record = broLogQueue.take()
                    try {
                        tableMutators(record.getLogPath).mutate(record.getHbasePut)
                    }
                    hack = Instant.now()
                } while(broLogQueue.size() >= 0 && (Duration.between(hack,Instant.now()).toMinutes < 15))
                
                for(mutator <- tableMutators.values) {
                    mutator.close()
                }
                
            } catch {
                case e: IOException =>
                    LOG.info("exception while creating/destroying Connection or BufferedMutator", e)
            }
        }
    }
}

// TODO: skip/filter these: sensor-health