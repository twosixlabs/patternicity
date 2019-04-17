package com.punchcyber.patternicity.storm.spout

import java.io.{BufferedReader, FileInputStream, FileReader, InputStreamReader}
import java.nio.file.{Files, Paths}
import java.time.Instant
import java.util

import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.common.datatype.bro.record.BroRecord
import com.punchcyber.patternicity.common.utilities.FileMagic.recursiveFindFileType
import com.punchcyber.patternicity.enums.filetypes.SupportedFileType
import org.apache.commons.compress.compressors.{CompressorException, CompressorStreamFactory}
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.hbase.client.{Connection, ConnectionFactory, Get, Put, Table}
import org.apache.hadoop.hbase.util.Bytes
import org.apache.hadoop.hbase.{HBaseConfiguration, TableName}
import org.apache.storm.spout.SpoutOutputCollector
import org.apache.storm.task.TopologyContext
import org.apache.storm.topology.OutputFieldsDeclarer
import org.apache.storm.topology.base.BaseRichSpout
import org.apache.storm.tuple.{Fields, Values}
import org.slf4j.{Logger, LoggerFactory}

@SerialVersionUID(10101010L)
class FileLineSpout extends BaseRichSpout {
    var context: TopologyContext = _
    var conf: util.Map[_, _] = _
    var collector: SpoutOutputCollector = _
    val logger: Logger = LoggerFactory.getLogger(classOf[FileLineSpout])
    val fileQueue: java.util.concurrent.ConcurrentLinkedQueue[String] = new java.util.concurrent.ConcurrentLinkedQueue[String]()
    var ackEnabled = true
    var ackNum: Long = 0L
    val directoryScanner: Thread = new Thread(new FileLoader)
    var br: BufferedReader = null
    var line: String = null
    var broHeader: BroLogHeader = new BroLogHeader
    val hbaseConf: Configuration = HBaseConfiguration.create()
    hbaseConf.set("hbase.zookeeper.property.clientPort", "2181")
    hbaseConf.set("hbase.zookeeper.quorum", "master-1.punch.datareservoir.net,master-2.punch.datareservoir.net,master-3.punch.datareservoir.net,master-4.punch.datareservoir.net,master-5.punch.datareservoir.net")
    hbaseConf.set("zookeeper.znode.parent", "/hbase")
    val conn: Connection = ConnectionFactory.createConnection(hbaseConf)
    val table: Table = conn.getTable(TableName.valueOf(Bytes.toBytes("HACKSAW:FILE_STATUS")))
    
    override def open(conf: util.Map[_, _], context: TopologyContext, collector: SpoutOutputCollector): Unit = {
        // Just bringing in all our configuration info
        this.conf      = conf
        this.context   = context
        this.collector = collector
        
        // Determine if acks are enabled from the topology...Fancy!
        this.ackEnabled = {
            val ackObj = conf.get("topology.acker.executors")
            if (ackObj != null && ackObj == 0) false
            else true
        }
        
        // Start our directory scanner
        directoryScanner.start()
    
        ConnectionFactory.createConnection(hbaseConf)
    }
    
    override def close(): Unit = {
        // Need to stop our directory scanner when we close
        if(directoryScanner.isAlive) directoryScanner.interrupt()
    }
    
    override def declareOutputFields(declarer: OutputFieldsDeclarer): Unit = {
        declarer.declareStream("hacksaw-bro-logs",new Fields("record"))
    }
    
    override def nextTuple(): Unit = {
        /*
          Our buffered reader should be null under two conditions:
              1. This is the very first "pass", therefore, we need to get to work
              2. We got to the end of a log file and intentionally set it back to null
         */
        if(br == null) {
            var processed: Boolean = true
            var file: String = ""
            
            while(processed) {
                file = fileQueue.poll()
                if(!table.exists(new Get(Bytes.toBytes(file)))) {
                    val put: Put = new Put(Bytes.toBytes(file)).addColumn(Bytes.toBytes("F"),Bytes.toBytes("STARTED"),Bytes.toBytes(Instant.now.toString))
                    table.put(put)
                    processed = false
                }
            }
            
            try {
                val fileType: String = CompressorStreamFactory.detect(new FileInputStream(file))
                logger.info(s"$file is a compressed file of type: $fileType")
                br = new BufferedReader(new InputStreamReader(new CompressorStreamFactory().createCompressorInputStream(new FileInputStream(file))))
            } catch {
                case e: IllegalArgumentException =>
                    logger.error("File '" + file + "' cannot be read \n" + e.getStackTrace.mkString("\n"))
        
                case _: CompressorException =>
                    logger.info(s"$file is uncompressed Bro/Zeek log")
                    br = new BufferedReader(new FileReader(file))
            }
    
            // Finally, grab our Bro log header from the new file
            broHeader.parseHeader(br)
        }
        else {
            line = br.readLine()
            if(line != null && !line.startsWith("#")) {
                val record: BroRecord = BroRecord(line,broHeader)
                if(ackEnabled) {
                    collector.emit("hacksaw-bro-logs",new Values(record),ackNum)
                    ackNum += 1
                }
                else {
                    collector.emit("hacksaw-bro-logs",new Values(record))
                }
            }
            else {
                br = null
            }
        }
    }
    
    // Here is our thread that will load files onto the queue
    class FileLoader extends Runnable {
        override def run(): Unit = {
            val watchedDirectory: String = "/shares/data/input/restricted/DARPA"
            logger.info(s"Scanning input directory: $watchedDirectory")
    
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
            logger.info(s"Loaded ${fileQueue.size()} files from $watchedDirectory")
        }
    }
}
