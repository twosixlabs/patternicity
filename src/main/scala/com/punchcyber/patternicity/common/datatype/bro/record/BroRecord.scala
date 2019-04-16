package com.punchcyber.patternicity.common.datatype.bro.record

import java.nio.ByteBuffer
import java.time.Instant
import java.util.UUID

import com.punchcyber.patternicity.common.datatype.bro.BroDataTypeConversions._
import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader
import com.punchcyber.patternicity.enums.bro.LogPath
import org.apache.hadoop.hbase.client.Put
import org.apache.hadoop.hbase.util.Bytes

import scala.collection.mutable

@SerialVersionUID(10101010L)
trait BroRecord extends Serializable {
    val rowKey: String
    def getHbasePut: Put
    def getLogPath: LogPath
 }

class GenericBroRecord(rawRow: String, broHeader: BroLogHeader) extends BroRecord {
    override def getLogPath: LogPath = broHeader.logType
    val row: Array[String] = rawRow.split(broHeader.separatorChar)
    val broFieldMap: mutable.LinkedHashMap[String,Option[(String,String)]] = {
        val tbf: mutable.LinkedHashMap[String,Option[(String,String)]] = mutable.LinkedHashMap[String,Option[(String,String)]]()
        
        var c: Int = 0
    
        while(c < row.length) {
            if(!(row(c) equals broHeader.unsetField) && !(row(c) equals broHeader.emptyField)) {
                tbf.put(broHeader.fields(c)._1,Some((row(c),broHeader.fields(c)._2)))
            }
            else {
                tbf.put(broHeader.fields(c)._1,None)
            }
        
            c += 1
        }
        tbf
    }
    
    override val rowKey: String = UUID.randomUUID().toString
    
    override def getHbasePut: Put = {
        val ts: Instant = {
            if(broFieldMap("ts").isDefined) fromBroTime(broFieldMap("ts").get._1)
            else Instant.now()
        }
        
        val put: Put = new Put(Bytes.toBytes(rowKey),ts.toEpochMilli)
        
        var i: Int = 0
        broFieldMap.foreach(
            kv => {
                broHeader.fields(i)._2 match {
                    case "bool"     =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroBool(kv._2.getOrElse(("",""))._1).toString))
                    case "count"    =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroDouble(kv._2.getOrElse(("0","0"))._1)))
                        else put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(0D))
                    case "int"      =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroInt(kv._2.getOrElse(("0","0"))._1)))
                        else put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(0))
                    case "double"   =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroDouble(kv._2.getOrElse(("0","0"))._1)))
                        else put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(0D))
                    case "time"     =>
                        if(kv._2.isDefined) {
                            val tss: Instant = fromBroTime(kv._2.get._1)
                            val t: ByteBuffer = ByteBuffer.allocate(12)
                            t.putLong(0,tss.toEpochMilli)
                            t.putInt(8,tss.getNano)
                            put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),t.array())
                        }
                    case "interval" =>
                        // TODO: For now, we have the option of representing this as a Duration string or as a number secs/ms/us...doing the numeric route for now, but need to circle back
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroInterval(kv._2.getOrElse(("0","0"))._1).toMillis.toDouble))
                        else put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(0D))
                    case "pattern"  =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroString(kv._2.getOrElse(("",""))._1)))
                    case "port"     =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroInt(kv._2.getOrElse(("0","0"))._1)))
                        else put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(0))
                    case "addr"     =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroString(kv._2.getOrElse(("",""))._1)))
                    case _          =>
                        if(kv._2.isDefined) put.addColumn(Bytes.toBytes("B"),Bytes.toBytes(kv._1.toUpperCase()),Bytes.toBytes(fromBroString(kv._2.getOrElse(("",""))._1)))
                }
            
                i += 1
            }
        )
        put
    }
    
    // TODO: Override toString method to be useful
}

class BroConn(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
        
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
    
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroDns(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroFiles(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        // TODO: [improvement] Need to think if putting the hash first, allowing for super fast filehash lookups is better that starting with the mime type for distribution purposes
        val md5: String = fromBroString(broFieldMap("md5").get._1)
        val mimeType: String = fromBroString(broFieldMap("mime_type").getOrElse(("UNKNOWN","UNKNOWN"))._1)
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("fuid").get._1)
        
        Array[String](md5,mimeType,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroFtp(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        val user: String = fromBroString(broFieldMap("user").get._1)
        
        Array[String](user,ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroHttp(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroKerberos(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroMysql(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroNotice(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = UUID.randomUUID().toString
}

class BroPe(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    // TODO: Need to ensure this actually does provide a unique rowkey.  Also need to think how the rowkey could be better used
    override val rowKey: String = {
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("id").get._1)
        
        Array[String](uid,ts.toEpochMilli.toString).mkString("|")
    }
}

class BroRadius(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroRdp(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSip(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSmbCmd(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSmbMapping(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSmtp(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSnmp(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSsh(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSsl(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroSyslog(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroTunnel(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    override val rowKey: String = {
        val ipString: String = Array[String](fromBroAddr(broFieldMap("id.orig_h").get._1).getHostAddress,fromBroAddr(broFieldMap("id.resp_h").get._1).getHostAddress).sorted.mkString("|")
        val port: String = {
            val sport: Int = fromBroInt(broFieldMap("id.orig_p").get._1)
            val dport: Int = fromBroInt(broFieldMap("id.resp_p").get._1)
    
            if(dport >= sport) sport.toString + "|" + dport.toString
            else dport.toString + "|" + sport.toString
        }
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("uid").get._1)
        
        Array[String](ipString,port,ts.toEpochMilli.toString,uid).mkString("|")
    }
}

class BroX509(rawRow: String, broHeader: BroLogHeader) extends GenericBroRecord(rawRow, broHeader) {
    // TODO: Need to ensure this actually does provide a unique rowkey.  Also need to think how the rowkey could be better used
    override val rowKey: String = {
        val ts: Instant = fromBroTime(broFieldMap("ts").get._1)
        val uid: String = fromBroString(broFieldMap("id").get._1)
        
        Array[String](uid,ts.toEpochMilli.toString).mkString("|")
    }
}


object BroRecord {
    
    def apply(rawRow: String, broHeader: BroLogHeader): GenericBroRecord = {
        broHeader.logType match {
            case LogPath.CONN        => new BroConn(rawRow,broHeader)
            case LogPath.DNS         => new BroDns(rawRow,broHeader)
            case LogPath.FILES       => new BroFiles(rawRow,broHeader)
            case LogPath.FTP         => new BroFtp(rawRow,broHeader)
            case LogPath.HTTP        => new BroHttp(rawRow,broHeader)
            case LogPath.KERBEROS    => new BroKerberos(rawRow,broHeader)
            case LogPath.MYSQL       => new BroMysql(rawRow,broHeader)
            case LogPath.NOTICE      => new BroNotice(rawRow,broHeader)
            case LogPath.PE          => new BroPe(rawRow,broHeader)
            case LogPath.RADIUS      => new BroRadius(rawRow,broHeader)
            case LogPath.RDP         => new BroRdp(rawRow,broHeader)
            case LogPath.SIP         => new BroSip(rawRow,broHeader)
            case LogPath.SMB_CMD     => new BroSmbCmd(rawRow,broHeader)
            case LogPath.SMB_MAPPING => new BroSmbMapping(rawRow,broHeader)
            case LogPath.SMTP        => new BroSmtp(rawRow,broHeader)
            case LogPath.SNMP        => new BroSnmp(rawRow,broHeader)
            case LogPath.SSH         => new BroSsh(rawRow,broHeader)
            case LogPath.SSL         => new BroSsl(rawRow,broHeader)
            case LogPath.SYSLOG      => new BroSyslog(rawRow,broHeader)
            case LogPath.TUNNEL      => new BroTunnel(rawRow,broHeader)
            case LogPath.X509        => new BroX509(rawRow,broHeader)
            case _                   => new GenericBroRecord(rawRow,broHeader)
        }
    }
}
