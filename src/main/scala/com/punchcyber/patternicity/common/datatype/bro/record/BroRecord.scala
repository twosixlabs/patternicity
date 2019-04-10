package com.punchcyber.patternicity.common.datatype.bro.record

import java.net.InetAddress
import java.time.{Duration, Instant}
import java.util.regex.Pattern

import com.punchcyber.patternicity.common.datatype.bro.BroDataTypeConversions._
import com.punchcyber.patternicity.common.datatype.bro.BroLogHeader

import scala.collection.mutable.ArrayBuffer
import scala.util.matching.Regex

// TODO: extend  with Seq[(String,Any)]

@SerialVersionUID(10101010L)
class BroRecord(rawRow: String, broHeader: BroLogHeader) extends Serializable {
    private val row: Array[String] = rawRow.split(broHeader.separatorChar)
    
    val broFields: Array[(String,Option[Any])] = {
        val m: Regex = """^(?:set|table|vector)\s*\[([^\[\]]+)\]""".r
        var c: Int = 0
        val tfields: ArrayBuffer[(String,Option[Any])] = ArrayBuffer[(String,Option[Any])]()
    
        while(c < row.length) {
            if(!(row(c) equals broHeader.unsetField) && !(row(c) equals broHeader.emptyField)) {
                m.findFirstIn(broHeader.fields(c)._2) match {
                    case None        =>
                        tfields += ((broHeader.fields(c)._1,Some(fieldMap(broHeader.fields(c)._2)(row(c)))))
        
                    case Some(collectionOf) =>
                        collectionOf match {
                            case "bool"     =>
                                val tempArrayBuffer: ArrayBuffer[Boolean] = ArrayBuffer[Boolean]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroBool(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "count"    =>
                                val tempArrayBuffer: ArrayBuffer[Double] = ArrayBuffer[Double]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroDouble(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "int"      =>
                                val tempArrayBuffer: ArrayBuffer[Int] = ArrayBuffer[Int]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroInt(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "double"   =>
                                val tempArrayBuffer: ArrayBuffer[Double] = ArrayBuffer[Double]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroDouble(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "time"     =>
                                val tempArrayBuffer: ArrayBuffer[Instant] = ArrayBuffer[Instant]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroTime(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "interval" =>
                                val tempArrayBuffer: ArrayBuffer[Duration] = ArrayBuffer[Duration]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroInterval(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "pattern"  =>
                                val tempArrayBuffer: ArrayBuffer[Pattern] = ArrayBuffer[Pattern]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroPattern(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "port"     =>
                                val tempArrayBuffer: ArrayBuffer[Short] = ArrayBuffer[Short]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroShort(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            case "addr"     =>
                                val tempArrayBuffer: ArrayBuffer[InetAddress] = ArrayBuffer[InetAddress]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroAddr(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                
                            // Everything else gets treated as a string
                            case _          =>
                                val tempArrayBuffer: ArrayBuffer[String] = ArrayBuffer[String]()
                    
                                row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                    tempArrayBuffer += fromBroString(rv)
                                })
                    
                                tfields += ((broHeader.fields(c)._1,Some(tempArrayBuffer.toArray)))
                        }
                }
            }
            else {
                tfields += ((broHeader.fields(c)._1,None))
            }
            
            c += 1
        }
    
        tfields.toArray
    }
    
    // TODO: Override toString method to be useful
}

object BroRecord {
    
    def apply(rawRow: String, broHeader: BroLogHeader): BroRecord = {
        new BroRecord(rawRow,broHeader)
    }
    
    def parseRow(rawRow: String, broHeader: BroLogHeader): Array[(String,Any)] = {
        val m: Regex = """^(?:set|table|vector)\s*\[([^\[\]]+)\]""".r
        var c: Int = 0
        val tfields: ArrayBuffer[(String,Any)] = ArrayBuffer[(String,Any)]()
        val row: Array[String] = rawRow.split(broHeader.separatorChar)
        
        while(c < row.length) {
            m.findFirstIn(broHeader.fields(c)._2) match {
                case None        =>
                    tfields += ((broHeader.fields(c)._1,fieldMap(broHeader.fields(c)._2)(row(c))))
                case Some(collectionOf) =>
                    collectionOf match {
                        case "bool"     =>
                            val tempArrayBuffer: ArrayBuffer[Boolean] = ArrayBuffer[Boolean]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroBool(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "count"    =>
                            val tempArrayBuffer: ArrayBuffer[Double] = ArrayBuffer[Double]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroDouble(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "int"      =>
                            val tempArrayBuffer: ArrayBuffer[Int] = ArrayBuffer[Int]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroInt(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "double"   =>
                            val tempArrayBuffer: ArrayBuffer[Double] = ArrayBuffer[Double]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroDouble(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "time"     =>
                            val tempArrayBuffer: ArrayBuffer[Instant] = ArrayBuffer[Instant]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroTime(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "interval" =>
                            val tempArrayBuffer: ArrayBuffer[Duration] = ArrayBuffer[Duration]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroInterval(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "pattern"  =>
                            val tempArrayBuffer: ArrayBuffer[Pattern] = ArrayBuffer[Pattern]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroPattern(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "port"     =>
                            val tempArrayBuffer: ArrayBuffer[Short] = ArrayBuffer[Short]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroShort(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        case "addr"     =>
                            val tempArrayBuffer: ArrayBuffer[InetAddress] = ArrayBuffer[InetAddress]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroAddr(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    
                        // Everything else gets treated as a string
                        case _          =>
                            val tempArrayBuffer: ArrayBuffer[String] = ArrayBuffer[String]()
                        
                            row(c).split(broHeader.setSeparatorChar).foreach(rv => {
                                tempArrayBuffer += fromBroString(rv)
                            })
                        
                            tfields += ((broHeader.fields(c)._1,tempArrayBuffer.toArray))
                    }
            }
        
            c += 1
        }
    
        tfields.toArray
    }
}
