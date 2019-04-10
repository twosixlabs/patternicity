package com.punchcyber.patternicity.common.datatype.bro

import java.net.{InetAddress, UnknownHostException}
import java.time.{Duration, Instant}
import java.util.regex.{Pattern, PatternSyntaxException}

import org.apache.arrow.vector.types.{FloatingPointPrecision, IntervalUnit, TimeUnit}
import org.apache.arrow.vector.types.pojo.ArrowType
import org.apache.spark.sql.types._

import scala.collection.immutable.HashMap
import scala.util.matching.Regex

object BroDataTypeConversions {
    private def splitDecimalParts(in: String): (Long,Long) = {
        val double: Double = in.toDouble
        
        val secs: Long = double.toLong
        val nanos: Long = ((double - secs) * 1000000000).toLong
        
        (secs,nanos)
    }
    
    def fromBroTime(inputValue: String): Instant = {
        /*
      We operate on the assumption that (according to the Bro Documentation here: https://docs.zeek.org/en/stable/script-reference/types.html#type-time)
      Bro outputs UNIX timestamps as Double's, thus the timestamp will have a decimal point separating the Epoch seconds from the nanosecond adjustment
      or in the case of precision "only" to the second, there would be no decimal point.
      
      Example: "1552796991.346255" or "1552796991" will be properly parsed and result in the following Instant (with toString method) 2019-03-17T04:29:51.346255Z
      and 2019-03-17T04:29:51Z respectively.
     */
        val (secs,nanos) = splitDecimalParts(inputValue)
        Instant.ofEpochSecond(secs,nanos)
    }
    
    def fromBroBool(inputValue: String): Boolean = {
        inputValue match {
            case "T" => true
            case "F" => false
            case fail => throw new ClassCastException("Value '" + fail + "' cannot be cast to scala.Boolean")
        }
    }
    
    def fromBroShort(inputValue: String): Short = {
        try {
            inputValue.toShort
        } catch {
            case error: NumberFormatException => throw error
        }
    }
    
    def fromBroInt(inputValue: String): Int = {
        try {
            inputValue.toInt
        } catch {
            case error: NumberFormatException => throw error
        }
    }
    
    def fromBroDouble(inputValue: String): Double = {
        try {
            inputValue.toDouble
        } catch {
            case error: NumberFormatException => throw error
        }
    }
    
    def fromBroPattern(inputValue: String): Pattern = {
        try {
            Pattern.compile(inputValue.replaceAll("^\\/|\\/$",""))
        } catch {
            case error: PatternSyntaxException  => throw error
        }
    }
    
    def fromBroInterval(inputValue: String): Duration = {
        val regex: Regex = """^([0-9e\+\-\.]+)\s*(usec|msec|sec|min|hr|day)""".r
    
        /*
           Perhaps, this is a bit of premature optimization, but the idea for the
           negated "contains" here is that I expect the vast majority of interval
           values to be in seconds with no identifying unit at the end.
           TODO: need to benchmark this
        */
        regex.findFirstMatchIn(inputValue) match {
            case None    =>
                val (secondsPart,nanoPart) = splitDecimalParts(inputValue)
                Duration.ofSeconds(secondsPart,nanoPart)
            case Some(m) =>
                val numString: String = m.group(1)
                val unitString: String = m.group(2)
                
                unitString match {
                    // microseconds
                    case "usec" =>
                        Duration.ofNanos(numString.toDouble.toLong * 1000L)
                        
                    // milliseconds
                    case "msec" =>
                        val doubleValue: Double = numString.toDouble / 1000D
                        val secs: Long = doubleValue.toLong
                        val nanos: Long = (doubleValue - secs).toLong * 1000000L
                        Duration.ofSeconds(secs,nanos)
                        
                    // seconds
                    case "sec"  =>
                        val (secs,nanos) = splitDecimalParts(numString)
                        Duration.ofSeconds(secs,nanos)
                        
                    // minutes
                    case "min"  =>
                        /*
                          Here we take our potentially fractional number of minutes (e.g. 4.2) and multiply by 60
                          to get the number of seconds, which may yet be fractional, finally we split into seconds
                          and nanoseconds for the duration constructor
                        */
                        val doubleValue: Double = numString.toDouble * 60
                        val secs: Long = doubleValue.toLong
                        val nanos: Long = (doubleValue - secs).toLong * 1000000L
                        Duration.ofSeconds(secs,nanos)

                    // hours
                    case "hr"   =>
                        /*
                          Here we take our potentially fractional number of hours (e.g. 4.2) and multiply by (60 * 60)
                          to get the number of seconds, which may yet be fractional, finally we split into seconds
                          and nanoseconds for the duration constructor
                        */
                        val doubleValue: Double = numString.toDouble * 60 * 60
                        val secs: Long = doubleValue.toLong
                        val nanos: Long = (doubleValue - secs).toLong * 1000000L
                        Duration.ofSeconds(secs,nanos)

                    // hours
                    case "day"   =>
                        /*
                          Here we take our potentially fractional number of hours (e.g. 4.2) and multiply by (60 * 60)
                          to get the number of seconds, which may yet be fractional, finally we split into seconds
                          and nanoseconds for the duration constructor
                        */
                        val doubleValue: Double = numString.toDouble * 24 * 60 * 60
                        val secs: Long = doubleValue.toLong
                        val nanos: Long = (doubleValue - secs).toLong * 1000000L
                        Duration.ofSeconds(secs,nanos)
                    case _        =>
                        throw new NumberFormatException("Could not find an appropriate conversion mechanism for input: " + inputValue)
                }
                
        }
    }
    
    def fromBroAddr(inputValue: String): InetAddress = {
        try {
            InetAddress.getByName(inputValue)
        } catch {
            case error: UnknownHostException  => throw error
        }
    }
    
    def fromBroString(inputValue: String): String = inputValue
    
    def fromBroColString(inputValue: String): Array[String] = {
        val split: Array[String] = inputValue.split(',')
        split.map(fromBroString)
    }
    
    val fieldMap: HashMap[String, String => Any] = HashMap[String, String => Any](
        "bool"     -> fromBroBool,
        "count"    -> fromBroDouble,
        "int"      -> fromBroInt,
        "double"   -> fromBroDouble,
        "time"     -> fromBroTime,
        "interval" -> fromBroInterval,
        "string"   -> fromBroString,
        "pattern"  -> fromBroPattern,
        "port"     -> fromBroShort,
        "addr"     -> fromBroAddr,
        "subnet"   -> fromBroString,
        "enum"     -> fromBroString
    )
    
    val broTypeToSparkType: HashMap[String,DataType] = HashMap[String,DataType](
        "bool" ->  BooleanType,
        "count"    -> DoubleType,
        "int"      -> IntegerType,
        "double"   -> DoubleType,
        "time"     -> TimestampType,
        "interval" -> DoubleType,
        "string"   -> StringType,
        "pattern"  -> StringType,
        "port"     -> ShortType,
        "addr"     -> StringType,
        "subnet"   -> StringType,
        "enum"     -> StringType
    )
    
    val broTypeToArrowType: HashMap[String,ArrowType] = HashMap[String,ArrowType](
        "bool" ->  new ArrowType.Bool,
        "count"    -> new ArrowType.FloatingPoint(FloatingPointPrecision.DOUBLE),
        "int"      -> new ArrowType.Int(32,true),
        "double"   -> new ArrowType.FloatingPoint(FloatingPointPrecision.DOUBLE),
        "time"     -> new ArrowType.Timestamp(TimeUnit.MILLISECOND,"UTC"),
        "interval" -> new ArrowType.Interval(IntervalUnit.DAY_TIME),
        "string"   -> new ArrowType.Utf8,
        "pattern"  -> new ArrowType.Utf8,
        "port"     -> new ArrowType.Int(16,true),
        "addr"     -> new ArrowType.Utf8,
        "subnet"   -> new ArrowType.Utf8,
        "enum"     -> new ArrowType.Utf8
    )
}
