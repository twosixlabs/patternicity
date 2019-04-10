package com.punchcyber.patternicity.common.datatype.bro

import BroDataTypeConversions.broTypeToSparkType
import org.apache.spark.sql.types._

import scala.collection.mutable.ArrayBuffer

object BroSparkUtils {
    
    def getSparkStructType(broHeader: BroLogHeader): StructType = {
        
        val structFields: Array[StructField] = {
            val tarray: ArrayBuffer[StructField] = ArrayBuffer[StructField]()
    
            for((columnName,columnType) <- broHeader.fields) {
                tarray += StructField(columnName,broTypeToSparkType(columnType), nullable = true)
            }
            
            tarray.toArray
        }
        
        StructType(structFields)
    }
}
