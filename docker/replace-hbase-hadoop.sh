#! /bin/bash
HBASE_HADOOP_VERSION:=2.7.7
REPLACEMENT_HADOOP_VERSION:=3.1.1

for i in /opt/hbase/lib/hadoop-*; do
      case $i in
        *test*);;
        *)
          NEW_FILE=$(echo $i | sed -e "s/$HBASE_HADOOP_VERSION/$REPLACEMENT_HADOOP_VERSION/g; s/\/opt\/hbase\/lib\///g");
          FOLDER=$(echo $NEW_FILE | sed -e "s/-$REPLACEMENT_HADOOP_VERSION.jar//g");
          wget -O /opt/hbase/lib/$NEW_FILE https://search.maven.org/remotecontent?filepath=org/apache/hadoop/$FOLDER/$REPLACEMENT_HADOOP_VERSION/$NEW_FILE;;
      esac;

      rm $i;
    done