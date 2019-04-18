FROM openjdk:8

RUN apt-get update
RUN apt-get -y install supervisor python-pip net-tools vim
RUN pip install supervisor-stdout
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV DESTINATION=/opt/hbase HBASE_VERSION=2.0.2

RUN curl -L http://archive.apache.org/dist/hbase/${HBASE_VERSION}/hbase-${HBASE_VERSION}-bin.tar.gz -o /hbase-${HBASE_VERSION}-bin.tar.gz
RUN tar -xvf hbase-${HBASE_VERSION}-bin.tar.gz
RUN mv /hbase-${HBASE_VERSION} ${DESTINATION}
ADD hbase-site.xml /${DESTINATION}/conf/hbase-site.xml

# Folder for data
RUN mkdir -p /data/hbase
RUN mkdir -p /data/zookeeper

# Add Useful Scripts
ADD wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

# Upgrade Hadoop to from 2.7.7 to 3.1.1 
# Note: I tried to upgrade the hadoop version  but got: java.lang.ClassNotFoundException: com.ctc.wstx.io.InputBootstrapper
# Commenting out for now
# ENV HBASE_HADOOP_VERSION=2.7.7 REPLACEMENT_HADOOP_VERSION=3.1.1
# ADD replace-hbase-hadoop.sh /replace-hbase-hadoop.sh
# RUN . /replace-hbase-hadoop.sh

# Install Phoenix
ENV PHOENIX_VERSION=5.0.0 HBASE_MAJOR_VERSION=2.0
RUN curl -L http://apache.cs.utah.edu/phoenix/apache-phoenix-${PHOENIX_VERSION}-HBase-${HBASE_MAJOR_VERSION}/bin/apache-phoenix-${PHOENIX_VERSION}-HBase-${HBASE_MAJOR_VERSION}-bin.tar.gz -o /apache-phoenix-${PHOENIX_VERSION}-HBase-${HBASE_MAJOR_VERSION}-bin.tar.gz
RUN tar -xvf apache-phoenix-${PHOENIX_VERSION}-HBase-${HBASE_MAJOR_VERSION}-bin.tar.gz
RUN mv /apache-phoenix-5.0.0-HBase-2.0-bin /opt/phoenix
RUN cp /opt/phoenix/phoenix-${PHOENIX_VERSION}-HBase-${HBASE_MAJOR_VERSION}-server.jar ${DESTINATION}/lib/

ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
ENV PATH $PATH:/${DESTINATION}/bin

# Phoenix Port
EXPOSE 8765

# Zookeeper port
EXPOSE 2181

# Master port
EXPOSE 16000
# Master info port
EXPOSE 16010

# Regionserver port
EXPOSE 16020
# Regionserver info port
EXPOSE 16030

VOLUME /data/hbase
VOLUME /data/zookeeper
WORKDIR ${DESTINATION}


CMD ["/usr/bin/supervisord"]