name := "patternicity"

version := "0.1"

scalaVersion := "2.12.8"

javacOptions ++= Seq("-source", "1.8", "-target", "1.8", "-Xlint")

initialize := {
    val _ = initialize.value
    if (sys.props("java.specification.version") != "1.8")
        sys.error("Java 8 is required for this project.")
}

assemblyJarName in assembly := name.value + "-" + version.value + ".jar"

resolvers ++= Seq(
    "clojars"           at "http://clojars.org/repo/",
    "HDP"               at "http://repo.hortonworks.com/content/repositories/releases/",
    "Hortonworks Jetty" at "http://repo.hortonworks.com/content/repositories/jetty-hadoop/"
)

// HDP and HDF minor version tags to tack on to dependencies
val hdpM: String = "3.1.0.0-78"
val hdfM: String = "3.4.0.0-155"

libraryDependencies ++= Seq(
    "org.apache.storm"   %  "storm-core" % "1.2.1.3.1.0.0-78" % Provided
            exclude("org.slf4j", "slf4j-log4j12")
            exclude("log4j"    , "log4j"),
    "org.apache.arrow"   %  "arrow-memory"    % "0.12.0",
    "org.apache.arrow"   %  "arrow-vector"    % "0.12.0",
    "org.apache.maven"   %  "maven-artifact"  % "3.6.0",
    "org.apache.kafka"   %  "kafka-clients"   % "2.0.0.3.1.0.0-78",
    "org.apache.commons" % "commons-lang3" % "3.8.1",
    "commons-collections" % "commons-collections" % "20040616",
    "org.apache.commons" % "commons-compress" % "1.18"
            exclude("commons-beanutils", "commons-beanutils-core")
            exclude("commons-beanutils", "commons-beanutils")
            exclude("commons-collections", "commons-collections"),
    "org.apache.hbase"   % "hbase-common"     % "2.0.2.3.1.0.0-78"
            exclude("org.slf4j","slf4j-log4j12")
            exclude("log4j","log4j"),
    "org.apache.hbase"   % "hbase-client"     % "2.0.2.3.1.0.0-78"
            exclude("org.slf4j","slf4j-log4j12")
            exclude("log4j","log4j"),
    "org.apache.hadoop"  % "hadoop-aws"       % "3.1.1.3.1.0.0-78"
            exclude("org.slf4j", "slf4j-log4j12")
            exclude("log4j","log4j")
            exclude("commons-beanutils", "commons-beanutils-core")
            exclude("commons-beanutils", "commons-beanutils")
            exclude("commons-collections", "commons-collections"),
    "org.apache.hadoop" % "hadoop-common" % "3.1.1.3.1.0.0-78"
            exclude("org.slf4j", "slf4j-log4j12")
            exclude("log4j","log4j")
            exclude("commons-beanutils", "commons-beanutils-core")
            exclude("commons-beanutils", "commons-beanutils")
            exclude("commons-collections", "commons-collections")
)

val circeVersion = "0.10.0"

libraryDependencies ++= Seq(
    "io.circe" %% "circe-core",
    "io.circe" %% "circe-generic",
    "io.circe" %% "circe-parser"
).map(_ % circeVersion)

assemblyMergeStrategy in assembly := {
    case PathList(ps @ _*) if ps.last endsWith "io.netty.versions.properties" =>
        MergeStrategy.rename
    case PathList(ps @ _*) if ps.last equalsIgnoreCase "package-info.class" =>
        MergeStrategy.rename
    case PathList(ps @ _*) if ps.last equalsIgnoreCase "UnusedStubClass.class" =>
        MergeStrategy.rename
    case PathList(ps @ _*) if ps.last equalsIgnoreCase "git.properties" =>
        MergeStrategy.rename
    /*case PathList("io","netty", _ @ _*) =>
        MergeStrategy.last*/
    /*case PathList(ps @ _*) if ps.last equalsIgnoreCase  "libnetty-transport-native-epoll.so" =>
        MergeStrategy.first*/
    case x => val oldStrategy = (assemblyMergeStrategy in assembly).value
        oldStrategy(x)
}
