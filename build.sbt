name := "patternicity"

version := "0.1"

scalaVersion := "2.12.8"

assemblyJarName in assembly := name.value + "-" + version.value + ".jar"

resolvers ++= Seq(
    "clojars"           at "http://clojars.org/repo/",
    "HDP"               at "http://repo.hortonworks.com/content/repositories/releases/",
    "Hortonworks Jetty" at "http://repo.hortonworks.com/content/repositories/jetty-hadoop/"
)

libraryDependencies ++= Seq(
    "org.apache.storm" % "storm-core" % "1.2.1.3.1.0.0-78" % Provided
            exclude("org.slf4j", "slf4j-log4j12")
            exclude("log4j","log4j"),
    "org.apache.arrow" % "arrow-memory" % "0.12.0",
    "org.apache.arrow" % "arrow-vector" % "0.12.0",
    "org.apache.spark" %% "spark-sql" % "2.4.0",
    "org.apache.maven" % "maven-artifact" % "3.6.0"
)

assemblyMergeStrategy in assembly := {
    
    case x => val oldStrategy = (assemblyMergeStrategy in assembly).value
        oldStrategy(x)
}