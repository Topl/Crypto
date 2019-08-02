

name := "prosomo"

version := "0.2"

scalaVersion := "2.12.8"

mainClass in (Compile, run) := Some("crypto.ouroboros.Prosomo")

val circeVersion = "0.7+"

val networkDependencies = Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.5.23",
  "org.bitlet" % "weupnp" % "0.1.+",
  "commons-net" % "commons-net" % "3.+"
)

val apiDependencies = Seq(
  "io.circe" %% "circe-core" % circeVersion,
  "io.circe" %% "circe-generic" % circeVersion,
  "io.circe" %% "circe-parser" % circeVersion,
  "io.swagger" %% "swagger-scala-module" % "1.0.3",
  // "io.swagger" % "swagger-core" % "1.5.10",
  // "io.swagger" % "swagger-annotations" % "1.5.10",
  // "io.swagger" % "swagger-models" % "1.5.10",
  // "io.swagger" % "swagger-jaxrs" % "1.5.10",
  "com.github.swagger-akka-http" %% "swagger-akka-http" % "0.+",
  "com.typesafe.akka" %% "akka-http" % "10.+"
)

val loggingDependencies = Seq(
  "ch.qos.logback" % "logback-classic" % "1.+",
  "ch.qos.logback" % "logback-core" % "1.+",
  "com.typesafe.akka" % "akka-slf4j_2.12" % "2.5.23"
)

val testingDependencies = Seq(
  "com.typesafe.akka" %% "akka-testkit" % "2.5.23" % "test",
  "org.scalactic" %% "scalactic" % "3.0.+",
  "org.scalatest" %% "scalatest" % "3.0.+" % "test",
  "org.scalacheck" %% "scalacheck" % "1.13.+" % "test",
  "net.databinder.dispatch" %% "dispatch-core" % "+" % "test"
)

libraryDependencies ++= Seq(
  "com.chuusai" %% "shapeless" % "2.+",
  "org.consensusresearch" %% "scrypto" % "1.2.+",
  "io.circe" %% "circe-optics" % circeVersion
) ++ networkDependencies ++ apiDependencies ++ loggingDependencies ++ testingDependencies

libraryDependencies ++= Seq(
  "org.scorexfoundation" %% "iodb" % "0.3.+",
  "com.typesafe.akka" %% "akka-testkit" % "2.5.23" % "test",
  "com.typesafe.akka" %% "akka-http-testkit" % "10.0.7",
  "net.databinder.dispatch" %% "dispatch-core" % "+" % "test",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.61"
)

libraryDependencies += "com.typesafe.akka" %% "akka-actor" % "2.5.19"


libraryDependencies += "org.json4s" %% "json4s-native" % "3.5.2"
libraryDependencies += "com.thesamet.scalapb" %% "scalapb-json4s" % "0.7.0"

// https://mvnrepository.com/artifact/org.whispersystems/curve25519-java
libraryDependencies += "org.whispersystems" % "curve25519-java" % "0.5.0"

val consoleDependencies = Seq(
  // https://mvnrepository.com/artifact/org.apache.httpcomponents/httpclient
  "org.apache.httpcomponents" % "httpclient" % "4.5.3",
  // https://mvnrepository.com/artifact/org.apache.httpcomponents/httpasyncclient
  "org.apache.httpcomponents" % "httpasyncclient" % "4.1.3",
  // https://mvnrepository.com/artifact/org.apache.commons/commons-pool2
  "org.apache.commons" % "commons-pool2" % "2.4.2"
)

libraryDependencies += "org.graalvm" % "graal-sdk" % "1.0.0+"
// https://mvnrepository.com/artifact/com.oracle.truffle/truffle-api
libraryDependencies += "com.oracle.truffle" % "truffle-api" % "1.0.0-rc7"

libraryDependencies ++= consoleDependencies


libraryDependencies  ++= Seq(
  // Last snapshot
  "org.scalanlp" %% "breeze" % "latest.integration"
)

scalacOptions ++= Seq("-feature", "-deprecation")

javaOptions ++= Seq(
  "-Dcom.sun.management.jmxremote"
)

enablePlugins(JavaAppPackaging)
