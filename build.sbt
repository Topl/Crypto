

name := "Crypto"

version := "1.0"

scalaVersion := "2.12.8"

mainClass in (Compile, run) := Some("crypto.Crypto")

val circeVersion = "0.9.0"
val akkaVersion = "2.5.24"
val akkaHttpVersion = "10.1.9"

resolvers ++= Seq("Bintray" at "https://jcenter.bintray.com/")

libraryDependencies += "org.scala-lang.modules" %% "scala-swing" % "2.1.1"
libraryDependencies += "com.formdev" % "flatlaf" % "0.38"
libraryDependencies ++= Seq(
  "org.scorexfoundation" %% "iodb" % "0.3.+",
  "org.iq80.leveldb" % "leveldb" % "0.12"
)

val networkDependencies = Seq(
  "com.typesafe.akka" %% "akka-actor" % akkaVersion,
  "com.typesafe.akka" %% "akka-http-core" % akkaHttpVersion,
  "com.typesafe.akka" %% "akka-http" % akkaHttpVersion,
  "com.typesafe.akka" %% "akka-parsing" % akkaHttpVersion,
  "com.typesafe.akka" %% "akka-protobuf" % akkaVersion,
  "com.typesafe.akka" %% "akka-stream" % akkaVersion,
  "org.bitlet" % "weupnp" % "0.1.4",
  "commons-net" % "commons-net" % "3.6"
)

val apiDependencies = Seq(
  "io.circe" %% "circe-core" % circeVersion,
  "io.circe" %% "circe-generic" % circeVersion,
  "io.circe" %% "circe-parser" % circeVersion,
  "de.heikoseeberger" %% "akka-http-circe" % "1.20.0"
)

val loggingDependencies = Seq(
  "ch.qos.logback" % "logback-classic" % "1.3.0-alpha4"
)

val scorexUtil = "org.scorexfoundation" %% "scorex-util" % "0.1.6"

val testingDependencies = Seq(
  "com.typesafe.akka" %% "akka-testkit" % akkaVersion % "test",
  "com.typesafe.akka" %% "akka-http-testkit" % akkaHttpVersion % "test",
  "org.scalactic" %% "scalactic" % "3.0.3" % "test",
  "org.scalatest" %% "scalatest" % "3.0.3" % "test",
  "org.scalacheck" %% "scalacheck" % "1.13.+",
  scorexUtil, (scorexUtil % Test).classifier("tests")
)

libraryDependencies ++= Seq(
  "com.iheart" %% "ficus" % "1.4.2",
  "org.scorexfoundation" %% "scrypto" % "2.1.7",
  scorexUtil
) ++ networkDependencies ++ apiDependencies ++ loggingDependencies ++ testingDependencies

scalacOptions ++= Seq(
  "-Xfatal-warnings",
  "-feature",
  "-deprecation")

enablePlugins(JavaAppPackaging)
enablePlugins(TestNGPlugin)
testNGSuites := Seq("src/test/resources/testng.xml")
