Topl Crypto repository

Testbed for cryptographic primitives and the Ouroboros consensus protocol for future integration into project Bifrost.  Prosomo is the main app that executes the simulation of the consensus protocol.

Building the project requires sbt and OpenJDK runtime environment 8

To compile and execute the application, use 'sbt run' in the project directory.  To build the project for staging enter 'sbt stage' and the executable will be compiled and written to 'Crypto/target/universal/stage/bin/prosomo'.  The stage directory can be moved or renamed to execute on a remote server, as long as lib and bin are in the same directory.

To execute with a given *.conf file, the simulation is run with './prosomo *.conf' or './prosomo *' where '*.conf' contains the desired configuration in the executable path. The default configuration is 'Crypto/src/main/resources/application.conf' and contains comments on all parameters. The output data directory is specified in the configuration settings.

The command line script cmd.sh in the project directory can be used to issue commands to an instance of the simulation running locally, provided that the data output directory is the default directory.  This is used for debugging and testing purposes and commands may be scheduled in the configuration file.

