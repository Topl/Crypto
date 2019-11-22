# Topl Crypto repository

Testbed for cryptographic primitives and the Ouroboros consensus protocol for future integration into project Bifrost.  Prosomo is the main app that executes the simulation of the consensus protocol.

Building the project requires sbt and OpenJDK runtime environment 8

To compile and execute the application, use 'sbt run' in the project directory.  To build the project for staging enter 'sbt stage' and the executable will be compiled and written to 'Crypto/target/universal/stage/bin/prosomo'.  The stage directory can be moved or renamed to execute on a remote server, as long as lib and bin are in the same directory.

To execute with a given *.conf file, the simulation is run with './prosomo *.conf' or './prosomo *' where '*.conf' contains the desired configuration in the executable path. The default configuration is 'Crypto/src/main/resources/application.conf' and contains comments on all parameters. The output data directory is specified in the configuration settings.

The command line script cmd.sh in the project directory can be used to issue commands to an instance of the simulation running locally, provided that the data output directory is the default directory.  This is used for debugging and testing purposes and commands may be scheduled in the configuration file.


# Ouroboros Prosomoiotís (0.4)
Aaron Schutza
September 2019


- Introduction / purpose
- Requirements
    - Capabilities
    - Constraints
- Specification
- Rationale


# Purpose

A simulation of the Ouroboros Proof of Stake protocol has been written.  *Prosomoiotís* - the Greek word for simulator, is a stand alone application that executes the Ouroboros protocol in a simulated environment.  Properties of the protocol have been studied and metrics of chain data have been plotted under different parameterizations of the model.  Key parameters include the active slots coefficient, epoch length, network delay, active party number, stake distribution, and confirmation depth.  The simulation is designed to mimic the real world execution of the protocol amongst a set of actors communicating in a simplified global network model.  The simulation was developed in Scala so that functionalities and methods can be ported to project Bifrost.  Cryptographic methods are exectued by the actors at runtime, serving as a test bed for the cryptographic primitives that have been implemented for Bifrost.  Simulation output consists of block data that includes forger, transaction, signature, and verification information.  Additionally the stakeholder global position, network connectivity graphs, and stake distribution are also available for plotting.

# Requirements
## Capabilities
- Uses Akka actors to emulate stakeholders, i.e. nodes of the P2P network
- One coordinator actor instantiates the stakeholders, collects their public keys, and disseminates the genesis block
- A router actor collects messages and sends them chronologically using the Akka system scheduler using a delay calculated from a simple global network latency model
- The coordinator acts as a global clock from which all stakeholders get the current time
- Stakeholders communicate exclusively via Akka message passing
- Forged blocks give stakeholders a forger reward that adds to their stake distribution
- Transactions are issued, broadcast, and added to forged blocks
## Constraints
- Designed to emulate Ouroboros Genesis - the actors should mimic the dynamic stake protocol given in Genesis as closely as possible
- The execution should be resilient against adversarial tampering assuming honest majority
- Actors should reach consensus
- Should achieve a robust live ledger
- Simulation must have a mode that generates reproducible deterministic output
- Deterministic output must be a subset of possible output of multi-threaded execution
# Specification

The specification of the protocol used in Prosomo is Ouroboros Genesis.  Ouroboros Chronos is then newest specification of the consensus protocol and is a direct extension of Genesis.  Since Chronos focuses on synchronization and serves to replace the synchronization functionality in Genesis, we have chosen Genesis as a starting point which we can update to Chronos at a later time.  Ouroboros Praos is the previous specification and many of the concepts and terminology will carry over to Genesis.  Since the three specifications use the same staking procedure with differences in chain selection and synchronization, we shed light on the properties of all three protocols by studying Prosomo.  The main difference between Praos and Genesis is the chain selection rule and the removal of checkpoint blocks in Genesis.

**Overview of Protocol**

The most up to date specification is given in the February 2019 edit of  Ouroboros Genesis:

https://www.dropbox.com/s/5z7h4gyijjn0xys/Genesis.pdf?dl=0


The basic procedure of the Ouroboros protocol is a round by round execution of a leader election process that is publicly verifiable.  Blocks are forged in a chronological fashion where time is segmented into integer slots.  Each round corresponds to one slot and epochs represent a fixed interval of slots.  Slot leaders are elected by comparing an integer value produced by a Verifiable Random Function (VRF) against a threshold calculated from the forgers net stake.  The length of the epoch is determined by the network delay tolerance and is parameterized to guarantee certain security and chain quality properties.  The stake distribution and epoch nonce is set at the beginning of each epoch.  The epoch nonce represents the seed randomness for which all stakeholders apply their VRF for slot leader election and future nonce generation.  The threshold of slot leader eligibility during the epoch is held constant.  The stake distribution for calculating the threshold is sampled from a snapshot of the stake two epochs in the past.  This ensures that tampering the stake distribution in a given epoch will not affect slot leader election in the present epoch.  The nonce information is sampled from a special VRF output included in the blocks of the previous epoch.  Only the first two thirds of the epoch VRF nonces are sampled to ensure a smooth transition between epochs.  The stakeholders proceed round by round communicating forged blocks and transactions that are issued from stakeholders.

**Communication Parties**

Stakeholders participate in rounds by diffusing messages and registering the other parties present on the network.  This allows separate parties of stakeholders to be active on the network.  The parties only share information among themselves and the coordinator chooses which holders are in each party.  In each party, the stakeholders use a simplified gossip protocol to share transactions and blocks.  Stakeholders broadcast Hello messages to their neighbor and populate a list of gossipers based on who responds first.  The number of gossipers has a sinusoidal variation to allow bootstrapping new stakeholders.  When the simulation begins, the initial set of stakeholders are all in one party that can be split into sub parties with scripted commands.  The sub parties can be later rejoined to emulate a network split scenario.

**Global Delay Model**

In the simple global network delay model, each stakeholder is assigned random global latitude and longitude.  The network delay is calculated from the distance between each actors coordinates using a proportionality constant in ms/km.  Additionally a delay is added that is proportionate to the size of the message using a constant in ms/byte.  A randomly determined delay is added to each message up to a maximum delay given in ms to emulate random network delay.  The net delay on a message is

    delay = delay_ms_km*distance + delay_ms_byte*messageBytes.size + randDouble*delay_ms_noise

This serves as a crude representation of the effects of network latency, bandwidth, and dynamic availability giving a first order approximation of global delay in a peer to peer network.  A more complete model would use empirical data from real world measurements of operational networks, but that would be beyond the scope of what is planned for this project.  An end goal of Prosomo is to add real network communication to run the simulation on multiple nodes.

**Cryptographic Primitives**

Two functionalities have been implemented specifically for Prosomo: the Key Evolving Signature (KES), and Verifiable Random Function (VRF).  These correspond to the KES and VRF ideal functionalities used in the universally composable construction of Ouroboros Genesis.  A global clock is represented with the system clock to keep the actors in sync.  The coordinator actor behaves as a global clock, giving each stakeholder its system time passed through a message.  Each stakeholder actor then sets its own clock to correspond with the time it was passed.  This acts as a stand in for the global clock functionality used in Ouroboros Genesis.  The global random oracle is implemented with a fast cryptographic hash function that is used to produce unique identifiers and for block hashing.  The hash function currently used is the Blake2b 256-bit java implementation of RFC7693 given in Scorex.  The digital signature functionality is used for transaction verification and party identification.  We use the BouncyCastle java implementation of Ed25519 signature routine specified in RFC8032 https://tools.ietf.org/html/rfc8032.  This gives strong signatures with deterministic output.  The VRF is used for slot leader election and epoch nonce generation and is a modified version of the BouncyCastle Ed25519 adapted to implement ECVRF-ED25519-SHA512-TAI specified in https://tools.ietf.org/html/draft-irtf-cfrg-vrf-04.  The KES functionality is used for block signing and verification, implemented using the Malkin-Micciancio-Miner (MMM) construction specified in https://dl.acm.org/citation.cfm?id=647087.715826 using the BouncyCastle Ed25519 implementation as a base signature functionality.

**Forging Blocks**

Block forging proceeds at the beginning of each slot.  The epoch nonce produced at the beginning of the epoch is concatenated with the slot bytes along with a test constant and applied to the VRF.  The VRF produces an output proof and pseudorandom hash output, called the test value.  This pseudorandom output is compared against the threshold calculated with the aggregate staking function at the begging of the epoch.  If the test output is less than the threshold, then the forger is considered a slot leader.  If the forger is not a slot leader, then the forger idles, listening for blocks and transactions until the next slot.  Valid blocks contain the following information:


    block = (
    parent_block_hash,
    ledger,
    slot,
    certificate,
    vrf_nonce,
    vrf_proof,
    kes_signature,
    kes_public_key,
    block_number,
    parent_block_slot
    )

The ledger contains validated transactions and the forger reward corresponding to the blocks forger.  The certificate contains the VRF test information and public keys so that the threshold of leader eligibility can be calculated and verified when the block is received.

Future epoch nonces are generated by hashing the concatenation of VRF nonces from the first 2/3 of the previous epoch along with the previous epoch nonce.  All actors keep a view of local state from which the stake distribution and epoch threshold can be calculated for block validation.  In a given epoch, the relative stake for block validation and leader election is sampled from the stake distribution from two epochs prior. Every stakeholder will need the exact same snapshot of local state to validate blocks that were forged in a given epoch.  The snapshot, called the staking distribution, is tracked in history.  This ensures that validators can recalculate the exact same threshold and verify the VRF values given in the block.  The stake distribution changes over time through transactions and forger rewards.

**Tine Construction**

Blocks are broadcast among stakeholders as they are forged and when a new block is received a holder will try to build a tine from it.  Tines represent candidates that may be adopted if they are validated and have a common block somewhere on the stakeholders local chain.  When an actor hears about a new block, it adds it to its database.  Blocks are identified by their hash.  If the blocks slot is at or below the current slot, its considered the head of a new tine.  The parent hash included in the new block is used to identify the parent block.  If a parent block is not found in the actors local database, the actor will request that block by querying the sender.  In return if any parent block is not found for subsequently fetched blocks, the sender will be queried again until a parent block is found that is on the local chain of the actor.  Once this common ancestor block is found the tine is then a candidate for chain validation.  If no common ancestor is found, the tine is discarded.

**Chain Adoption**
  
Chain selection occurs in accordance with *maxvalid-bg* specified in Ouroboros Genesis as new tines are built and confirmed to have a common ancestor in the local chain.  The ancestor block for both tines represent the head of the prefix to both tines.  Any tine with a prefix above a certain depth is considered.  This depth is parameterized by *k* and any tine that has a common prefix above *k* blocks deep is selected by longest chain rule, i.e. the tine with a head containing a higher block number than the head of the local chain.  If a common prefix below *k* blocks is found an alternative selection rule is used.  This selection rule prefers the tine with a higher number of blocks in a window of slots starting at the prefix slot and ending at prefix slot + *s* where *s* is the slot window interval.  Both *k* and *s* < *k* are parameterized to satisfy chain quality properties in the honest majority setting.  If either of these conditions are satisfied then the tine is validated block by block.

The tines with appropriate block number are validated per the isValidChain specification in Ouroboros Genesis.  The transactions included in each ledger are verified and a new state is calculated for each block on the tine.  If an invalid state is produced then the entire tine is discarded.  If the resulting state is valid, then each block is verified according to the VRF proofs, KES signatures, and slot leader eligibility according to the forger public keys and the local staking state.  Once the tine has passed all tests it is adopted as the local chain.

The implementation of chain validation in Prosomo has an additional check not specified in Ouroboros Genesis.  The threshold calculated upon forging is included in the block certificate.  The validator calculates this same threshold for the forger from its local staking state, and the locally calculated threshold must be equal to the certificate threshold for the block to be valid.  In Ouroboros Genesis, the locally calculated threshold is evaluated in an inequality against the VRF test nonce, and there is no assurance that the forger and verifier calculated the exact same threshold value.

**Transactions, State, and History**

During the execution of the simulation, transactions are randomly generated at a specified rate. 
Transactions may also be scheduled between specific actors with commands.  Transactions that are issued and new transactions that are discovered are broadcast to the set of gossipers.  An account based model is used for tracking state transitions and each transaction has a unique ID and a nonce.  State consists of a balance along with the next expected transaction nonce.  For a transaction to be applied to state it must have a nonce equal to the expected nonce and it must not deplete the account balance to below zero.  If those conditions are satisfied, then the new state balance is calculated and the next expected nonce is incremented by one.

The state of each stakeholder is represented as an integer value balance along with a transaction counter and activity flag.  Following the account based model of Etherium, the transaction counter enforces the ordering of transactions issued by stakeholders and prevents double counting state transitions when blocks are applied to state.  Block validity is predicated on the state validity check, so that all transactions on the block ledger are valid state transitions.

The activity of stake is currently always on, and inactive stake is not considered in Ouroboros.   If the stake is active, the activity flag is true and the balance contributes the the net stake of the system.  We plan to experiment with setting stake inactive to account for scenarios where a significant portion of stake goes dark.

Each block that produces a valid state is stored in a history object that the actors use to store copies of state.  When the epoch is updated, the snapshot of state used for the staking distribution is collected from history by querying it based on the hash of the block associated with that state.  History is also used to revert the local state to the common prefix and apply new state transitions when checking a new tine.  The staking state is collected from history when the epoch is incremented.

**Wallet**

Each stakeholder has a wallet object that is used to track pending transactions.  The pending transactions are only confirmed after they have appeared in a block at or below the confirmation depth given as a parameter.  This is achieved by sending the wallet a copy of the state at the confirmation depth and removing any pending transactions with a nonce that is lower than the nonce contained in that state.  The balance and total balance can be queried by a command for individual actors.

When tines are adopted the wallet is updated.  All transactions pertaining to the wallet on the local chain from above the common prefix to the head are added to the set of pending transactions.  The new tine that is adopted is applied and the state at confirmation depth is used to trim the set of pending transactions.  The local state is then used to see which transactions appear in the unconfirmed interval of tine that was just adopted.  Any pending transaction that has a nonce greater than or equal to the local state nonce is rebroadcast to the gossiper set.  This ensures that any pending transaction that is missed by a portion of the network will eventually hear about it and either forge it in a block or adopt it in a tine.

**Mempool Management**

The mempool contains pending transactions that are to be applied to the local state upon block forging.  If a new transaction is discovered, i.e. it’s unique ID does not appear in the mempool, its transaction nonce is checked against the expected nonce recorded in local state for that transactions sender.  If the new transaction nonce is greater than or equal to the local state nonce, then the transaction is added to the mempool and broadcast to the set of gossipers.  The mempool accumulates new transactions until either a block is forged, or individual transactions are encountered on the ledgers of adopted tines.

When a tine is adopted, all transactions on the local chain from above the common prefix to the head are added to the mempool.  The new local state is used to trim the mempool of all old transactions that have a transaction nonce lower than the state nonce.  When a tine is discarded, all transactions from that tine are added to the mempool and then the mempool is trimmed with the local state nonces.

**Ledger Selection**

Transactions that are broadcast on the network file into stakeholders mempools and are statefully tracked as eligible ledger entries according to local state.  When a block is forged, the ledger for that block is created from entries in the mempool.  First a buffer is created from the mempool that consists of a sorted list of transactions that are sorted by their nonces.  The lowest nonce is applied first, beyond that there is no order.  Once a maximum number of valid transactions have been parsed, the mempool returns the sorted list and the block is forged with that ledger including the forger reward for the block.  The size of the ledger and the forger reward are configuration parameters not specified in Ouroboros.

**Executing the Simulation**

The simulation is designed to execute a predetermined number of slots, retaining all information in memory.  Chain data is written to disk only when the command is given, stakeholders retain all data in memory and don’t save or load blocks to disk.  The project can be run either in the scala build tool (sbt) console or staged for deployment to a server by running ‘sbt stage’ in the project directory.  This creates the executable Crypto/target/universal/stage/bin/prosomo that can be run independently of sbt.  A command line script for interacting with the simulation is provided in the project directory.  To execute the command line, run Crypto/cmd.sh in a separate terminal.  This is used to pass commands to Prosomo via a file tmp/scorex/test-data/crypto/cmd and also can be used to queue commands at a later slot.  Just enter the desired slot number next to the command.  The command line input script is mostly for debugging purposes, and is useful for manipulating repeated simulation runs in real time.

Prosomo has command line configuration capabilities.  The *.conf files are HOCON formatted configuration files that specify the simulation parameters and commands.  To run a simulation with a given input command, they can be entered into an array in the .conf file.  The default input.conf file is given below, and is included in the project directory:


    input{
      params {
        //your parameters go here
      }
    
      command {
        //your commands go here
        cmd = []
      }
    }

The command line also accepts HOCON formatted strings in the command line to enable scripts to set values in batch jobs.  An example of a parameter sweep run in the bin directory is given below (using GNU parallel):


    parallel --jobs 32 "./prosomo input \"input{params{f_s={1},delay_ms_km={2},inputSeed={3}}}\"" ::: 0.15 0.25 0.35 ::: 0.0 0.1 0.2 0.3 0.4 ::: seed1 seed2 seed3

The prosomo executable will look for a file called input.conf in the local directory and load those values, then it loads the values specified in the string.  The first argument of the prosomo executable specifies the file to look for, e.g. ./prosomo run1 will look for a file called run1.conf

**Commands**

Commands may be specified to execute in a given slot in the configuration file.
Several commands are available:


    status_all

Prints the status of each stakeholder, including the chain hash and number of transactions in the mempool and on the chain.  Individual holders can be addressed by replacing all with the holder index.


    verify_all

Prints the status of each stakeholder, including the chain hash, transaction in mempool, and verifies the chain from the genesis block.  Individual holders can be addressed by replacing all with the holder index.


    inbox

Stakeholders print their inbox which represents a list of all known parties which they are aware of and communicating with.


    print_0

Specifies the holder of the given index to print to console if printing is on.  Default holder to print is holder 0, e.g. print_23 will tell the stakeholder at index 23 to print to console.


    write

Clears the file writer buffer and writes it to the data directory.  Run before plotting.


    kill

Stops all execution.


    stall

Stalls all actors except for the coordinator.  The global clock will continue to tick.


    stall_0

Stalls the holder with the given index.  e.g. stall_0 will stall only the 0th holder stall_2 will stall the 2nd holder etc.


    pause

Pauses the coordinator.  The global clock will stop but all stakeholders will continue to respond to messages they receive.


    randtx

Turns on or off the  coordinator issuing randomized transactions.


    graph

Outputs the network connectivity matrix of the system to the data directory, for plotting with obGraph.py


    tree

Outputs all block data, chain history, and parameters of the printing holder to the data directory.


    tree_all

Same as tree command but outputs all holders in the simulation.


    split

Splits all stakeholders into two randomly selected parties.


    split_stake_0.5

Splits the holders into two parties based on the relative stake.  The two parties will have a net relative stake split by the specified double value between 0.0 and 1.0, e.g. split_stake_0.4 would make two parties with 40% and 60% of the stake, respectively.


    bridge

Splits all stakeholders into two randomly selected parties with one stakeholder in both parties.


    bridge_stake_0.5

Splits all stakeholders into two randomly selected parties with one stakeholder in both parties but splits the parties in the specified stake ratio in the same fashion as split_stake_0.5.  Different value between 0.0 and 1.0 can be used.


    join

Joins the parties back together and resets all actors gossipers.


    new_holder

Creates a new holder that bootstraps from the genesis block.  The new holder will not have any stake initially and won’t be able to forge blocks until future epochs where it has acquired tokens through transactions.

**Configuration Files**

In order to schedule commands and set parameters, spdecify the command in the cmd list of the input.conf file.  For example:


    input{
      params {
        //your parameters go here
        numHolders = 32
      }
    
      command {
        //your commands go here
        cmd = ["split_stake_0.3 100","join 200"]
      }
    }

would set the number of holders in the simulation to 32.  The simulation would evolve until slot 100 and the 32 holders would be split based on their stake into parties consisting of ~30% and ~70% of the net stake respectively.  Then once slot 200 is reached, the parties are joined back together.  This kind of control allows specific network conditions to be emulated to study how the protocol responds to these scenarios.  The plan is to model adversarial behavior with commands that stall parties and change the network connectivity.

The parameters available to be set in the *.conf format files are listed below:


    params {
      //seed for pseudo random runs
      inputSeed = ""
      //number of stakeholders
      numHolders = 64
      //duration of slot in milliseconds
      slotT = 1000
      //delay in milliseconds per killometer in router model
      delay_ms_km = 0.2
      //delay in ms per byte in router model
      delay_ms_byte = 2.0e-4
      //delay random noise
      delay_ms_noise = 100.0
      //use router if true, use direct communication if false
      useRouting = true
      //use network delay parameterization if true
      useDelayParam = true
      //alert stake ratio
      alpha_s = 1.0
      //participating stake ratio
      beta_s = 1.0
      //epoch paramter
      epsilon_s = 0.1
      // checkpoint depth in slots, k > 192*delta/epsilon*beta useDelayParam = true
      k_s = 20000
      // epoch length, R >= 3k/2f if useDelayParam = true
      epochLength = 90000
      // slot window for chain selection, s = k/4f if useDelayParam = true
      slotWindow = 15000
      //active slot coefficient, f <= 1-exp(1/(delta_s+1))*(1+epsilon_s)/(2.0*alpha_s) if useDelayParam = true
      f_s = 0.35
      //simulation runtime in slots
      L_s = 20000
      //number of holders on gossip list for sending new blocks and transactions
      numGossipers = 6
      //use gossiper protocol
      useGossipProtocol = true
      //max number of tries for a tine to ask for parent blocks
      tineMaxTries = 10
      //max depth in multiples of confirmation depth that can be returned from an actor
      tineMaxDepth = 10
      //time out for dropped messages from coordinator, in seconds
      waitTime = 600
      //duration between update tics that stakeholder actors send to themselves, in milliseconds
      updateTime = 1
      //duration between update tics that coordinator and router actors send to themselves, in milliseconds
      commandUpdateTime = 10
      //Issue transactions if true
      transactionFlag = true
      // p = txProbability => chance of issuing transaction per coordinator update
      txProbability = 0.6
      //number of txs per block
      txPerBlock = 2000
      //max number of transactions to be issued over lifetime of simulation
      txMax = 1000000
      //transaction confirmation depth in blocks
      confirmationDepth = 10
      //max initial stake
      initStakeMax = 2.0e9
      //max random transaction delta
      maxTransfer = 100 //5.0e8
      //reward for forging blocks
      forgerReward = 1.0e8
      //percent of transaction amount taken as fee by the forger
      transactionFee = 0.01
      //uses randomness for public key seed and initial stake, set to false for deterministic run
      randomFlag = true
      //use fencing and action based round progression to enforce deterministic runs, set true for deterministic run
      useFencing = false
      //when true, if system cpu load is too high the coordinator will stall to allow stakeholders to catch up
      performanceFlag = true
      //threshold of cpu usage above which coordinator will stall if performanceFlag = true
      systemLoadThreshold = 0.95
      //number of values to average for load threshold
      numAverageLoad = 3
      //print Stakeholder 0 status per slot if true
      printFlag = true
      //print Stakeholder 0 execution time per slot if true
      timingFlag = false
      //Record data if true, plot data points with ./cmd.sh and enter command: plot
      dataOutFlag = true
      //path for data output files
      dataFileDir = "/tmp/scorex/test-data/crypto"
    }


# Rationale

Ouroboros has been presented in a very rigorous and formal mathematical style that stands out among other protocol designs. The protocol is formulated from probabilistic arguments drawn from mathematical proofs about the outcome of an idealized representation constructed from ideal functionalities.  This presentation style gives assurance that the protocol is secure but makes it difficult to conceptualize the procedure and how it operates on a network.  We wish to form a better intuition about protocol behavior under different circumstances to put theory to the test.  The papers provide sparse data about the execution of the protocol.   We will remedy this by plotting metrics of the simulated network for different settings of key parameters.  Work has been done involving simulation of adversarial manipulation, network connectivity conditions, and chain visualization.

