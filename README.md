# spaceheater

A ClojureScript Library for Litecoin mining. 

The block hashing algorithm of this library clocks in at a ~~blazing~~
1 hash per second. That means you'll have about a 1/1E chance of finding
target and winning a Litecoin mining round. 

If mining Litecoins isn't really your style, then you're in luck. If you
let this library run its hashing algorithm in hundreds browser tabs at
once, then it can also serve as an efficient space heater for your room!

This library mostly exists as a side effect of playing around with bit
twiddling and the scrypt algorithm. There isn't any serious value in
it but enjoy!

## Usage

Nope

## TODOs

- Proper Litecoin network calls for retrieving and submitting blocks.
- Various other Litecoin network calls
- Cleaner interface for calling the Litecoin miner
- General internal cleanup

## License

Copyright © 2016 Ed Babcock

Distributed under the Eclipse Public License version 1.0 
