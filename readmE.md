# Cjdnswalk network walker

## Usage:

    npm install
    node ./walk.js | tee mydump.txt

## Output Format

The output from the walker is newline-deliniated json arrays, each line is one of the following
messages types.

### Announcements

#### "info"
General purpose information about the walk, printed every 10 seconds.

* "info"
* current time in seconds
* number of messages which are queued to send, this number can decrease very fast because some
messages become no longer interesting to send because other messages do their job for them.
* number of messages which are outstanding on the wire (waiting for replies)
* number of nodes that have (so far) been talked to
* number of links which have (so far) been probed, a link will not count until it's actually been
used to send some data

`["info",1488444062,0,1,1029,6848]`

#### "node"
Announce that a node has been discovered, only printed when we have actually talked to the node.

* "node"
* current time in seconds
* txid of message which discovered the node
* node identity (version.path.key)
* node encoding scheme (needed in order to properly splice routes through this node)

`["node",1488443448,"Th7g3+UAPFxP/twMiV413Q==","v19.0000.0000.0000.0863.2v6dt6f841hzhq2wsqwt263w2dswkt6fz82vcyxqptk88mtp8y50.k",[{"bitCount":3,"prefix":"01","prefixLen":1},{"bitCount":5,"prefix":"02","prefixLen":2},{"bitCount":8,"prefix":"00","prefixLen":2}]]`

#### "link"
Announce that a link has been discovered, only printed after we have actually used the link.
Links are considered one-way so each actual connection means there are 2 links.

* "link"
* current time in seconds
* txid of message which discovered the link
* public key of link child (node reachable via link)
* public key of link parent (node we must reach in order to use the link)
* label fragment for reaching the child from the parent

`["link",1488443448,"bHp6O2fLKpiveszKL+DcJQ==","47n26mub6hhf6tcpn2cxggkbk0yfhlmkrvpt911xrukrzvnxb680.k","cmnkylz1dx8mx3bdxku80yw20gqmg0s9nsrusdv0psnxnfhqfmu0.k","0000.0000.0000.001d"]`

#### "hzn"
Announce that we have encountered the switch label horizon and there are nodes which we will not be
able to talk with.

* "hzn"
* current time in seconds
* txid of message which caused discovery of a path which finally cannot be spliced
* key of node which is at the end of unsplicable path
* identity of node/path which told us about a peer that we now cannot reach
* label fragment for getting from node we talked to to node which we cannot reach

`["hzn",1488443503,"edEp602IO/8AUQyFHspG9A==","lhkuc5yybssnh3u1vy0bd8cvtr6qbq2cry8wbw6s0c2qffwwyqd0.k","v16.014d.2e6a.b9e5.34e3.2rgvm4zsk88pgmflrcz9f6jpu422ps34wmum4fk541mws5sd0df0.k","0000.0000.0000.001d"]`

### Data

#### "send"
Informing that a packet has been sent by the walker.

* "send"
* current time in seconds
* txid of message (note: resends of the same message will have the same txid)
* node identity of the node which we are sending to
* node identity of the node which told us about this node
* if getPeers request then the "nearPath" of that request, if ping request then literally "ping"
* retry-number, if sending to the node fails, it will retry up to MAX_REQS times

`["send",1488443448,"L3Ts6FCOogMo4m0ju80+pA==","v19.0000.0000.0000.0823.tcbvl7zf6d8127d1phgq1t01jqdtug7qwmfcg97lcstt22ct7jg0.k","v19.0000.0000.0000.0013.cmnkylz1dx8mx3bdxku80yw20gqmg0s9nsrusdv0psnxnfhqfmu0.k","0000.0000.0000.001f",1]`

#### "recv"
Informing that a packet has been well received.

* "recv"
* current time in seconds
* txid of message (can be compared to corrisponding "send")
* node identity of the node which we talked to

`["recv",1488443448,"SwCc7tJIdlytl1oI2rcY0A==","v18.0000.0000.0000.08e3.4skguq0yfbqqu03k5qgczgmz4q8r8t4t7y7ctcfhhpd05muxbtc0.k"]`

#### "queueresend"
Informing that a reply to a message was not received in TIMEOUT_MS time and so the message will be
resent. There will also be a normal "send" when the resent request is actually sent to the wire.

* "queueresend"
* current time in seconds
* txid of message (will be the same for each resend)
* send number (how many times the request will have been sent when this resend goes out)

`["queueresend",1488448351,"v/XelQEh8cMgD+cqP3d+SA==",2]`

#### "sendkeyping"
Informing that a switch KEYPING was sent to the node in order to confirm that the link is ok and
it that the public key for this node is what we expect. This is sent for each failed "send".

* "sendkeyping"
* current time in seconds
* txid of message (will be the same as the "send" which failed)
* identity of the node which was sent to in send message which failed and caused this KEYPING, the
label from this identity will be the path used for this KEYPING.

`["sendkeyping",1488443492,"BXZLXiOZ3hB0DxXcXRYBrQ==","v19.0000.0000.004e.7523.8hgr62ylugxjyyhxkz254qtz60p781kbswmhhywtbb5rpzc5lxj0.k"]`

#### "recvkeyping"
Informing that the response to a KEYPING has been properly received.

* "recvkeyping"
* current time in seconds
* txid of message (will be the same as the "sendkeyping" and the original "send" which failed)
* identity of node as it was known when sending the ping
* label which was received when the packet came in, this should match the

`["recvkeyping",1488443492,"BXZLXiOZ3hB0DxXcXRYBrQ==","v19.0000.0000.004e.7523.8hgr62ylugxjyyhxkz254qtz60p781kbswmhhywtbb5rpzc5lxj0.k"]`

### Errors

#### "switcherr"
Informing that a switch CTRL message of type ERROR was received. This might not imply any issue with
the walk but an error caused by other usage of the same cjdns node.

* "switcherr"
* current time in seconds
* label of packet which we received (should match path which message causing error was sent)
* label of packet at point where the error occurred, can be used to infer which node sent back the
error message.
* error type
* nonce of packet which caused the error if 0xffffffff then it is a CTRL packet.

`["switcherr",1488444063,"0000.001a.da7b.5523","9708.1e40.0000.00d6","MALFORMED_ADDRESS",1]`

#### "unrecognized_keypong"
Inform that a switch level KEYPING was responded to but we do not know about the original KEYPING.
This might be innocent in the event that the original KEYPING was not done inside of this walker
but rather by cjdns or another user.

* "unrecognized_keypong"
* current time in seconds
* path to node which responded

`["unrecognized_keypong",1488443683,"0000.0000.7fed.5463"]`

#### "keypingmismatch"
Inform that a KEYPING which was sent to a node responded with a version or key which did not match
the expectation.

* "keypingmismatch"
* current time in seconds
* txid of message (will be the same as the "sendkeyping" and the original "send" which failed)
* expected node identity
* actual label
* actual version
* actual key

`["keypingmismatch",1488447837,"ZvBt5zPgqv7P7aE8i076ag==","v16.0000.0000.0369.5463.x640449s40upflgq0m1fw7u3y6xj77jh47ufnn2cwzc73k4j2kh0.k","0000.0000.0369.5463",16,"90tqhh6gc1mwdtrsgqp3wdutxd530vbz5z0j919zdgbx305jkrr0.k"]`

#### "ctrlerr"
Inform that the cjdns CTRL parser threw an error, this generally means the switch frame was invalid.

* "ctrlerr"
* current time in seconds
* error message

`["ctrlerr",1488447794,"invalid checksum, expected [59521] got [33256]"]`
