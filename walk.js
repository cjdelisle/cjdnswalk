#!/usr/bin/env node
/* -*- Mode:js */
/* vim: set expandtab ts=4 sw=4: */
/*
 * You may redistribute this program and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
const Crypto = require('crypto');
const RBTree = require('bintrees').RBTree;
const Cjdnsniff = require('cjdnsniff');
const nThen = require('nthen');
const Cjdnsadmin = require('cjdnsadmin');
const Cjdnsplice = require('cjdnsplice');
const Cjdnskeys = require('cjdnskeys');
const Cjdnsencode = require('cjdnsencode');
const Cjdnsctrl = require('cjdnsctrl');

// This gives you a rough idea of the kbps of traffic which you're going to send/receive.
// Each rtt is somewhere around 500 bytes so 100ms -> 5kB/s of network traffic.
const CYCLE_TIME = 50;
const MAX_REQS = 10;
const TIMEOUT_MS = 1000 * 10;

const mkBoilerPlater = (node) => {
    return (destLabel) => {
        return {
            p: node.version,
            es: node.schemeBin,
            ei: Cjdnsplice.getEncodingForm(destLabel, node.scheme)
        };
    }
};

const NodesResponse =  {};
NodesResponse.parse = (contentBenc) => {
    if (!contentBenc.n || !contentBenc.np) {
        throw new Error("missing n or np from the response");
    }
    const versions = contentBenc.np;
    if (versions[0] !== 1) { throw new Error("multi-byte version"); }
    const nodes = contentBenc.n;
    const out = [];
    for (let i = 0, j = 1; j < versions.length;) {
        const version = versions[j++];
        const key = nodes.slice(i, i += 32);
        const label = nodes.slice(i, i += 8);
        if (i > nodes.length) { throw new Error(); }
        out.push('v' + version + '.' +
            label.toString('hex').replace(/[0-9a-f]{4}/g, (x) => (x + '.')) +
                Cjdnskeys.keyBytesToString(key));
    }
    return out;
};

const mkNode = (scheme, fullName) => {
    const parsed = Cjdnskeys.parseNodeName(fullName);
    return Object.freeze({
        version: parsed.v,
        publicKey: parsed.key,
        reachableBy: {},
        testedPeers: {},
        visited: false,
        scheme: Cjdnsencode.parse(scheme),
        schemeBin: scheme,
        mut: {
            time: +new Date()
        }
    });
};

const keyPing = (ctx, path, txid, ping) => {
    const out = {
        routeHeader: {
            switchHeader: {
                label: path,
                version: 1
            },
            isCtrl: true
        },
        content: {
            type: 'KEYPING',
            key: ctx.selfNode.publicKey,
            version: ctx.selfNode.version,
            content: txid
        }
    };
    console.log(JSON.stringify(["sendkeyping", nowSeconds(), ping.txid, ping.target]))
    ctx.ctrllink.send(out);
};

const nowSeconds = () => ( Math.floor(new Date().getTime() / 1000) );

const onMessage = (msg, ping, ctx) => {
    //console.log(msg);
    console.log(JSON.stringify(['recv', nowSeconds(), ping.txid, ping.target ]));
    let node = ctx.nodes[msg.routeHeader.publicKey];
    if (!node) {
        node = ctx.nodes[msg.routeHeader.publicKey] = mkNode(msg.contentBenc.es, ping.target);
        console.log(JSON.stringify(['node', nowSeconds(), ping.txid, ping.target, node.scheme ]))
    }
    node.mut.time = +new Date();

    const link = JSON.stringify([ msg.routeHeader.publicKey, Cjdnskeys.parseNodeName(ping.parentTarget).key, ping.labelPc ]);
    if (!(link in ctx.links)) {
        ctx.links[link] = 1;
        console.log(JSON.stringify([
            'link',
            nowSeconds(),
            ping.txid,
            msg.routeHeader.publicKey,
            Cjdnskeys.parseNodeName(ping.parentTarget).key,
            ping.labelPc
        ]));
    }

    const gpName = JSON.stringify([ msg.routeHeader.publicKey, ping.nearPath ]);
    ctx.getPeersCalls[gpName] = 1;

    if (!node.schemeBin.equals(msg.contentBenc.es)) {
        throw new Error("changing scheme");
    }
    if (msg.routeHeader.switchHeader.label !== ping.label) {
        throw new Error("return path different");
    }

    const rb = node.reachableBy[ping.parentNode.publicKey] = {
        label: ping.labelPc,
        formNum: msg.contentBenc.ei,
        time: +new Date()
    };

    if (ping.isPing) {
        //console.log(JSON.stringify(['ann', ping.parentNode.publicKey, msg.routeHeader.publicKey, rb]));
        return;
    }

//    console.log(node);
    const hints = ('n' in msg.contentBenc) ? NodesResponse.parse(msg.contentBenc) : [];

    for (let i = hints.length - 1; i >= 0; i--) {
        if (hints.indexOf(hints[i]) !== i) {
            hints.splice(i, 1);
        }
    }

    var discoveredSomething = false;
    if (!node.visited) {
        ping.querySet.hints = ping.querySet.hints || {};
        hints.forEach((h) => {
            const parsed = Cjdnskeys.parseNodeName(h);
            if (parsed.path === '0000.0000.0000.0001') { return; }
            parsed.cpath = Cjdnsplice.reEncode(parsed.path, node.scheme, Cjdnsplice.FORM_CANNONICAL);
            //console.log(JSON.stringify(['gpr', nowSeconds(), ping.txid, node.publicKey, parsed.key, parsed.cpath]));
            if (node.testedPeers[parsed.key]) { return; }
            if (ping.querySet.hints[parsed.key]) { return; }
            parsed.fullPath = Cjdnsplice.splice(parsed.path, msg.routeHeader.switchHeader.label);

const ppath = Cjdnskeys.parseNodeName(ping.target).path;
if (ppath !== msg.routeHeader.switchHeader.label) {
    console.log(ping.target);
    console.log(msg.routeHeader.switchHeader.label);
    throw new Error('label mismatch');
}
if (parsed.fullPath.replace(/^[0\.]*/, '').length < ppath.replace(/^[0\.]*/, '').length) {
    console.log(parsed.fullPath);
    console.log(ppath);
    console.log(parsed.path);
    throw new Error('short label');
}

            ping.querySet.hints[parsed.key] = parsed;
            discoveredSomething = true;
        });
    }

    if (discoveredSomething) {
        const path = hints[0].replace(/^v[0-9]+\.([0-9a-f\.]{19})\.[^\.]+\.k$/, (all, a) => (a));
        if (path.length !== 19) { throw new Error(); }
        sendToNode(ctx, ping.target, path, ping.parentNode, ping.labelPc, ping.parentTarget, ping.querySet);
    } else {
        //console.log(ping.parentNode.publicKey + ' -> ' + msg.routeHeader.publicKey + ' ' + JSON.stringify(rb))
        //console.log(JSON.stringify(['ann', ping.parentNode.publicKey, msg.routeHeader.publicKey, rb]));
        ping.parentNode.testedPeers[msg.routeHeader.publicKey] = { time: +new Date() };
        if (node.visited) { return; }
        node.visited = true;
        if (!ping.querySet) { return; }
        for (const k in ping.querySet.hints) {
            const v = ping.querySet.hints[k];
            const childNode = ctx.nodes[v.key];
            if (childNode && childNode.reachableBy[msg.routeHeader.publicKey]) { continue; }
            if (v.fullPath === 'ffff.ffff.ffff.ffff') {
                console.log(JSON.stringify(["hzn", nowSeconds(), ping.txid, v.key, ping.target, v.path]))
                continue;
            }
            if (v.key === ctx.selfNode.publicKey) {
                continue;
            }
            let request = '0000.0000.0000.0001';
            if (childNode && childNode.visited) {
                request = "ping";
            }
            sendToNode(ctx, 'v' + v.v + '.' + v.fullPath + '.' + v.key, '0000.0000.0000.0001', node, v.cpath, ping.target, {});
        }
    }
    //console.log(msg);
};

/*
{ routeHeader:
   { publicKey: '1fsvgdy0ypfdl7zfhjkh2ffjkpbs0g3j1r3zm2fr2yhz6qnu1xm0.k',
     version: 18,
     ip: 'fcd8:a4e5:3af7:557e:72e5:f9d1:a599:e329',
     switchHeader:
      { label: '0000.0001.7539.33a3',
        congestion: 0,
        suppressErrors: 0,
        version: 1,
        labelShift: 39,
        penalty: 20030 },
     isIncoming: true },
  dataHeader: { contentType: 'CJDHT', version: 1 },
  contentBytes: <Buffer a1 e1 ed 98 07 be 36 26 cf 6f 0f c6 27 5a 83 b1 2a 0c dc 80 e1 8e 3f 45 bb c2 bf 6f 2c d5 a1 4f 00 00 00 01 75 39 33 a3 00 67 4e 3e 00 00 00 12 01 00 ... >,
  contentBenc:
   Dict {
     ei: 1,
     es: <Buffer 61 14 45 81 00>,
     p: 18,
     txid: <Buffer 79 45 11 2d 66 46 d5 94 9c 00 50 8a> } }

*/

const sendToNode = (ctx, target, nearPath, parentNode, labelPc, parentTarget, querySet) => {
    const parsed = Cjdnskeys.parseNodeName(target);
    if (nearPath !== '0000.0000.0000.0001') {
        const node = ctx.nodes[parsed.key];
        if (node && node.visited) {
            throw new Error(target);
            return;
        }
    }

    const parentKey = Cjdnskeys.parseNodeName(parentTarget).key;
    const ppath = Cjdnskeys.parseNodeName(parentTarget).path;
    if (parsed.path.replace(/^[0\.]*/, '').length < ppath.replace(/^[0\.]*/, '').length) {
        console.log(target);
        console.log(parentTarget);
        console.log(labelPc);
        console.log(nearPath);
        throw new Error("path is shorter than parent path WAT");
    }

    const out = {
        routeHeader: {
            publicKey: parsed.key,
            ip: Cjdnskeys.publicToIp6(parsed.key),
            version: parsed.v,
            switchHeader: {
                label: parsed.path,
                version: 1
            }
        },
        dataHeader: { contentType: 'CJDHT', version: 1 },
        contentBenc: ctx.plater(parsed.path)
    };

    const txid = Crypto.randomBytes(16);
    out.contentBenc.txid = txid;
    const ping = ctx.messages[txid.toString('base64')] = {
        labelPc: labelPc,
        parentNode: parentNode,
        target: target,
        parentTarget: parentTarget,
        label: parsed.path,
        time: +new Date(),
        reqs: 0,
        timeout: undefined,
        isPing: false,
        querySet: querySet,
        txid: txid.toString('base64'),
        nearPath: nearPath
    };
    if (nearPath === 'ping') {
        out.contentBenc.q = 'pn';
        ping.isPing = true;
    } else {
        out.contentBenc.q = 'gp';
        out.contentBenc.tar = new Buffer(nearPath.replace(/\./g, ''), 'hex');
    }
    const trySend = () => {
        if (ping.reqs++ > MAX_REQS) {
            console.log(JSON.stringify(["fail", nowSeconds(), ping.txid, target, parentTarget]));
            delete ctx.messages[txid.toString('base64')];
            return;
        }
        if (ping.reqs > 1) {
            console.log(JSON.stringify(["queueresend", nowSeconds(), ping.txid, ping.reqs]));
        }
        //console.log(JSON.stringify(["insert", nowSeconds(), ping.txid]));
        const oldSize = ctx.sendMessageQueue.size;
        ctx.sendMessageQueue.insert({
            label: parsed.path,
            nearPath: nearPath,
            target: target,
            txid: ping.txid,
            func: function () {
                //console.log(JSON.stringify(["callfunc", nowSeconds(), ping.txid]));
                let drop = false;
                if (nearPath != '0000.0000.0000.0001' && nearPath != 'ping') {
                    const gpName = JSON.stringify([ parsed.key, nearPath ]);
                    if (ctx.getPeersCalls[gpName]) { drop = true; }
                } else {
                    const link = JSON.stringify([ parsed.key, Cjdnskeys.parseNodeName(ping.parentTarget).key, ping.labelPc ]);
                    if (ctx.links[link]) { drop = true; }
                }
                if (drop) {
                    //console.log(JSON.stringify(["remove", nowSeconds(), ping.txid]));
                    delete ctx.messages[txid.toString('base64')];
                    return false;
                }
                if (ping.reqs > 1) {
                    keyPing(ctx, parsed.path, txid, ping);
                    if (ping.reqs === 2 && nearPath !== 'ping') {
                        setTimeout(() => {
                            sendToNode(ctx, target, 'ping', parentNode, labelPc, parentTarget, querySet);
                        });
                    }
                }
                console.log(JSON.stringify(['send', nowSeconds(), ping.txid, target, parentTarget, nearPath, ping.reqs]));
                ctx.cjdnslink.send(out);
                ping.timeout = setTimeout(trySend, TIMEOUT_MS);
            }
        })
        if (ctx.sendMessageQueue.size !== oldSize + 1) {
            console.log(ping);
            console.log(ctx.sendMessageQueue.size + ' !== ' + oldSize);
            throw new Error("identical entries");
        }
        //getSessionInfo(ctx, parsed.key, (ret) => {
            //console.log(JSON.stringify(['send', ret.state, ret.handle, nowSeconds(), target, parentTarget, nowSeconds(), nearPath, ping.reqs]));
            //sendMsg(ctx, out, target, nearPath, { parentTarget: parentTarget, reqs: ping.reqs, key: parsed.key, ping: ping, trySend: trySend });
        //});
    };

    trySend();
};

const getPeerStats = (cjdns, cb) => {
    const peers = [];
    const again = (i) => {
        cjdns.InterfaceController_peerStats(i, (err, ret) => {
            if (err) { throw err; }
            ret.peers.forEach((p) => {
                if (p.state !== 'ESTABLISHED') { return; }
                peers.push(p.addr);
            });
            if (typeof(ret.more) !== 'undefined') {
                again(i+1);
            } else {
                cb(peers);
            }
        });
    };
    again(0);
};

const main = () => {
    const ctx = {
        nodes: {},
        messages: {},
        sendMessageQueue: new RBTree((a, b) => {
            let out = 0;
            out += (a.label > b.label);
            out -= (a.label < b.label);
            if (out) { return out; }
            out += (b.nearPath === '0000.0000.0000.0001');
            out -= (a.nearPath === '0000.0000.0000.0001');
            if (out) { return out; }
            out += a.target < b.target;
            out -= a.target > b.target;
            if (out) { return out; }
            out += a.nearPath < b.nearPath;
            out -= a.nearPath > b.nearPath;
            return out;
        }),
        probedLinks: {},
        getPeersCalls: {},
        links: {},
        cjdns: undefined,
        cjdnslink: undefined,
        ctrllink: undefined,
        selfNode: undefined,
        peers: undefined
    };
    let selfTarget;
    nThen((waitFor) => {
        Cjdnsadmin.connectWithAdminInfo(waitFor((c) => { ctx.cjdns = c; }));
    }).nThen((waitFor) => {
        getPeerStats(ctx.cjdns, waitFor((p) => { ctx.peers = p; }));
    }).nThen((waitFor) => {
        ctx.cjdns.Core_nodeInfo(waitFor((err, ni) => {
            if (err) { throw err; }
            const selfNode = mkNode(new Buffer(ni.compressedSchemeHex, 'hex'), ni.myAddr);
            ctx.selfNode = ctx.nodes[selfNode.publicKey] = selfNode;
            ctx.plater = mkBoilerPlater(selfNode);
            selfTarget = ni.myAddr;
        }));
    }).nThen((waitFor) => {
        Cjdnsniff.sniffTraffic(ctx.cjdns, 'CJDHT', waitFor((err, cl) => {
            //console.log("Connected to cjdns engine DHT");
            if (err) { throw err; }
            ctx.cjdnslink = cl;
        }));
        Cjdnsniff.sniffTraffic(ctx.cjdns, 'CTRL', waitFor((err, cl) => {
            //console.log("Connected to cjdns engine CTRL");
            if (err) { throw err; }
            ctx.ctrllink = cl;
        }));
    }).nThen((waitFor) => {
        ctx.cjdnslink.on('error', (e) => {
            console.error('sniffTraffic error');
            console.error(e.stack);
        });
        ctx.cjdnslink.on('message', (msg) => {
            const txid = msg.contentBenc.txid.toString('base64');
            const ping = ctx.messages[txid];
            if (ping) {
                clearTimeout(ping.timeout);
                delete ctx.messages[txid];
                try {
                    onMessage(msg, ping, ctx);
                } catch (e) {
                    console.error("failed to parse message");
                    console.error(msg.contentBenc);
                    console.error(e.stack);
                    process.exit(0);
                }
            }
        });
        ctx.ctrllink.on('error', (e) => {
            console.log(JSON.stringify(['ctrlerr', nowSeconds(), e.message]));
            //console.error(e.stack);
        });
        ctx.ctrllink.on('message', (msg) => {
            msg.content = Cjdnsctrl.parse(msg.contentBytes);
            if (msg.content.type === 'KEYPONG') {
                const ping = ctx.messages[msg.content.content.toString('base64')];
                if (!ping) {
                    console.log(JSON.stringify([
                        "unrecognized_keypong",
                        nowSeconds(),
                        msg.routeHeader.switchHeader.label
                    ]));
                    return;
                }
                if (ping.target !== 'v' + msg.content.version + '.' +
                    msg.routeHeader.switchHeader.label + '.' + msg.content.key)
                {
                    console.log(JSON.stringify([
                        "keypingmismatch",
                        nowSeconds(),
                        ping.txid,
                        ping.target,
                        msg.routeHeader.switchHeader.label,
                        msg.content.version,
                        msg.content.key
                    ]));
                } else {
                    console.log(JSON.stringify([
                        "recvkeyping",
                        nowSeconds(),
                        ping.txid,
                        ping.target
                    ]));
                }
                return;
            }
            if (msg.content.type !== 'ERROR' || !msg.routeHeader.isIncoming) { return; }
            console.log(JSON.stringify([
                'switcherr',
                nowSeconds(),
                msg.routeHeader.switchHeader.label,
                msg.content.switchHeader.label,
                msg.content.errType,
                msg.content.nonce
            ]));
        });

        const parsed = Cjdnskeys.parseNodeName(ctx.peers[0]);
        sendToNode(ctx, ctx.peers[0], '0000.0000.0000.0001', ctx.selfNode, parsed.path, selfTarget, {});

        setInterval(() => {
            for (;;) {
                if (!ctx.sendMessageQueue.size) { return; }
                const next = ctx.sendMessageQueue.min();
                //console.log(JSON.stringify(["invoke", nowSeconds(), next.txid]));
                ctx.sendMessageQueue.remove(next);
                if (next.func() !== false) { break; }
            }
        }, CYCLE_TIME);

        setInterval(() => {
            const queueSize = ctx.sendMessageQueue.size;
            const outstandingMsgs = Object.keys(ctx.messages).length;
            const nodes = Object.keys(ctx.nodes).length;
            const links = Object.keys(ctx.links).length;
            console.log(JSON.stringify(["info", nowSeconds(), queueSize, outstandingMsgs - queueSize, nodes, links]));
            if (!queueSize && !outstandingMsgs) { process.exit(0); }
        }, 5000)
    })
};

main();
