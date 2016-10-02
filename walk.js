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

// This gives you a rough idea of the kbps of traffic which you're going to send/receive.
// Each rtt is somewhere around 500 bytes so 100ms -> 5kB/s of network traffic.
const CYCLE_TIME = 50;

const parseNodeName = (name) => {
    let ver;
    let path;
    let key;
    const ret = name.replace(/^v([0-9]+)\.([0-9a-f\.]{19})\.([^.]{52}).k$/, (all, a, b, c) => {
        ver = Number(a);
        path = b;
        key = c + '.k';
        return '';
    });
    if (ret !== '') { throw new Error("failed to parse node name [" + name + "]"); }
    return { v: ver, path: path, key: key };
};

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
    const parsed = parseNodeName(fullName)
    return Object.freeze({
        version: parsed.v,
        publicKey: parsed.key,
        reachableBy: {},
        testedPeers: {},
        hints: {},
        visited: false,
        scheme: Cjdnsencode.parse(scheme),
        schemeBin: scheme,
        mut: {
            time: +new Date()
        }
    });
};

const _sendMsg = (ctx, obj) => {
    ctx.cjdnslink.send(obj.blob);
};

const sendMsg = function (ctx, toSend, target, nearPath) {
    const parsed = parseNodeName(target);
    ctx.sendMessageQueue.insert({
        blob: toSend,
        label: parsed.path,
        nearPath: nearPath,
        target: target
    });
};

const onMessage = (msg, ping, ctx) => {
    //console.log(msg);
    console.log(JSON.stringify(['recv', ping.target]));
    const node = ctx.nodes[msg.routeHeader.publicKey] = ctx.nodes[msg.routeHeader.publicKey] ||
        mkNode(msg.contentBenc.es, ping.target);
    node.mut.time = +new Date();

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

//    console.log(node);
    const hints = NodesResponse.parse(msg.contentBenc);

    for (let i = hints.length - 1; i >= 0; i--) {
        if (hints.indexOf(hints[i]) !== i) {
            hints.splice(i, 1);
        }
    }

    var discoveredSomething = false;
    if (!node.visited) {
        hints.forEach((h) => {
            const parsed = parseNodeName(h);
            if (parsed.path === '0000.0000.0000.0001') { return; }
            if (node.testedPeers[parsed.key]) { return; }
            if (node.hints[parsed.key]) { return; }
            parsed.cpath = Cjdnsplice.reEncode(parsed.path, node.scheme, Cjdnsplice.FORM_CANNONICAL);
            parsed.fullPath = Cjdnsplice.splice(parsed.path, msg.routeHeader.switchHeader.label);
            node.hints[parsed.key] = parsed;
            console.log(JSON.stringify(['gpr', node.publicKey, parsed.key, parsed.cpath]));
            discoveredSomething = true;
        });
    }

    if (discoveredSomething) {
        const path = hints[0].replace(/^v[0-9]+\.([0-9a-f\.]{19})\.[^\.]+\.k$/, (all, a) => (a));
        if (path.length !== 19) { throw new Error(); }
        sendToNode(ctx, ping.target, path, ping.parentNode, ping.labelPc);
    } else {
        //console.log(ping.parentNode.publicKey + ' -> ' + msg.routeHeader.publicKey + ' ' + JSON.stringify(rb))
        console.log(JSON.stringify(['ann', ping.parentNode.publicKey, msg.routeHeader.publicKey, rb]));
        ping.parentNode.testedPeers[msg.routeHeader.publicKey] = { time: +new Date() };
        if (!node.visited) {
            node.visited = true;
            for (const k in node.hints) {
                const v = node.hints[k];
                const childNode = ctx.nodes[v.key];
                if (childNode && childNode.reachableBy[msg.routeHeader.publicKey]) { continue; }
                if (v.fullPath === 'ffff.ffff.ffff.ffff') {
                    console.log(JSON.stringify(["hzn", v.key, v.path, msg.routeHeader.switchHeader.label]))
                    continue;
                }
                sendToNode(ctx, 'v' + v.v + '.' + v.fullPath + '.' + v.key, '0000.0000.0000.0001', node, v.cpath);
            }
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

const MAX_REQS = 10;
const TIMEOUT_MS = 1000 * 30;

const sendToNode = (ctx, target, nearPath, parentNode, labelPc) => {
    const parsed = parseNodeName(target);
    if (nearPath !== '0000.0000.0000.0001') {
        const node = ctx.nodes[parsed.key];
        if (node && node.visited) {
            throw new Error(target);
            return;
        }
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
        label: parsed.path,
        time: +new Date(),
        reqs: 0,
        timeout: undefined
    };
    out.contentBenc.q = 'gp';
    out.contentBenc.tar = new Buffer(nearPath.replace(/\./g, ''), 'hex');

    const trySend = () => {
        if (ping.reqs++ > MAX_REQS) {
            console.log(JSON.stringify(["fail", target]));
            delete ctx.messages[txid.toString('base64')];
            return;
        }
        console.log(JSON.stringify(['send', target, ping.reqs]));
        sendMsg(ctx, out, target, nearPath);
        ping.timeout = setTimeout(trySend, TIMEOUT_MS);
    };
    trySend();
};

const main = () => {
    const nodeName = process.argv.pop();
    if (!/v[0-9]+\.[0-9a-f\.]+\.[a-z0-9]+\.k/.test(nodeName)) {
        console.log("usage: cjdnsping v<version>.<path>.<key>.k");
        return;
    }

    const ctx = {
        nodes: {},
        messages: {},
        sendMessageQueue: new RBTree((a, b) => {
            let out = 0;
            out += (b.nearPath === '0000.0000.0000.0001');
            out -= (a.nearPath === '0000.0000.0000.0001');
            if (out) { return out; }
            out += (a.label > b.label);
            out -= (a.label < b.label);
            if (out) { return out; }
            out += a.target < b.target;
            if (out) { return out; }
            out += a.target > b.target;
            return out;
        }),
        cjdns: undefined,
        cjdnslink: undefined,
        selfNode: undefined
    };
    nThen((waitFor) => {
        Cjdnsadmin.connectWithAdminInfo(waitFor((c) => { ctx.cjdns = c; }));
    }).nThen((waitFor) => {
        ctx.cjdns.Core_nodeInfo(waitFor((err, ni) => {
            if (err) { throw err; }
            const selfNode = mkNode(new Buffer(ni.compressedSchemeHex, 'hex'), ni.myAddr);
            ctx.selfNode = ctx.nodes[selfNode.publicKey] = selfNode;
            ctx.plater = mkBoilerPlater(selfNode);
        }));
    }).nThen((waitFor) => {
        Cjdnsniff.sniffTraffic(ctx.cjdns, 'CJDHT', waitFor((err, cl) => {
            console.log("Connected to cjdns engine");
            if (err) { throw err; }
            ctx.cjdnslink = cl;
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
                }
            }
        });
        const parsed = parseNodeName(nodeName);
        sendToNode(ctx, nodeName, '0000.0000.0000.0001', ctx.selfNode, parsed.path);
        //v18.0000.0000.0000.0013.cmnkylz1dx8mx3bdxku80yw20gqmg0s9nsrusdv0psnxnfhqfmu0.k

        setInterval(() => {
            if (!ctx.sendMessageQueue.size) { return; }
            const next = ctx.sendMessageQueue.min();
            ctx.sendMessageQueue.remove(next);
            _sendMsg(ctx, next);
        }, CYCLE_TIME);

        setInterval(() => {
            const queueSize = ctx.sendMessageQueue.size;
            const outstandingMsgs = Object.keys(ctx.messages).length;
            console.log(JSON.stringify(["info", queueSize, outstandingMsgs]));
            if (!queueSize && !outstandingMsgs) { process.exit(0); }
        }, 5000)
    })
};

main();
