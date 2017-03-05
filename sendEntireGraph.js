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
const Fs = require('fs');
const Querystring = require('querystring');
const Http = require('http');
const Cjdnskeys = require('cjdnskeys');
const Split = require('split');

const MAIL = (()=>{throw new Error("You need to set your email...")})();
const SERVER = 'fc53:dcc5:e89d:9082:4097:6622:5e82:c654';

const parseNode = (x) => {
    const nn = Cjdnskeys.parseNodeName(x[3]);
    return { version: nn.v, ip: Cjdnskeys.publicToIp6(nn.key) };
};

const parseLink = (x) => {
    const nodes = [ x[3], x[4] ];
    nodes.sort();
    return { a: Cjdnskeys.publicToIp6(nodes[0]), b: Cjdnskeys.publicToIp6(nodes[1]) };
};

const main = () => {
    const dupeFilter = {};
    const filterDups = (x) => {
        const xstr = JSON.stringify(x);
        if (xstr in dupeFilter) { return; }
        dupeFilter[xstr] = 1;
        return x;
    }
    const nodes = [];
    const links = [];
    if (process.stdout.isTTY) {
        console.log("Usage: node sendEntireGraph.js < walkData.txt");
        return;
    }
    process.stdin.pipe(Split()).on('data', (line) => {
        if (!/^\["node"|\["link"/.test(line)) { return; }
        const parsed = JSON.parse(line);
        const isNode = (parsed[0] === 'node');
        const obj = isNode ? parseNode(parsed) : parseLink(parsed);
        if (!filterDups(obj)) { return; }
        (isNode ? nodes : links).push(obj);
    }).on('end', () => {
        const post = Querystring.stringify({
            data: JSON.stringify({ nodes: nodes, edges: links }),
            version: 2,
            mail: MAIL });

        var opts = {
            host: SERVER,
            port: '80',
            path: '/sendGraph',
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Content-Length': Buffer.byteLength(post)
            }
        };
        const req = Http.request(opts, (res) => {
            res.setEncoding('utf8');
            res.on('data', (chunk) => {
                console.log('Response: ' + chunk);
            });
        });
        req.write(post);
        req.end();
    })
}
main();
