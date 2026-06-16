const express = require('express')
const app = express()
const bodyParser = require('body-parser');
const Blockchain = require('./blockchain');
const { v1: uuid } = require('uuid');
const port = process.argv[2];
const rp = require('request-promise');
const path = require('path');
const fs = require('fs');
const sha256 = require('sha256');
const { json } = require('body-parser');

const nodeAddress = uuid().split('-').join('');

// Safety net: a P2P node must survive an unreachable peer. Log stray rejections
// instead of letting Node crash the process (handlers below also catch directly).
process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection (ignored):', reason && reason.message ? reason.message : reason);
});

// Auth store (per node — not shared across the network), persisted to disk
// and namespaced by port so concurrently-running nodes don't clobber each other.
const dataDir = path.join(__dirname, 'data');
const authFile = path.join(dataDir, `auth-${port}.json`);
const SESSION_TIMEOUT_MS = Number(process.env.SESSION_TIMEOUT_MS) || 5 * 60 * 1000; // auto-logout after 5 minutes idle
let users = [];
let sessions = new Map(); // token -> { username, lastActivity }

function loadAuth() {
    try {
        const data = JSON.parse(fs.readFileSync(authFile, 'utf8'));
        users = data.users || [];
        // Normalise legacy sessions (plain username strings) to the activity-tracked shape.
        sessions = new Map((data.sessions || []).map(([token, val]) =>
            typeof val === 'string' ? [token, { username: val, lastActivity: Date.now() }] : [token, val]));
        console.log(`Loaded ${users.length} user(s) from ${authFile}`);
    } catch (e) {
        // No store yet (first run) — start empty.
    }
}

function saveAuth() {
    try {
        fs.mkdirSync(dataDir, { recursive: true });
        fs.writeFileSync(authFile, JSON.stringify({ users, sessions: [...sessions] }, null, 2));
    } catch (e) {
        console.error('Failed to persist auth store:', e.message);
    }
}

loadAuth();

function hashPassword(password, salt) {
    return sha256(password + salt);
}

// Password policy: >= 8 chars with upper, lower, number, and special character.
// Returns an error message, or null if the password is acceptable.
function validatePassword(password) {
    if (typeof password !== 'string' || password.length < 8) {
        return 'Password must be at least 8 characters long.';
    }
    if (!/[A-Z]/.test(password)) return 'Password must contain an uppercase letter.';
    if (!/[a-z]/.test(password)) return 'Password must contain a lowercase letter.';
    if (!/[0-9]/.test(password)) return 'Password must contain a number.';
    if (!/[^A-Za-z0-9]/.test(password)) return 'Password must contain a special character.';
    return null;
}

// Add an already-hashed user record from a peer if we don't have it. Returns
// true if it was newly added (idempotent by username).
function mergeUser(user) {
    if (user && user.username && user.salt && user.passwordHash &&
        !users.find(u => u.username === user.username)) {
        users.push({
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            emailVerified: !!user.emailVerified,
            verifyToken: user.verifyToken || null,
            salt: user.salt,
            passwordHash: user.passwordHash
        });
        return true;
    }
    return false;
}

function requireAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const session = token ? sessions.get(token) : null;
    if (session) {
        if (Date.now() - session.lastActivity > SESSION_TIMEOUT_MS) {
            sessions.delete(token);
            saveAuth();
            return res.status(401).json({ note: 'Logged out after 5 minutes of inactivity.', code: 'timeout' });
        }
        session.lastActivity = Date.now(); // sliding window: each request refreshes it
        req.username = session.username;
        return next();
    }
    res.status(401).json({ note: 'Authentication required.' });
}


const bitcoin = new Blockchain();

// Track consecutive broadcast failures per peer and prune a peer that has been
// unreachable too many times in a row, so dead nodes don't linger forever.
const peerFailures = new Map();
const MAX_PEER_FAILURES = 3;

function removePeer(nodeUrl) {
    bitcoin.networkNodes = bitcoin.networkNodes.filter(url => url !== nodeUrl);
    peerFailures.delete(nodeUrl);
}

function broadcastToPeer(nodeUrl, pathSuffix, body) {
    return rp({ uri: nodeUrl + pathSuffix, method: 'POST', body: body, json: true })
        .then(data => { peerFailures.delete(nodeUrl); return data; })
        .catch(() => {
            const fails = (peerFailures.get(nodeUrl) || 0) + 1;
            peerFailures.set(nodeUrl, fails);
            if (fails >= MAX_PEER_FAILURES) {
                removePeer(nodeUrl);
                console.log(`Pruned unreachable peer ${nodeUrl} after ${fails} failed broadcasts.`);
            }
            return null;
        });
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false}));

app.post('/auth/register', function(req, res){
    const { firstName, lastName, username, email, password } = req.body;
    if (!firstName || !lastName || !username || !email || !password) {
        return res.status(400).json({ note: 'First name, last name, username, email, and password are required.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ note: 'Enter a valid email address.' });
    }

    const passwordError = validatePassword(password);
    if (passwordError) return res.status(400).json({ note: passwordError });

    if (users.find(u => u.username === username)) return res.status(409).json({ note: 'Username already taken.' });
    if (users.find(u => u.email === email)) return res.status(409).json({ note: 'Email already registered.' });

    const salt = uuid();
    const verifyToken = uuid().split('-').join('');
    const newUser = {
        username: username,
        firstName: firstName,
        lastName: lastName,
        email: email,
        emailVerified: false,
        verifyToken: verifyToken,
        salt: salt,
        passwordHash: hashPassword(password, salt)
    };
    users.push(newUser);

    const token = uuid().split('-').join('');
    sessions.set(token, { username: username, lastActivity: Date.now() });
    saveAuth();

    // Broadcast the new credential to every peer so it works network-wide.
    const broadcast = bitcoin.networkNodes.map(nodeUrl => rp({
        uri: nodeUrl + '/auth/receive-user',
        method: 'POST',
        body: { user: newUser },
        json: true
    }).catch(() => null));

    // Dev mode: instead of emailing, log the verification link (and return it so
    // the UI can show it locally). Username login works without verification.
    const verificationLink = `${bitcoin.currentNodeUrl}/auth/verify?token=${verifyToken}`;
    console.log(`\n[email verification] would send to ${email}:\n  ${verificationLink}\n`);

    Promise.all(broadcast).then(() => {
        res.json({ token: token, username: username, email: email, emailVerified: false, verificationLink: verificationLink });
    });
});

// Verify an email by clicking the link. Marks the account verified and tells
// peers to do the same, then shows a confirmation page.
app.get('/auth/verify', function(req, res){
    const token = req.query.token;
    const user = token && users.find(u => u.verifyToken && u.verifyToken === token);
    const page = (title, body) => `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;text-align:center;padding:64px">
        <h2 style="color:#38bdf8">Nexis Blockchain</h2><h3>${title}</h3><p>${body}</p></body></html>`;
    if (!user) {
        return res.status(400).send(page('Invalid or expired link', 'This verification link is not valid. The email may already be verified.'));
    }
    user.emailVerified = true;
    user.verifyToken = null;
    saveAuth();
    bitcoin.networkNodes.forEach(nodeUrl =>
        rp({ uri: nodeUrl + '/auth/receive-verification', method: 'POST', body: { username: user.username }, json: true }).catch(() => null));
    res.send(page('Email verified ✓', `${user.email} is now verified. You can close this tab and sign in with your username or email.`));
});

// Internal: a peer told us one of its users verified their email.
app.post('/auth/receive-verification', function(req, res){
    const user = users.find(u => u.username === req.body.username);
    if (user && !user.emailVerified) { user.emailVerified = true; user.verifyToken = null; saveAuth(); }
    res.json({ note: 'Verification synced.' });
});

// Internal: receive a single credential broadcast from a peer (no re-broadcast).
app.post('/auth/receive-user', function(req, res){
    if (mergeUser(req.body.user)) saveAuth();
    res.json({ note: 'User synced.' });
});

// Internal: bulk credential sync, sent to a node when it joins the network.
app.post('/auth/sync-users', function(req, res){
    const incoming = req.body.users || [];
    let added = 0;
    incoming.forEach(user => { if (mergeUser(user)) added++; });
    if (added) saveAuth();
    res.json({ note: `Synced ${added} user(s).` });
});

app.post('/auth/login', function(req, res){
    const { username, password } = req.body; // identifier: a username, or a verified email
    const identifier = username;

    // Username always works; email only once verified (so an undelivered link
    // never locks anyone out — they fall back to their username).
    const user = users.find(u => u.username === identifier) ||
                 users.find(u => u.email === identifier && u.emailVerified);

    if (!user || user.passwordHash !== hashPassword(password, user.salt)) {
        const unverified = users.find(u => u.email === identifier && !u.emailVerified);
        if (unverified) {
            return res.status(401).json({ note: 'That email is not verified yet — sign in with your username instead.' });
        }
        return res.status(401).json({ note: 'Invalid username/email or password.' });
    }

    const token = uuid().split('-').join('');
    sessions.set(token, { username: user.username, lastActivity: Date.now() });
    saveAuth();
    res.json({ token: token, username: user.username });
});

// Invalidate the current session server-side (manual logout or idle timeout).
app.post('/auth/logout', function(req, res){
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (token && sessions.has(token)) { sessions.delete(token); saveAuth(); }
    res.json({ note: 'Logged out.' });
});

app.get('/blockchain', requireAuth, function(req, res) {
    res.send(bitcoin);
});

app.post('/transaction', function(req, res){
    const newTransaction = req.body;
    const blockIndex = bitcoin.addTransactionToPendingTransactions(newTransaction);
    res.json({ note: `Transaction will be added in block ${blockIndex}.`});
});

app.post('/transaction/broadcast', function(req, res){
    const { amount, sender, recipient } = req.body;

    // Coinbase (mining reward) is exempt; everything else must be between
    // registered users so you can't transact with a random name.
    const isCoinbase = sender === '00';
    if (!isCoinbase) {
        if (!users.find(u => u.username === sender)) {
            return res.status(400).json({ note: `Sender "${sender}" is not a registered user.` });
        }
        if (!users.find(u => u.username === recipient)) {
            return res.status(400).json({ note: `Recipient "${recipient}" is not a registered user.` });
        }
    }

    const newTransaction = bitcoin.createNewTransaction(amount, sender, recipient);
    bitcoin.addTransactionToPendingTransactions(newTransaction);

    const requestPromises = bitcoin.networkNodes.map(networkNodeUrl =>
        broadcastToPeer(networkNodeUrl, '/transaction', newTransaction));

    Promise.all(requestPromises)
    .then(data => {
        res.json({ note: 'Transaction created and broadcast successfully.', transaction: newTransaction });
    });

});

app.get('/mine', requireAuth, function(req, res){
    const lastBlock = bitcoin.getLastBlock();
    const previousBlockHash = lastBlock['hash'];
    const currentBlockData = {
        transactions: bitcoin.pendingTransactions, 
        index: lastBlock['index'] + 1
    };
    const nonce = bitcoin.proofOfWork(previousBlockHash, currentBlockData);
    const blockHash = bitcoin.hashBlock(previousBlockHash, currentBlockData, nonce);


    const newBlock = bitcoin.createNewBlock(nonce, previousBlockHash, blockHash);

    const requestPromises = bitcoin.networkNodes.map(networkNodeUrl =>
        broadcastToPeer(networkNodeUrl, '/receive-new-block', { newBlock: newBlock }));

    Promise.all(requestPromises)
    .then(data => {
        const requestOptions = {
            uri: bitcoin.currentNodeUrl + '/transaction/broadcast',
            method: 'POST',
            body: {
                amount: 12.5,
                sender: "00",
                recipient: nodeAddress
            },
            json: true
        };
        return rp(requestOptions).catch(() => null);
    })
    .then(data => {
        res.json({
            note: "New block mined and broadcast successfully",
            block: newBlock
        });
    });
});

app.post('/receive-new-block', function(req, res){
    const newBlock = req.body.newBlock;
    const lastBlock = bitcoin.getLastBlock();
    const correctHash = lastBlock.hash === newBlock.previousBlockHash;
    const correctIndex = lastBlock['index'] + 1 === newBlock['index'];
    if (correctHash && correctIndex) {
        bitcoin.chain.push(newBlock);
        bitcoin.pendingTransactions = [];
        res.json({
            note: 'New block received and accepted',
            newBlock: newBlock
        });
    } else {
        res.json({
            note: 'New block rejected',
            newBlock: newBlock
        })
    }
})

app.post('/register-and-broadcast-node', function(req, res){
    const newNodeUrl = req.body.newNodeUrl;
    if (bitcoin.networkNodes.indexOf(newNodeUrl) == -1) bitcoin.networkNodes.push(newNodeUrl);

    const regNodesPromises = [];
    bitcoin.networkNodes.forEach(networkNodeUrl => {
        const requestOptions = {
            uri: networkNodeUrl + '/register-node',
            method: 'POST',
            body: { newNodeUrl: newNodeUrl },
            json: true
        };
        regNodesPromises.push(rp(requestOptions).catch(() => null));
    });
    Promise.all(regNodesPromises)
    .then(data => {
        const bulkRegisterOptions = {
            uri: newNodeUrl + '/register-nodes-bulk',
            method: 'POST',
            body: { allNetworkNodes: [ ...bitcoin.networkNodes, bitcoin.currentNodeUrl ]},
            json: true
        };
        return rp(bulkRegisterOptions);
    })
    .then(data => {
        const syncUsersOptions = {
            uri: newNodeUrl + '/auth/sync-users',
            method: 'POST',
            body: { users: users },
            json: true
        };
        return rp(syncUsersOptions);
    })
    .then(data => {
        res.json({ note: 'New node registered with network successfully'});
    })
    .catch(err => {
        // The joining node was unreachable mid-handshake — roll it back so we
        // don't keep broadcasting to a node that never finished registering.
        bitcoin.networkNodes = bitcoin.networkNodes.filter(url => url !== newNodeUrl);
        res.status(502).json({ note: 'Failed to register new node — it was unreachable.' });
    });
});

app.post('/register-node', function(req, res){
    const newNodeUrl = req.body.newNodeUrl;
    const nodeNotAlreadyPresent = bitcoin.networkNodes.indexOf(newNodeUrl) == -1;
    const notCurrentNode = bitcoin.currentNodeUrl !== newNodeUrl;
    if (nodeNotAlreadyPresent && notCurrentNode) bitcoin.networkNodes.push(newNodeUrl);
    res.json({ note: 'New node registered successfully.'});
});

// Remove a node from the network and tell every peer to do the same.
app.post('/deregister-and-broadcast-node', function(req, res){
    const nodeUrl = req.body.nodeUrl;
    if (!nodeUrl) return res.status(400).json({ note: 'nodeUrl is required.' });

    const peers = bitcoin.networkNodes.filter(url => url !== nodeUrl);
    removePeer(nodeUrl);

    const deregisterPromises = peers.map(peer =>
        rp({ uri: peer + '/deregister-node', method: 'POST', body: { nodeUrl: nodeUrl }, json: true }).catch(() => null));

    Promise.all(deregisterPromises)
    .then(() => res.json({ note: `Node ${nodeUrl} deregistered from the network.` }));
});

// Internal: remove a single node locally (no re-broadcast).
app.post('/deregister-node', function(req, res){
    removePeer(req.body.nodeUrl);
    res.json({ note: 'Node deregistered.' });
});

// List registered usernames (for the transaction recipient picker).
app.get('/users', requireAuth, function(req, res){
    res.json({ users: users.map(u => u.username) });
});

app.post('/register-nodes-bulk', function(req, res){
    const allNetworkNodes = req.body.allNetworkNodes;
    allNetworkNodes.forEach(networkNodeUrl => {
        const nodeNotAlreadyPresent = bitcoin.networkNodes.indexOf(networkNodeUrl) == -1;
        const notCurrentNode = bitcoin.currentNodeUrl !== networkNodeUrl;
        if (nodeNotAlreadyPresent && notCurrentNode) bitcoin.networkNodes.push(networkNodeUrl);
    });
    res.json({ note: 'Bulk registration successful.'});
});


app.get('/block/:blockHash', requireAuth, function(req, res){
    const block = bitcoin.getBlock(req.params.blockHash);
    res.json({ block: block });
});

app.get('/transaction/:transactionId', requireAuth, function(req, res){
    const { transaction, block } = bitcoin.getTransaction(req.params.transactionId);
    res.json({ transaction: transaction, block: block });
});

app.get('/address/:address', requireAuth, function(req, res){
    const addressData = bitcoin.getAddressData(req.params.address);
    res.json({ addressData: addressData });
});

app.get('/block-explorer', function(req, res){
    res.sendFile(path.join(__dirname, 'block-explorer', 'index.html'));
});


app.listen(port, function( ){
    console.log(`Listening on port ${port}....`);
})