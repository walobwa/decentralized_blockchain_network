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

// Auth store (per node — not shared across the network), persisted to disk
// and namespaced by port so concurrently-running nodes don't clobber each other.
const dataDir = path.join(__dirname, 'data');
const authFile = path.join(dataDir, `auth-${port}.json`);
let users = [];
let sessions = new Map();

function loadAuth() {
    try {
        const data = JSON.parse(fs.readFileSync(authFile, 'utf8'));
        users = data.users || [];
        sessions = new Map(data.sessions || []);
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

// Add an already-hashed user record from a peer if we don't have it. Returns
// true if it was newly added (idempotent by username).
function mergeUser(user) {
    if (user && user.username && user.salt && user.passwordHash &&
        !users.find(u => u.username === user.username)) {
        users.push({ username: user.username, salt: user.salt, passwordHash: user.passwordHash });
        return true;
    }
    return false;
}

function requireAuth(req, res, next) {
    const header = req.headers['authorization'] || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (token && sessions.has(token)) {
        req.username = sessions.get(token);
        return next();
    }
    res.status(401).json({ note: 'Authentication required.' });
}


const bitcoin = new Blockchain();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false}));

app.post('/auth/register', function(req, res){
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ note: 'Username and password are required.' });
    if (users.find(u => u.username === username)) return res.status(409).json({ note: 'Username already taken.' });

    const salt = uuid();
    const newUser = { username: username, salt: salt, passwordHash: hashPassword(password, salt) };
    users.push(newUser);

    const token = uuid().split('-').join('');
    sessions.set(token, username);
    saveAuth();

    // Broadcast the new credential to every peer so it works network-wide.
    const broadcast = bitcoin.networkNodes.map(nodeUrl => rp({
        uri: nodeUrl + '/auth/receive-user',
        method: 'POST',
        body: { user: newUser },
        json: true
    }).catch(() => null));

    Promise.all(broadcast).then(() => {
        res.json({ token: token, username: username });
    });
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
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password, user.salt)) {
        return res.status(401).json({ note: 'Invalid username or password.' });
    }

    const token = uuid().split('-').join('');
    sessions.set(token, username);
    saveAuth();
    res.json({ token: token, username: username });
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
    const newTransaction = bitcoin.createNewTransaction(req.body.amount, req.body.sender, req.body.recipient);
    bitcoin.addTransactionToPendingTransactions(newTransaction);

    const requestPromises = [];
    bitcoin.networkNodes.forEach(networkNodeUrl => {
        const requestOptions = {
            uri: networkNodeUrl + '/transaction',
            method: 'POST',
            body: newTransaction,
            json: true
        };
        requestPromises.push(rp(requestOptions));
        
    });
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

    const requestPromises = [];
    bitcoin.networkNodes.forEach(newNodeUrl => {
        const requestOptions = {
            uri: newNodeUrl + '/receive-new-block',
            method: 'POST',
            body: { newBlock: newBlock},
            json: true
        };
        requestPromises.push(rp(requestOptions));
    });

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
        return rp(requestOptions);
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
        regNodesPromises.push(rp(requestOptions));
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
    });
});

app.post('/register-node', function(req, res){
    const newNodeUrl = req.body.newNodeUrl;
    const nodeNotAlreadyPresent = bitcoin.networkNodes.indexOf(newNodeUrl) == -1;
    const notCurrentNode = bitcoin.currentNodeUrl !== newNodeUrl;
    if (nodeNotAlreadyPresent && notCurrentNode) bitcoin.networkNodes.push(newNodeUrl);
    res.json({ note: 'New node registered successfully.'});
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