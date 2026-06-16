const express = require('express')
const app = express()
const bodyParser = require('body-parser');
const Blockchain = require('./blockchain');
const { v1: uuid } = require('uuid');
const port = process.argv[2];
const rp = require('request-promise');
const path = require('path');
const sha256 = require('sha256');
const { json } = require('body-parser');

const nodeAddress = uuid().split('-').join('');

// In-memory auth store (per node — not shared across the network).
const users = [];
const sessions = new Map();

function hashPassword(password, salt) {
    return sha256(password + salt);
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
    users.push({ username: username, salt: salt, passwordHash: hashPassword(password, salt) });

    const token = uuid().split('-').join('');
    sessions.set(token, username);
    res.json({ token: token, username: username });
});

app.post('/auth/login', function(req, res){
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user || user.passwordHash !== hashPassword(password, user.salt)) {
        return res.status(401).json({ note: 'Invalid username or password.' });
    }

    const token = uuid().split('-').join('');
    sessions.set(token, username);
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
    bitcoin.networkNodes.forEach(newNodeUrl => {
        const requestOptions = {
            uri: newNodeUrl + '/register-node',
            method: 'POST',
            body: { newNodeUrl: newNodeUrl},
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