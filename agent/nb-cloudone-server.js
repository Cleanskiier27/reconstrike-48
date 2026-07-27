// nb-cloudone-server.js
// networkbusteros cloud server for branch bigtree

const http = require('http');

const PORT = process.env.PORT || 8080;

const server = http.createServer((req, res) => {
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify({
        status: 'ok',
        branch: 'bigtree',
        service: 'networkbusteros cloud one',
        timestamp: new Date().toISOString()
    }));
});

server.listen(PORT, () => {
    console.log(`networkbusteros cloud one server running on port ${PORT} (branch: bigtree)`);
});
