// nb-cloudone-smoketest.js
// Simple smoke test for nb-cloudone-server.js

const http = require('http');

const options = {
    hostname: 'localhost',
    port: 8080,
    path: '/',
    method: 'GET'
};

const req = http.request(options, (res) => {
    let data = '';
    res.on('data', chunk => { data += chunk; });
    res.on('end', () => {
        try {
            const result = JSON.parse(data);
            if (result.status === 'ok' && result.service === 'networkbusteros cloud one') {
                console.log('Smoke test passed:', result);
            } else {
                console.error('Smoke test failed: Unexpected response', result);
            }
        } catch (e) {
            console.error('Smoke test failed: Invalid JSON', e);
        }
    });
});

req.on('error', (e) => {
    console.error('Smoke test failed: Server not reachable', e);
});

req.end();
