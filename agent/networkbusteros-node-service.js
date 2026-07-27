// networkbusteros Node.js Service Loader
// Loads JSON and placeholder for other services

const fs = require('fs');
const path = require('path');

const jsonPath = path.join(__dirname, '../SecureBoot/hashes.json');

if (fs.existsSync(jsonPath)) {
    const hashes = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    console.log('Loaded SecureBoot hashes:', hashes);
} else {
    console.log('SecureBoot hashes.json not found.');
}

console.log('networkbusteros Node.js services loaded.');
