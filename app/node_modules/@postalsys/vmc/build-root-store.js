'use strict';

// Root certificates from https://bimigroup.org/vmc-issuers/

const Path = require('path');
const fs = require('fs').promises;
const { parsePemBundle } = require('./lib/tools');

async function main() {
    const rootStoreFilesPath = Path.join(__dirname, 'data', 'root-store');

    let rootCerts = [];

    let files = (await fs.readdir(rootStoreFilesPath)).filter(file => /\.pem$/.test(file));
    for (let file of files) {
        let certs = parsePemBundle(await fs.readFile(Path.join(rootStoreFilesPath, file)));
        for (let cert of certs) {
            rootCerts.push(cert);
        }
    }

    await fs.writeFile(Path.join(__dirname, 'data', 'root-store.json'), JSON.stringify(rootCerts, false, 2));
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
