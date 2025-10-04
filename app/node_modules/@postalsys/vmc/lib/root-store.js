'use strict';

const { X509Certificate } = require('crypto');
const rootCerts = require('../data/root-store.json');

class RootStore {
    static create(config = {}) {
        return new RootStore(config);
    }

    constructor(config) {
        this.config = config;
        this.rootCerts = rootCerts
            .map(pem => {
                try {
                    return new X509Certificate(pem);
                } catch (err) {
                    console.error(`Failed to parse root cert`);
                    console.error(err);
                    console.error(pem);
                }
            })
            .filter(cert => cert);
    }

    addCert(pem) {
        let cert = new X509Certificate(pem);
        for (let rootCert of this.rootCerts) {
            if (rootCert.fingerprint256 === cert.fingerprint256) {
                return false;
            }
        }
        this.rootCerts.push(cert);
        return true;
    }
}

module.exports = {
    RootStore
};
