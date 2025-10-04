'use strict';

const { RootStore } = require('./root-store');
const { getCerts } = require('./tools');
const { validatedChain } = require('./validated-chain');
const { parseVMC } = require('./parse-vmc');
const { certInfo } = require('./cert-info');

const defaultRootStore = RootStore.create();

const vmc = async (pem, options) => {
    options = options || {};

    let rootStore = options.rootStore || defaultRootStore;
    let now = options.now;

    const vmcCerts = getCerts(pem);

    if (!vmcCerts) {
        let err = new Error('Empty or missing certificate bundle');
        err.code = 'INVALID_CERT_BUNDLE';
        throw err;
    }

    const chain = validatedChain(vmcCerts, rootStore, now);
    if (!chain) {
        let err = new Error('Empty or missing certificate chain');
        err.code = 'INVALID_CHAIN';
        throw err;
    }

    const logo = await parseVMC(chain[0].cert.raw);
    const certificate = certInfo(chain[0].cert);

    switch (certificate && certificate.subject && certificate.subject.markType) {
        case 'Prior Use Mark':
        case 'Modified Registered Mark':
            logo.type = 'CMC';
            break;

        case 'Registered Mark':
        case 'Government Mark':
        default: // older certificates without markType
            logo.type = 'VMC';
            break;
    }

    logo.certificate = certificate;

    logo.hashValue = logo.hashValue && logo.hashValue.toString('hex');
    logo.logoFile = logo.logoFile && logo.logoFile.toString('base64');

    return logo;
};

module.exports = { vmc, RootStore };
