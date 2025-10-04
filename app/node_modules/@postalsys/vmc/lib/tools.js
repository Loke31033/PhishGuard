/* eslint no-control-regex: 0 */
'use strict';

const { X509Certificate } = require('crypto');

const oids = {
    '1.3.6.1.4.1.53087.1.2': 'trademarkOfficeName',
    '1.3.6.1.4.1.53087.1.3': 'trademarkCountryOrRegionName',
    '1.3.6.1.4.1.53087.1.4': 'trademarkRegistration',
    '1.3.6.1.4.1.53087.1.5': 'legalEntityIdentifier',
    '1.3.6.1.4.1.53087.1.6': 'wordMark',
    '1.3.6.1.4.1.53087.1.13': 'markType',
    '1.3.6.1.4.1.53087.4.1': 'pilotIdentifier',
    CN: 'commonName',
    O: 'organizationName',
    OU: 'organizationalUnitName',
    L: 'localityName',
    ST: 'stateOrProvinceName',
    S: 'stateOrProvinceName',
    C: 'countryName',
    jurisdictionC: 'jurisdictionCountryName',
    jurisdictionST: 'jurisdictionStateOrProvinceName',
    jurisdictionL: 'jurisdictionLocalityName'
};

function parsePemBundle(bundle) {
    bundle = (bundle || '').toString().split(/\r?\n/).join('\x00');
    let matches = bundle.match(/[-]{3,}BEGIN [^-]+[-]{3,}.*?[-]{3,}END [^-]+[-]{3,}/g);
    if (matches) {
        matches = Array.from(matches).map(cert => cert.replace(/\x00/g, '\n') + '\n');
    }
    return matches;
}

function getCerts(bundle) {
    let certs = parsePemBundle(bundle);
    if (!certs) {
        return false;
    }

    return certs.map(pem => ({
        pem,
        cert: new X509Certificate(pem)
    }));
}

function getDateString(date) {
    if (!date) {
        return null;
    }
    if (typeof date === 'string') {
        let dateObject = new Date(date);
        if (dateObject.toString() !== 'Invalid Date') {
            return dateObject.toISOString();
        }
        return date;
    }
    if (date && typeof date.toISOString === 'function') {
        return date.toISOString();
    }
    if (date && typeof date.toString === 'function') {
        return date.toString();
    }
    return null;
}

function parseSubject(subject) {
    return Object.fromEntries(
        (subject || '')
            .split(/\r?\n/)
            .map(line => {
                let separatorPos = line.indexOf('=');
                if (separatorPos < 0) {
                    return false;
                }
                let key = line.substring(0, separatorPos);
                key = oids[key] || key;
                let value = line.substring(separatorPos + 1);

                value = value.replace(/\\,/g, ',');
                if (value.charAt(0) === '"') {
                    try {
                        value = JSON.parse(value);
                    } catch (err) {
                        // ignore
                    }
                }
                return [key, value];
            })
            .filter(entry => entry)
    );
}

module.exports = { parsePemBundle, getCerts, getDateString, parseSubject };
