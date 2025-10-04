'use strict';

const { getDateString, parseSubject } = require('./tools');

function certInfo(cert) {
    let subject = parseSubject(cert.subject);

    let subjectAltName = (cert.subjectAltName || '')
        .split(/^DNS:|,\s*DNS:/g)
        .map(subject => subject.trim())
        .filter(subject => subject);

    return {
        subject,
        subjectAltName,
        fingerprint: cert.fingerprint,
        serialNumber: cert.serialNumber,
        validFrom: getDateString(cert.validFrom),
        validTo: getDateString(cert.validTo),
        issuer: parseSubject(cert.issuer)
    };
}

module.exports = { certInfo };
