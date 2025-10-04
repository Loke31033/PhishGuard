'use strict';

const { getDateString, parseSubject } = require('./tools');

function formatCertError(cert, message, code, meta) {
    let error = new Error(message);
    let subjectAltName = (cert.subjectAltName || '')
        .split(/^DNS:|,\s*DNS:/g)
        .map(subject => subject.trim())
        .filter(subject => subject);

    error.details = Object.assign({}, meta || {}, {
        certificate: {
            subject: parseSubject(cert.subject),
            subjectAltName,
            fingerprint: cert.fingerprint,
            serialNumber: cert.serialNumber,
            validFrom: getDateString(cert.validFrom),
            validTo: getDateString(cert.validTo),
            issuer: parseSubject(cert.issuer)
        }
    });
    error.code = code;
    return error;
}

function assertCertTime(now, cert) {
    const validFrom = new Date(cert.validFrom);
    const validTo = new Date(cert.validTo);
    if (now < validFrom || now > validTo) {
        throw formatCertError(cert, 'The certificate has expired or is not yet valid', 'CERTIFICATE_VERIFICATION_ERROR');
    }
}

function assertCaCert(cert) {
    if (!cert.ca) {
        throw formatCertError(cert, 'Signing certificate is not a certificate authority', 'CERTIFICATE_VERIFICATION_ERROR');
    }
}

function validatedChain(certs, rootStore, now) {
    if (!certs || !certs.length) {
        return false;
    }

    now = now || new Date();

    assertCertTime(now, certs[0].cert);

    for (let i = 1; i < certs.length; i++) {
        assertCaCert(certs[i].cert);
        if (!certs[i - 1].cert.checkIssued(certs[i].cert)) {
            throw formatCertError(certs[i - 1].cert, 'Invalid certificate chain', 'INVALID_CHAIN');
        }
        assertCertTime(now, certs[i].cert);
    }

    let chainRoot = certs[certs.length - 1];

    let validated = false;
    for (let rootCert of rootStore.rootCerts) {
        if (rootCert.fingerprint512 === chainRoot.cert.fingerprint512) {
            assertCaCert(rootCert);
            validated = true;
            break;
        }

        if (chainRoot.cert.checkIssued(rootCert)) {
            assertCertTime(now, rootCert);
            assertCaCert(rootCert);
            validated = true;
            break;
        }
    }

    if (!validated) {
        throw formatCertError(certs[0].cert, 'Self signed certificate in certificate chain', 'SELF_SIGNED_CERT_IN_CHAIN');
    }

    if (![].concat(certs[0].cert.keyUsage || []).includes('1.3.6.1.5.5.7.3.31')) {
        throw formatCertError(certs[0].cert, 'Certificate is missing required Extended Key Usage identifier', 'BIMI_EXT_KEY_MISSING', {
            description: 'BIMI certificates must include the id-kp-BrandIndicatorforMessageIdentification Extended Key Usage OID'
        });
    }

    return certs;
}

module.exports = { validatedChain };
