'use strict';

const crypto = require('crypto');
const { AsnParser } = require('@peculiar/asn1-schema');
const { LogotypeExtn } = require('@peculiar/asn1-x509-logotype');
const { Certificate } = require('@peculiar/asn1-x509');
const zlib = require('zlib');
const util = require('util');
const gunzip = util.promisify(zlib.gunzip);

const hashAlgos = {
    '1.3.14.3.2.26': 'sha1',
    '2.16.840.1.101.3.4.2.4': 'sha224',
    '2.16.840.1.101.3.4.2.1': 'sha256',
    '2.16.840.1.101.3.4.2.2': 'sha384',
    '2.16.840.1.101.3.4.2.3': 'sha512',
    '2.16.840.1.101.3.4.2.5': 'sha512-224',
    '2.16.840.1.101.3.4.2.6': 'sha512-256'
};

function parseDataUrl(url) {
    if (url.indexOf('data:') !== 0) {
        return {};
    }

    let commaPos = url.indexOf(',');
    if (commaPos < 0) {
        return {};
    }

    let header = url.substring('data:'.length, commaPos);
    let content = url.substring(commaPos + 1);

    let parts = header.split(';');
    let mediaType = parts.shift() || '';
    let base64 = parts.shift() === 'base64';

    return { header, content, mediaType, base64 };
}

async function parseVMC(buf) {
    const cert = AsnParser.parse(buf, Certificate);
    const logoExtension = cert.tbsCertificate.extensions.find(ext => ext.extnID === '1.3.6.1.5.5.7.1.12');

    if (logoExtension && logoExtension.extnValue) {
        let logo = AsnParser.parse(logoExtension.extnValue, LogotypeExtn);

        let imageDetails =
            logo.subjectLogo &&
            logo.subjectLogo.direct &&
            logo.subjectLogo.direct.image &&
            logo.subjectLogo.direct.image[0] &&
            logo.subjectLogo.direct.image[0].imageDetails;

        if (imageDetails) {
            let hashAlgo, hashValue, hashAlgoOid;

            let hashObject = imageDetails.logotypeHash && imageDetails.logotypeHash[0] && imageDetails.logotypeHash[0];

            if (hashObject) {
                hashAlgoOid = hashObject.hashAlg && hashObject.hashAlg.algorithm;
                if (hashAlgoOid && hashAlgos[hashAlgoOid]) {
                    hashAlgo = hashAlgos[hashAlgoOid];
                }

                if (hashObject.hashValue && hashObject.hashValue.buffer) {
                    hashValue = Buffer.from(hashObject.hashValue.buffer);
                }
            }

            let logotypeURI = imageDetails.logotypeURI && imageDetails.logotypeURI[0];
            let logoFile;
            if (logotypeURI) {
                let { content, base64 } = parseDataUrl(logotypeURI);
                if (content) {
                    if (base64) {
                        content = Buffer.from(content, 'base64');
                    }
                    logoFile = await gunzip(content);
                }
            }

            let data = {
                mediaType: imageDetails.mediaType,
                hashAlgo,
                hashValue,
                logoFile
            };

            if (data.logoFile && (data.hashAlgo || data.hashAlgoOid) && data.hashValue) {
                let hasher;
                try {
                    hasher = crypto.createHash(data.hashAlgo || data.hashAlgoOid);
                } catch (err) {
                    // invalid hash
                }
                if (hasher) {
                    data.validHash = hashValue.equals(hasher.update(logoFile).digest());
                }
            }

            return data;
        }
    }

    let error = new Error('Invalid or missing logotype extension in the certificate');
    error.code = 'INVALID_LOGOTYPE_EXT';
    throw error;
}

module.exports = { parseVMC };
