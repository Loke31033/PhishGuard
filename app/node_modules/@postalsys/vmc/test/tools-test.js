/* eslint no-unused-expressions:0 */
'use strict';

const fs = require('fs');
const chai = require('chai');
const expect = chai.expect;
const Path = require('path');
const { X509Certificate } = require('crypto');

const { getCerts, parsePemBundle } = require('../lib/tools');

chai.config.includeStack = true;

const fixtures = {
    cnn: fs.readFileSync(Path.join(__dirname, 'fixtures', 'cnn.pem')),
    redshift: fs.readFileSync(Path.join(__dirname, 'fixtures', 'redshift.pem')),
    digicert: fs.readFileSync(Path.join(__dirname, 'fixtures', 'digicert.pem')),
    entrust: fs.readFileSync(Path.join(__dirname, 'fixtures', 'entrust_vmc_specific.pem')),
    globalsignRoot: fs.readFileSync(Path.join(__dirname, 'fixtures', 'globalsign-root.pem'))
};

describe('Tools Tests', () => {
    describe('parsePemBundle Tests', () => {
        it('Should parse CNN bundle', async () => {
            let certs = parsePemBundle(fixtures.cnn);
            expect(certs.length).to.equal(3);
        });

        it('Should parse Redshift bundle', async () => {
            let certs = parsePemBundle(fixtures.redshift);
            expect(certs.length).to.equal(2);
        });

        it('Should parse DigiCert root', async () => {
            let certs = parsePemBundle(fixtures.digicert);
            expect(certs.length).to.equal(1);
        });

        it('Should parse Entrust root', async () => {
            let certs = parsePemBundle(fixtures.entrust);
            expect(certs.length).to.equal(1);
        });

        it('Should parse Globalsign root', async () => {
            let certs = parsePemBundle(fixtures.globalsignRoot);
            expect(certs.length).to.equal(1);
        });
    });

    describe('getCerts Tests', () => {
        it('Should parse CNN bundle', async () => {
            let certs = getCerts(fixtures.cnn);
            expect(certs.length).to.equal(3);
            for (let cert of certs) {
                expect(cert.cert instanceof X509Certificate).to.be.true;
            }
        });

        it('Should parse Redshift bundle', async () => {
            let certs = getCerts(fixtures.redshift);
            expect(certs.length).to.equal(2);
            for (let cert of certs) {
                expect(cert.cert instanceof X509Certificate).to.be.true;
            }
        });
    });
});
