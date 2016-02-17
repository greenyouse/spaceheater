// Copyright 2012 The Closure Library Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS-IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

goog.provide('spaceheater.pbkdf2Sha256Test');
goog.setTestOnly('spaceheater.pbkdf2Sha256Test');

goog.require('goog.crypt');
goog.require('goog.testing.jsunit');
goog.require('goog.userAgent');
goog.require('spaceheater.pbkdf2Sha256');

function testPBKDF2() {
    // sha256 test vectors from:
    // https://tools.ietf.org/html/draft-josefsson-scrypt-kdf-04#section-8
    // http://stackoverflow.com/questions/5130513/pbkdf2-hmac-sha2-test-vectors
    // TODO: finish building the test runner for this too

    if (goog.userAgent.IE && goog.userAgent.isVersionOrHigher('7')) {
        return;
    }
    // SHA256
    testPassword = goog.crypt.stringToByteArray('password');
    testSalt = goog.crypt.stringToByteArray('salt');

    assertElementsEquals(
        goog.crypt.hexToByteArray('55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 1, 64));


    assertElementsEquals(
        goog.crypt.hexToByteArray('120fb6cffcf8b32c43e7225256c4f837a86548c9'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 1, 20));


    assertElementsEquals(
        goog.crypt.hexToByteArray('ae4d0c95af6b46d32d0adff928f06dd02a303f8e'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 2, 20));


    assertElementsEquals(
        goog.crypt.hexToByteArray('c5e478d59288c841aa530db6845c4c8d962893a0'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 4096, 20));


    assertElementsEquals(
        goog.crypt.hexToByteArray('cf81c66fe8cfc04d1f31ecb65dab4089f7f179e8'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 16777216, 20));


    testPassword = goog.crypt.stringToByteArray('passwordPASSWORDpassword');
    testSalt =
        goog.crypt.stringToByteArray('saltSALTsaltSALTsaltSALTsaltSALTsalt');


    assertElementsEquals(
        goog.crypt.hexToByteArray('348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 4096, 25));


    testPassword = goog.crypt.stringToByteArray('pass\0word');
    testSalt = goog.crypt.stringToByteArray('sa\0lt');

    assertElementsEquals(
        goog.crypt.hexToByteArray('89b69d0516f829893c696226650a8687'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword, testSalt, 4096, 16));

    testPassword = goog.crypt.stringToByteArray('Password');
    testSalt = goog.crypt.stringToByteArray('NaCl');

    assertElementsEquals(
        goog.crypt.hexToByteArray('4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33cd'),
        spaceheater.pbkdf2Sha256.deriveKeySha256(testPassword,testSalt, 8000, 64));

}
