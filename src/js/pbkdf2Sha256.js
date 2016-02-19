/**
 * @fileoverview Implementation of PBKDF2 in JavaScript.
 * @see http://en.wikipedia.org/wiki/PBKDF2
 *
 * I'm adding the HMAC-SHA256 hashing function to Google's PBKDF2
 * since it's necessary for the Litecoin mining algorithm.
 *
 * Usage:
 *   var key = pbkdf2.deriveKeySha256(
 *       stringToByteArray('password'), stringToByteArray('salt'), 1000, 128);
 *
 */

goog.provide('spaceheater.pbkdf2Sha256');

goog.require('goog.array');
goog.require('goog.asserts');
goog.require('goog.crypt');
goog.require('goog.crypt.Hmac');
goog.require('goog.crypt.Sha1');
goog.require('goog.crypt.pbkdf2');


/**
 * Derives key from password using PBKDF2-SHA256
 * @param {!Array.<number>} password Byte array representation of the password
 *     from which the key is derived.
 * @param {!Array.<number>} initialSalt Byte array representation of the salt.
 * @param {number} iterations Number of interations when computing the key.
 * @param {number} keyLength Length of the output key in bits.
 * @return {!Array.<number>} Byte array representation of the output key.
 */
spaceheater.pbkdf2Sha256.deriveKeySha256 = function(
    password, initialSalt, iterations, keyLength) {
  // Length of the HMAC-SHA256 output in bits.
  var HASH_LENGTH = 256;

  /**
   * Compute each block of the key using HMAC-SHA256.
   * @param {!Array.<number>} index Byte array representation of the index of
   *     the block to be computed.
   * @return {!Array.<number>} Byte array representation of the output block.
   */
  var computeBlock = function(index) {
    // Initialize the result to be array of 0 such that its xor with the first
    // block would be the first block.
    var result = goog.array.repeat(0, HASH_LENGTH / 8);
    // Initialize the salt of the first iteration to initialSalt || i.
    var salt = initialSalt.concat(index);
    var hmac = new goog.crypt.Hmac(new goog.crypt.Sha256(), password, 64);
    // Compute and XOR each iteration.
    for (var i = 0; i < iterations; i++) {
      // The salt of the next iteration is the result of the current iteration.
      salt = hmac.getHmac(salt);
      result = goog.crypt.xorByteArray(result, salt);
    }
    return result;
  };

  return goog.crypt.pbkdf2.deriveKeyFromPassword_(
      computeBlock, HASH_LENGTH, keyLength);
};
