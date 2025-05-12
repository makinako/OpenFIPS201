/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201 Copyright: (c) 2025 Commonwealth of Australia 
 * Author: Kim O'Sullivan / Makina (kim@makina.com.au / @makinako)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ******************************************************************************/

package org.openfips201.applet;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/** Provides functionality for ECC PIV key objects */
class PIVKeyECC extends PIVKeyPKI {
  
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  // PERSISTENT - The key store
  private KeyPair keyPair;

  PIVKeyECC(int id, byte modeContact, byte modeContactless, byte adminKey, byte mechanism, byte role, byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
  }

  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>
   * Notes:
   *
   * <ul>
   * <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust NV
   * RAM.
   * <li>The ELEMENT_ECC_POINT element must be formatted as an octet string as per ANSI X9.62.
   * <li>The ELEMENT_ECC_SECRET must be formatted as a big-endian, right-aligned big number.
   * <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer  containing the updated element
   * @param offset  first byte of the element in the buffer
   * @param length  the length of the element
   */
  @Override
  void update(byte element, byte[] buffer, short offset, short length) throws ISOException {

    // PRE-CONDITION 1 - If the key is initialised, it must be explicitly cleared first
    if (isInitialised() && element != ELEMENT_CLEAR) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    } else {
      // Ensure that the key objects are allocated
      // NOTE: Even if an invalid element is supplied, any call to updateElement()
      // will result in the allocation of memory for the key object.
      allocate();
    }

    switch (element) {
    case ELEMENT_ECC_POINT:
      // Only uncompressed points are supported
      if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        return; // Keep static analyser happy
      }
      if (length != getPublicPointLength()) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return; // Keep static analyser happy
      }

      ((ECPublicKey) keyPair.getPublic()).setW(buffer, offset, length);
      break;

    case ELEMENT_ECC_SECRET:
      if (length != getKeyLengthBytes()) {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return; // Keep static analyser happy
      }

      ((ECPrivateKey) keyPair.getPrivate()).setS(buffer, offset, length);
      break;

    default:
      super.update(element, buffer, offset, length);
      break;
    }
  }

  /***
   * Allocates memory for the private and public key parts
   */
  private void allocate() {

    if (keyPair != null) {
      return;
    }

    ECPrivateKey privateKey;
    ECPublicKey publicKey;
    
    switch (getMechanism()) {
    case Constants.ID_ALG_ECC_P256:
    case Constants.ID_ALG_ECC_CS2:
      privateKey = (ECPrivateKey)Platform.Cryptography.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256);
      publicKey = (ECPublicKey)Platform.Cryptography.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256);
      break;

    case Constants.ID_ALG_ECC_P384:
    case Constants.ID_ALG_ECC_CS7:
      privateKey = (ECPrivateKey)Platform.Cryptography.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_384);
      publicKey = (ECPublicKey)Platform.Cryptography.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_384);
      break;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return; // Keep compiler happy
    }
    
    keyPair = new KeyPair(publicKey, privateKey);
  }

  @Override
  short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    return Platform.Cryptography.sign((ECPrivateKey) keyPair.getPrivate(), inBuffer, inOffset, inLength, outBuffer,
        outOffset);
  }

  @Override
  short keyEstablish(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

    // PRE-CONDITION 1 - The input buffer must equal the expected public key point value
    // NOTE: This is checked by the underlying crypto implementation now

    return Platform.Cryptography.computeECDH((ECPrivateKey) keyPair.getPrivate(), inBuffer, inOffset, inLength,
        outBuffer, outOffset);
  }

  @Override
  short generate(byte[] outBuffer, short outOffset) throws CardRuntimeException {
    short length = 0;
    clear();
    allocate();
    keyPair.genKeyPair();

    TLVWriter writer = TLVWriter.getInstance();

    // We know that the worst-case of this will fit into a short-form length.
    writer.init(outBuffer, outOffset, TLV.LENGTH_1BYTE_MAX, CONST_TAG_RESPONSE);
    writer.writeTagByte(ELEMENT_ECC_POINT);
    writer.writeLength(getPublicPointLength());
    outOffset = writer.getOffset();
    outOffset += ((ECPublicKey) keyPair.getPublic()).getW(outBuffer, outOffset);
    writer.setOffset(outOffset);
    length = writer.finish();

    return length;
  }

  /**
   * ECC Keys don't have a block length but we conform to SP 800-73-4 Part 2 Para 4.1.4 and return
   * the key length
   *
   * @return the block length equal to the key length
   */
  @Override
  short getBlockLength() {
    return getKeyLengthBytes();
  }

  /**
   * The length, in bytes, of the key
   *
   * @return the length of the key
   */
  @Override
  short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
    case Constants.ID_ALG_ECC_P256:
    case Constants.ID_ALG_ECC_CS2:
      return KeyBuilder.LENGTH_EC_FP_256;

    case Constants.ID_ALG_ECC_P384:
    case Constants.ID_ALG_ECC_CS7:
      return KeyBuilder.LENGTH_EC_FP_384;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }
  }

  final short getPublicPointLength() throws ISOException {

    switch (getMechanism()) {
    case Constants.ID_ALG_ECC_P256:
    case Constants.ID_ALG_ECC_CS2:
      return ECParamsP256.PUBLIC_LENGTH_BYTES;

    case Constants.ID_ALG_ECC_P384:
    case Constants.ID_ALG_ECC_CS7:
      return ECParamsP384.PUBLIC_LENGTH_BYTES;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }
  }

  /**
   * @return true if the key is initialized with valid key values.
   */
  @Override
  boolean isInitialised() {
    return (keyPair != null && keyPair.getPrivate().isInitialized() && keyPair.getPublic().isInitialized());
  }

  @Override
  void clear() {
    if (keyPair == null)
      return;

    keyPair.getPrivate().clearKey();
    keyPair.getPublic().clearKey();
    keyPair = null;

    Platform.requestObjectDeletion();
  }

  /**
   * Curve P-256 (aka SECP256R1) domain parameters from NIST SP 800-186
   * (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf) para 4.2.1.3
   */
  static final class ECParamsP256 {

    private ECParamsP256() {
    }
    
    // The uncompressed public point length
    // NOTE: This is the 2 * KEY_LENGTH_BYTES + 1
    private static final short PUBLIC_LENGTH_BYTES = (short) 65;

    // cofactor
    static final short H = (short) 0x01;

    // Curve polynomial element a
    static final byte[] A = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFC };

    // Curve polynomial element b
    static final byte[] B = { (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93,
        (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86,
        (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0,
        (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60,
        (byte) 0x4B };

    // Base point
    static final byte[] G = { (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C,
        (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4,
        (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB,
        (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98,
        (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A,
        (byte) 0x7F, (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F,
        (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31,
        (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF,
        (byte) 0x51, (byte) 0xF5 };

    // Field definition
    static final byte[] P = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF };

    // Order n of G
    static final byte[] N = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E,
        (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25,
        (byte) 0x51 };
  }

  /**
   * Curve P-384 (aka SECP384R1) domain parameters from NIST SP 800-186
   * (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186-draft.pdf) para 4.2.1.4
   */
  static final class ECParamsP384 {

    private ECParamsP384() {
    }

    // The uncompressed public point length
    // NOTE: This is the 2 * KEY_LENGTH_BYTES + 1
    private static final short PUBLIC_LENGTH_BYTES = (short) 97;

    // cofactor
    static final short H = (short) 0x01;

    // Curve polynomial element a
    static final byte[] A = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFC };

    // Curve polynomial element b
    static final byte[] B = { (byte) 0xB3, (byte) 0x31, (byte) 0x2F, (byte) 0xA7, (byte) 0xE2, (byte) 0x3E, (byte) 0xE7,
        (byte) 0xE4, (byte) 0x98, (byte) 0x8E, (byte) 0x05, (byte) 0x6B, (byte) 0xE3, (byte) 0xF8, (byte) 0x2D,
        (byte) 0x19, (byte) 0x18, (byte) 0x1D, (byte) 0x9C, (byte) 0x6E, (byte) 0xFE, (byte) 0x81, (byte) 0x41,
        (byte) 0x12, (byte) 0x03, (byte) 0x14, (byte) 0x08, (byte) 0x8F, (byte) 0x50, (byte) 0x13, (byte) 0x87,
        (byte) 0x5A, (byte) 0xC6, (byte) 0x56, (byte) 0x39, (byte) 0x8D, (byte) 0x8A, (byte) 0x2E, (byte) 0xD1,
        (byte) 0x9D, (byte) 0x2A, (byte) 0x85, (byte) 0xC8, (byte) 0xED, (byte) 0xD3, (byte) 0xEC, (byte) 0x2A,
        (byte) 0xEF };

    // Base point
    static final byte[] G = { (byte) 0x04, (byte) 0xAA, (byte) 0x87, (byte) 0xCA, (byte) 0x22, (byte) 0xBE, (byte) 0x8B,
        (byte) 0x05, (byte) 0x37, (byte) 0x8E, (byte) 0xB1, (byte) 0xC7, (byte) 0x1E, (byte) 0xF3, (byte) 0x20,
        (byte) 0xAD, (byte) 0x74, (byte) 0x6E, (byte) 0x1D, (byte) 0x3B, (byte) 0x62, (byte) 0x8B, (byte) 0xA7,
        (byte) 0x9B, (byte) 0x98, (byte) 0x59, (byte) 0xF7, (byte) 0x41, (byte) 0xE0, (byte) 0x82, (byte) 0x54,
        (byte) 0x2A, (byte) 0x38, (byte) 0x55, (byte) 0x02, (byte) 0xF2, (byte) 0x5D, (byte) 0xBF, (byte) 0x55,
        (byte) 0x29, (byte) 0x6C, (byte) 0x3A, (byte) 0x54, (byte) 0x5E, (byte) 0x38, (byte) 0x72, (byte) 0x76,
        (byte) 0x0A, (byte) 0xB7, (byte) 0x36, (byte) 0x17, (byte) 0xDE, (byte) 0x4A, (byte) 0x96, (byte) 0x26,
        (byte) 0x2C, (byte) 0x6F, (byte) 0x5D, (byte) 0x9E, (byte) 0x98, (byte) 0xBF, (byte) 0x92, (byte) 0x92,
        (byte) 0xDC, (byte) 0x29, (byte) 0xF8, (byte) 0xF4, (byte) 0x1D, (byte) 0xBD, (byte) 0x28, (byte) 0x9A,
        (byte) 0x14, (byte) 0x7C, (byte) 0xE9, (byte) 0xDA, (byte) 0x31, (byte) 0x13, (byte) 0xB5, (byte) 0xF0,
        (byte) 0xB8, (byte) 0xC0, (byte) 0x0A, (byte) 0x60, (byte) 0xB1, (byte) 0xCE, (byte) 0x1D, (byte) 0x7E,
        (byte) 0x81, (byte) 0x9D, (byte) 0x7A, (byte) 0x43, (byte) 0x1D, (byte) 0x7C, (byte) 0x90, (byte) 0xEA,
        (byte) 0x0E, (byte) 0x5F };

    // Field Definition
    static final byte[] P = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF };

    // Order of G
    static final byte[] N = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xC7, (byte) 0x63, (byte) 0x4D, (byte) 0x81, (byte) 0xF4, (byte) 0x37, (byte) 0x2D,
        (byte) 0xDF, (byte) 0x58, (byte) 0x1A, (byte) 0x0D, (byte) 0xB2, (byte) 0x48, (byte) 0xB0, (byte) 0xA7,
        (byte) 0x7A, (byte) 0xEC, (byte) 0xEC, (byte) 0x19, (byte) 0x6A, (byte) 0xCC, (byte) 0xC5, (byte) 0x29,
        (byte) 0x73 };    
  }

}
