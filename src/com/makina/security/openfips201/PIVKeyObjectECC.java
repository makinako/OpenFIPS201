/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.openfips201;

import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/** Provides functionality for ECC PIV key objects */
final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  private ECPrivateKey privateKey = null;
  private ECPublicKey publicKey = null;

  PIVKeyObjectECC(
      byte id,
      byte modeContact,
      byte modeContactless,
      byte adminKey,
      byte mechanism,
      byte role,
      byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
      	// Do nothing, just a mechanism check
        break;
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
  }

  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>Notes:
   *
   * <ul>
   *   <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust
   *       NV RAM.
   *   <li>The ELEMENT_ECC_POINT element must be formatted as an octet string as per ANSI X9.62.
   *   <li>The ELEMENT_ECC_SECRET must be formatted as a big-endian, right-aligned big number.
   *   <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer containing the updated element
   * @param offset first byte of the element in the buffer
   * @param length the length of the element
   */
  @Override
  void updateElement(byte element, byte[] buffer, short offset, short length) throws ISOException {

    switch (element) {
      case ELEMENT_ECC_POINT:
        if (length != getPublicPointLength()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        // Only uncompressed points are supported
        if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return; // Keep static analyser happy
        }

        allocatePublic();

        publicKey.setW(buffer, offset, length);
        break;

      case ELEMENT_ECC_SECRET:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        allocatePrivate();

        privateKey.setS(buffer, offset, length);
        break;

        // Clear all key parts
      case ELEMENT_CLEAR:
        clear();
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
    }
  }

  /** Clears and reallocates a private key. */
  private void allocatePrivate() {
    if (privateKey == null) {
      privateKey =
          (ECPrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
		privateKey.setA(ECParamsP256.A, (short) 0, (short) ECParamsP256.A.length);
		privateKey.setB(ECParamsP256.B, (short) 0, (short) ECParamsP256.B.length);
		privateKey.setG(ECParamsP256.G, (short) 0, (short) ECParamsP256.G.length);
		privateKey.setR(ECParamsP256.N, (short) 0, (short) ECParamsP256.N.length);
		privateKey.setFieldFP(ECParamsP256.P, (short) 0, (short) ECParamsP256.P.length);
		privateKey.setK(ECParamsP256.H);
		break;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
		privateKey.setA(ECParamsP384.A, (short) 0, (short) ECParamsP384.A.length);
		privateKey.setB(ECParamsP384.B, (short) 0, (short) ECParamsP384.B.length);
		privateKey.setG(ECParamsP384.G, (short) 0, (short) ECParamsP384.G.length);
		privateKey.setR(ECParamsP384.N, (short) 0, (short) ECParamsP384.N.length);
		privateKey.setFieldFP(ECParamsP384.P, (short) 0, (short) ECParamsP384.P.length);
		privateKey.setK(ECParamsP384.H);
		break;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	  }
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (ECPublicKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
              
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
		publicKey.setA(ECParamsP256.A, (short) 0, (short) ECParamsP256.A.length);
		publicKey.setB(ECParamsP256.B, (short) 0, (short) ECParamsP256.B.length);
		publicKey.setG(ECParamsP256.G, (short) 0, (short) ECParamsP256.G.length);
		publicKey.setR(ECParamsP256.N, (short) 0, (short) ECParamsP256.N.length);
		publicKey.setFieldFP(ECParamsP256.P, (short) 0, (short) ECParamsP256.P.length);
		publicKey.setK(ECParamsP256.H);
		break;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
		publicKey.setA(ECParamsP384.A, (short) 0, (short) ECParamsP384.A.length);
		publicKey.setB(ECParamsP384.B, (short) 0, (short) ECParamsP384.B.length);
		publicKey.setG(ECParamsP384.G, (short) 0, (short) ECParamsP384.G.length);
		publicKey.setR(ECParamsP384.N, (short) 0, (short) ECParamsP384.N.length);
		publicKey.setFieldFP(ECParamsP384.P, (short) 0, (short) ECParamsP384.P.length);
		publicKey.setK(ECParamsP384.H);
		break;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
	  }
    }
  }

  @Override
  short generate(byte[] scratch, short offset) throws CardRuntimeException {

    KeyPair keyPair;
    short length = 0;
    try {
      // Clear any key material
      clear();

      // Allocate both parts (this only occurs if it hasn't already been allocated)
      allocatePrivate();
      allocatePublic();

      // Since the call to clear() will delete this object automatically, it is safe to re-create
      keyPair = new KeyPair(publicKey, privateKey);
      keyPair.genKeyPair();

      TLVWriter writer = TLVWriter.getInstance();

      // We know that the worst-case of this will fit into a short-form length.
      writer.init(scratch, offset, TLV.LENGTH_1BYTE_MAX, CONST_TAG_RESPONSE);
      writer.writeTag(ELEMENT_ECC_POINT);
      writer.writeLength(getPublicPointLength());
      offset = writer.getOffset();
      offset += (publicKey).getW(scratch, offset);

      writer.setOffset(offset);
      length = writer.finish();
    } catch (CardRuntimeException cre) {
      // At this point we are in a nondeterministic state so we will
      // clear both the public and private keys if they exist
      clear();
      CardRuntimeException.throwIt(cre.getReason());
    } finally {
      // We new'd the keyPair, so we make sure the memory is freed up once it is out of scope.
      runGc();
    }

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
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        return KeyBuilder.LENGTH_EC_FP_256;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        return KeyBuilder.LENGTH_EC_FP_384;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }
  
  short getPublicPointLength() throws ISOException {
	  
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        return ECParamsP256.PUBLIC_LENGTH_BYTES;

      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        return ECParamsP384.PUBLIC_LENGTH_BYTES;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
	  
  }

  /**
   * @return true if the privateKey exists and is initialized.
   */
  @Override
  boolean isInitialised() {

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        return (privateKey != null && privateKey.isInitialized());

      case PIV.ID_ALG_ECC_CS2:
      case PIV.ID_ALG_ECC_CS7:
        // At a minimum we need the private key AND the Card Verifiable Certificate object
        return (privateKey != null && privateKey.isInitialized());

      default:
        return false; // Satisfy the compiler
    }
  }

  @Override
  void clear() {
    if (publicKey != null) {
      publicKey.clearKey();
      publicKey = null;
    }
    if (privateKey != null) {
      privateKey.clearKey();
      privateKey = null;
    }
  }

  /**
   * Performs an ECDH key agreement
   *
   * @param inBuffer the public key of the other party
   * @param inOffset the the location of first byte of the public key
   * @param inLength the length of the public key
   * @param outBuffer the computed secret
   * @param outOffset the location of the first byte of the computed secret
   * @return the length of the computed secret
   */
  @Override
  short keyAgreement(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {
    return PIVCrypto.doKeyAgreement(privateKey, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length of the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  @Override
  short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {
    return PIVCrypto.doSign(privateKey, inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
}
