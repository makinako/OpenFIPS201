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

package com.makina.security.OpenFIPS201;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.*;

/** Provides functionality for ECC PIV key objects */
public final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  private final ECParams params;
  private final short marshaledPubKeyLen;

  public PIVKeyObjectECC(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
    super(id, modeContact, modeContactless, mechanism, role);

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
        params = ECParamsP256.Instance();
        break;
      case PIV.ID_ALG_ECC_P384:
        params = ECParamsP384.Instance();
        break;
      default:
        params = null; // Keep the compiler happy
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // where the length of the X and Y coordinates is the byte length of the key.
    marshaledPubKeyLen = (short) (getKeyLengthBytes() * 2 + 1);
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
  public void updateElement(byte element, byte[] buffer, short offset, short length) {
    switch (element) {
      case ELEMENT_ECC_POINT:
        if (length != marshaledPubKeyLen) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Only uncompressed points are supported
        if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        allocatePublic();
        ((ECPublicKey) publicKey).setW(buffer, offset, length);
        break;

      case ELEMENT_ECC_SECRET:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // ECC Private Key
        allocatePrivate();
        ((ECPrivateKey) privateKey).setS(buffer, offset, length);
        break;

        // Clear Key
      case ELEMENT_CLEAR:
        clear();
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        break;
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
  public short keyAgreement(
      KeyAgreement csp,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    if (inLength != marshaledPubKeyLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    csp.init(privateKey);
    return csp.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param csp the csp that does the signing.
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length of the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  @Override
  public short sign(
      Object csp,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    ((Signature) csp).init(privateKey, Signature.MODE_SIGN);
    return ((Signature) csp)
        .signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * The public key marshaled per ANSI X9.62
   *
   * @param pubKey the publicKey to marshal
   * @param scratch the buffer to marshal the key to
   * @param offset the location of the first byte of the marshalled key
   * @return the length of the marshaled public key
   */
  @Override
  public short marshalPublic(PublicKey pubKey, byte[] scratch, short offset) {
    pubKeyWriter.reset();
    // adding 5 bytes to the marshaled key to account for other APDU overhead.
    pubKeyWriter.init(scratch, offset, (short) (marshaledPubKeyLen + 5), CONST_TAG_RESPONSE);
    pubKeyWriter.writeTag(ELEMENT_ECC_POINT);
    pubKeyWriter.writeLength(marshaledPubKeyLen);
    offset = pubKeyWriter.getOffset();
    offset += ((ECPublicKey) pubKey).getW(scratch, offset);

    pubKeyWriter.setOffset(offset);
    return pubKeyWriter.finish();
  }

  /**
   * ECC Keys don't have a block length but we conform to SP 800-73-4 Part 2 Para 4.1.4 and return
   * the key length
   *
   * @return the block length equal to the key length
   */
  @Override
  public short getBlockLength() {
    return getKeyLengthBytes();
  }

  /**
   * The length, in bytes, of the key
   *
   * @return the length of the key
   */
  @Override
  public short getKeyLengthBits() {
    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
        return KeyBuilder.LENGTH_EC_FP_256;

      case PIV.ID_ALG_ECC_P384:
        return KeyBuilder.LENGTH_EC_FP_384;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }

  /** Clears and reallocates a private key. */
  @Override
  protected void allocatePrivate() {
    clearPrivate();
    privateKey =
        (PrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);
    setPrivateParams();
  }

  /** Clears and if necessary reallocates a public key. */
  @Override
  protected void allocatePublic() {
    clearPublic();
    publicKey =
        (PublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
    setPublicParams();
  }

  /** Set ECC domain parameters. */
  private void setPrivateParams() {

    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPrivateKey) privateKey).setA(a, (short) 0, (short) (a.length));
    ((ECPrivateKey) privateKey).setB(b, (short) 0, (short) (b.length));
    ((ECPrivateKey) privateKey).setG(g, (short) 0, (short) (g.length));
    ((ECPrivateKey) privateKey).setR(r, (short) 0, (short) (r.length));
    ((ECPrivateKey) privateKey).setFieldFP(p, (short) 0, (short) (p.length));
    ((ECPrivateKey) privateKey).setK(params.getH());
  }

  /** Set ECC domain parameters. */
  protected void setPublicParams() {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPublicKey) publicKey).setA(a, (short) 0, (short) (a.length));
    ((ECPublicKey) publicKey).setB(b, (short) 0, (short) (b.length));
    ((ECPublicKey) publicKey).setG(g, (short) 0, (short) (g.length));
    ((ECPublicKey) publicKey).setR(r, (short) 0, (short) (r.length));
    ((ECPublicKey) publicKey).setFieldFP(p, (short) 0, (short) (p.length));
    ((ECPublicKey) publicKey).setK(params.getH());
  }
}
