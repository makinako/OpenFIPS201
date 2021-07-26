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
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/** Provides functionality for ECC PIV key objects */
public final class PIVKeyObjectECC extends PIVKeyObjectPKI {
  private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;

  // The ECC public key element tag
  private static final byte ELEMENT_ECC_POINT = (byte) 0x86;

  // The ECC private key element tag
  private static final byte ELEMENT_ECC_SECRET = (byte) 0x87;

  private final ECParams params;
  private final short marshaledPubKeyLen;

  // Cipher implementations (static so they are shared with all instances of PIVKeyObjectECC)
  private static KeyAgreement keyAgreement = null;
  private static Signature signerSHA1 = null;
  private static Signature signerSHA256 = null;
  private static Signature signerSHA384 = null;
  private static Signature signerSHA512 = null;
  private static MessageDigest digestSHA256 = null;
  private static MessageDigest digestSHA384 = null;
  private static Cipher cipherAES = null;

  protected PIVKeyObjectECC(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes)
      throws ISOException {
    super(id, modeContact, modeContactless, mechanism, role, attributes);

    // MECHANISM CHECK - SIGN
    if (hasRole(PIVKeyObject.ROLE_SIGN)
        && (signerSHA1 == null)
        && (signerSHA256 == null)
        && (signerSHA384 == null)
        && (signerSHA512 == null)) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    // MECHANISM CHECK - KEY_ESTABLISH and SECURE_MESSAGING
    if ((hasRole(PIVKeyObject.ROLE_KEY_ESTABLISH) || hasRole(PIVKeyObject.ROLE_SECURE_MESSAGING))
        && keyAgreement == null) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    switch (getMechanism()) {
      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_CS2:
        params = ECParamsP256.getInstance();
        break;
      case PIV.ID_ALG_ECC_P384:
      case PIV.ID_ALG_ECC_CS7:
        params = ECParamsP384.getInstance();
        break;
      default:
        params = null; // Keep the compiler happy
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // where the length of the X and Y coordinates is the byte length of the key.
    // TODO: We can use 2 consts and decide which to compare against based on the mechanism!
    marshaledPubKeyLen = (short) (getKeyLengthBytes() * 2 + 1);
  }

  /*
   * Allows safe allocation of cryptographic service providers at applet instantiation
   */
  public static void createProviders() {

    if (keyAgreement == null) {
      try {
        keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
      } catch (CryptoException ex) {
        keyAgreement = null;
      }
    }

    if (signerSHA1 == null) {
      try {
        signerSHA1 = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
      } catch (CryptoException ex) {
        signerSHA1 = null;
      }
    }

    if (signerSHA256 == null) {
      try {
        signerSHA256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
      } catch (CryptoException ex) {
        signerSHA256 = null;
      }
    }

    if (signerSHA384 == null) {
      try {
        signerSHA384 = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
      } catch (CryptoException ex) {
        signerSHA384 = null;
      }
    }

    if (signerSHA512 == null) {
      try {
        signerSHA512 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
      } catch (CryptoException ex) {
        signerSHA512 = null;
      }
    }

    if (digestSHA256 == null) {
      try {
        digestSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
      } catch (CryptoException ex) {
        digestSHA256 = null;
      }
    }

    if (digestSHA384 == null) {
      try {
        digestSHA384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
      } catch (CryptoException ex) {
        digestSHA384 = null;
      }
    }

    if (cipherAES == null) {
      try {
        cipherAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
      } catch (CryptoException ex) {
        cipherAES = null;
      }
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
  public void updateElement(byte element, byte[] buffer, short offset, short length)
      throws ISOException {

    switch (element) {
      case ELEMENT_ECC_POINT:
        if (length != marshaledPubKeyLen) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        // Only uncompressed points are supported
        if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
          ISOException.throwIt(ISO7816.SW_WRONG_DATA);
          return; // Keep static analyser happy
        }

        allocatePublic();

        ((ECPublicKey) publicKey).setW(buffer, offset, length);
        break;

      case ELEMENT_ECC_SECRET:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
          return; // Keep static analyser happy
        }

        allocatePrivate();

        ((ECPrivateKey) privateKey).setS(buffer, offset, length);
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
          (PrivateKey)
              KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, getKeyLengthBits(), false);
      setPrivateParams();
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (PublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, getKeyLengthBits(), false);
      setPublicParams();
    }
  }

  @Override
  public short generate(byte[] scratch, short offset) throws CardRuntimeException {

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
      writer.writeLength(marshaledPubKeyLen);
      offset = writer.getOffset();
      offset += ((ECPublicKey) publicKey).getW(scratch, offset);

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
  public short getBlockLength() {
    return getKeyLengthBytes();
  }

  /**
   * The length, in bytes, of the key
   *
   * @return the length of the key
   */
  @Override
  public short getKeyLengthBits() throws ISOException {
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

  /** @return true if the privateKey exists and is initialized. */
  @Override
  public boolean isInitialised() {

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
  public void clear() {
    if (publicKey != null) {
      publicKey.clearKey();
      publicKey = null;
    }
    if (privateKey != null) {
      privateKey.clearKey();
      privateKey = null;
    }
  }

  /** Set ECC domain parameters. */
  private void setPrivateParams() {

    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPrivateKey) privateKey).setA(a, (short) 0, (short) a.length);
    ((ECPrivateKey) privateKey).setB(b, (short) 0, (short) b.length);
    ((ECPrivateKey) privateKey).setG(g, (short) 0, (short) g.length);
    ((ECPrivateKey) privateKey).setR(r, (short) 0, (short) r.length);
    ((ECPrivateKey) privateKey).setFieldFP(p, (short) 0, (short) p.length);
    ((ECPrivateKey) privateKey).setK(params.getH());
  }

  /** Set ECC domain parameters. */
  private void setPublicParams() {
    byte[] a = params.getA();
    byte[] b = params.getB();
    byte[] g = params.getG();
    byte[] p = params.getP();
    byte[] r = params.getN();

    ((ECPublicKey) publicKey).setA(a, (short) 0, (short) a.length);
    ((ECPublicKey) publicKey).setB(b, (short) 0, (short) b.length);
    ((ECPublicKey) publicKey).setG(g, (short) 0, (short) g.length);
    ((ECPublicKey) publicKey).setR(r, (short) 0, (short) r.length);
    ((ECPublicKey) publicKey).setFieldFP(p, (short) 0, (short) p.length);
    ((ECPublicKey) publicKey).setK(params.getH());
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
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    if (inLength != marshaledPubKeyLen) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    keyAgreement.init(privateKey);
    return keyAgreement.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
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
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {

    Signature signer = null;

    switch (inLength) {
      case MessageDigest.LENGTH_SHA:
        signer = signerSHA1;
        break;
      case MessageDigest.LENGTH_SHA_256:
        signer = signerSHA256;
        break;
      case MessageDigest.LENGTH_SHA_384:
        signer = signerSHA384;
        break;
      case MessageDigest.LENGTH_SHA_512:
        signer = signerSHA512;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return (short) 0; // Keep compiler happy
    }

    signer.init(privateKey, Signature.MODE_SIGN);
    return signer.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }
}
