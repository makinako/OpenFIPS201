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
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public final class PIVKeyObjectRSA extends PIVKeyObjectPKI {

  // RSA Modulus Element
  private static final byte ELEMENT_RSA_N = (byte) 0x81;

  // RSA Public Exponent
  private static final byte ELEMENT_RSA_E = (byte) 0x82;

  // RSA Private Exponent
  private static final byte ELEMENT_RSA_D = (byte) 0x83;

  // NOTE: Currently RSA CRT keys are not used, this is a placeholder
  // private final byte ELEMENT_RSA_P = (byte) 0x91; // RSA Prime Exponent P
  // private final byte ELEMENT_RSA_Q = (byte) 0x92; // RSA Prime Exponent Q
  // private final byte ELEMENT_RSA_DP = (byte) 0x93; // RSA D mod P - 1
  // private final byte ELEMENT_RSA_DQ = (byte) 0x94; // RSA D mod Q - 1
  // private final byte ELEMENT_RSA_PQ = (byte) 0x95; // RSA Inverse Q

  // The list of ASN.1 tags for the public components
  private static final byte CONST_TAG_MODULUS = (byte) 0x81; // RSA - The modulus
  private static final byte CONST_TAG_EXPONENT = (byte) 0x82; // RSA - The public exponent
  private static final short CONST_LENGTH_EXPONENT = (short) 3; // RSA - The public exponent length

  // Cipher implementations (static so they are shared with all instances of PIVKeyObjectRSA)
  private static Cipher cipher = null;

  protected PIVKeyObjectRSA(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {
    super(id, modeContact, modeContactless, mechanism, role, attributes);

    // Check if this mechanism is supported
    if (cipher == null) ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
  }

  /*
   * Allows safe allocation of cryptographic service providers at applet instantiation
   */
  public static void createProviders() {
    if (cipher == null) {
      try {
        cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
      } catch (CryptoException ex) {
        // We couldn't create this algorithm, the card may not support it!
        cipher = null;
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
   *   <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer containing the updated element
   * @param offset first byte of the element in the buffer
   * @param length the length og the element
   */
  @Override
  public void updateElement(byte element, byte[] buffer, short offset, short length)
      throws ISOException {

    switch (element) {

        // RSA Modulus Element
      case ELEMENT_RSA_N:
        setModulus(buffer, offset, length);
        break;

        // RSA Public Exponent
      case ELEMENT_RSA_E:
        setPublicExponent(buffer, offset, length);
        break;

        // RSA Private Exponent
      case ELEMENT_RSA_D:
        setPrivateExponent(buffer, offset, length);
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
  protected void allocatePrivate() {
    if (privateKey == null) {
      privateKey =
          (PrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, getKeyLengthBits(), false);
    }
  }

  /** Clears and if necessary reallocates a public key. */
  private void allocatePublic() {
    if (publicKey == null) {
      publicKey =
          (PublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, getKeyLengthBits(), false);
    }
  }

  /** @return true if the privateKey exists and is initialized. */
  @Override
  public boolean isInitialised() {
    return (privateKey != null && privateKey.isInitialized());
  }

  @Override
  public void clear() {
    if (publicKey != null) {
      publicKey.clearKey();
      privateKey = null;
    }
    if (privateKey != null) {
      privateKey.clearKey();
      privateKey = null;
    }

    runGc();
  }

  /**
   * Writes the private exponent of RSA the key pair to the buffer
   *
   * @param buffer The destination buffer to write to
   * @param offset The starting offset to write to
   * @param length The length of the exponent to write
   */
  private void setPrivateExponent(byte[] buffer, short offset, short length) {
    if (privateKey == null) allocatePrivate();
    ((RSAPrivateKey) privateKey).setExponent(buffer, offset, length);
  }

  /**
   * Writes the public exponent of RSA the key pair to the buffer
   *
   * @param buffer The destination buffer to write to
   * @param offset The starting offset to write to
   * @param length The length of the exponent to write
   */
  public void setPublicExponent(byte[] buffer, short offset, short length) {
    if (publicKey == null) allocatePublic();
    ((RSAPublicKey) publicKey).setExponent(buffer, offset, length);
  }

  /**
   * Writes the modulus of RSA the key pair to the buffer
   *
   * @param buffer The destination buffer to write to
   * @param offset The starting offset to write to
   * @param length The length of the modulus to write
   */
  public void setModulus(byte[] buffer, short offset, short length) {
    if (length != getKeyLengthBytes()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

    if (privateKey == null) allocatePrivate();
    ((RSAPrivateKey) privateKey).setModulus(buffer, offset, length);

    if (publicKey == null) allocatePublic();
    ((RSAPublicKey) publicKey).setModulus(buffer, offset, length);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param csp the csp to do the signing.
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  @Override
  public short sign(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset)
      throws ISOException {
    if (inLength != getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

    //
    // IMPLEMENTATION NOTE:
    // If you think the operation below looks insane, that's OK. This requires explanation.
    // The PIV standard implements RSA digital signatures in a way that does not force you
    // to choose a specific padding scheme (though they recomend PKCS#1.5 or OAEP). This means
    // the client does not send the data to be signed, or even just the hash value. Instead,
    // it sends a fully-formatted block including the hash and all padding.
    //
    // The problem here is that the Javacard Signature object can only sign in two ways.
    // 1) Pass all data to update() and/or sign() which generates the hash, pads and encrypts.
    // 2) Pass the hash to signPreComputedHash() which validates the length, pads and encrypts.
    //
    // Neither of the above is suited to taking a fully-formed block, so we are left with the
    // only remaining option, which is to perform a private key encryption operation, which makes
    // us feel awkward and wrong.
    //
    // Yep, that's it.
    //
    cipher.init(privateKey, Cipher.MODE_ENCRYPT);
    return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /* Implements RSA Key Transport, which is just a private decrypt operation */
  @Override
  public short keyAgreement(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {

    if (inLength != getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    cipher.init(privateKey, Cipher.MODE_DECRYPT);
    return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  @Override
  public short generate(byte[] outBuffer, short outOffset) throws CardRuntimeException {

    KeyPair keyPair;
    try {
      // Clear any key material
      clear();

      // Allocate both parts (this only occurs if it hasn't already been allocated)
      allocatePrivate();
      allocatePublic();

      // We re-create every time generate() is called
      keyPair = new KeyPair(publicKey, privateKey);
      keyPair.genKeyPair();

      TLVWriter writer = TLVWriter.getInstance();

      // Create the TLV response with the appropriate expected length for public key + header
      if (getMechanism() == PIV.ID_ALG_RSA_1024) {
        // We can fit within a 2-byte length (128-255)
        writer.init(outBuffer, outOffset, TLV.LENGTH_2BYTE_MAX, CONST_TAG_RESPONSE);
      } else { // Mechanism == PIV.ID_ALG_RSA_2048
        // We require a 3-byte length (255-32767)
        writer.init(outBuffer, outOffset, TLV.LENGTH_3BYTE_MAX, CONST_TAG_RESPONSE);
      }

      // Modulus
      writer.writeTag(CONST_TAG_MODULUS);
      writer.writeLength(getKeyLengthBytes());

      // The modulus data must be written manually because of how RSAPublicKey works
      outOffset = writer.getOffset();
      outOffset += ((RSAPublicKey) publicKey).getModulus(outBuffer, outOffset);
      writer.setOffset(outOffset); // Move the current position forward

      // Exponent
      writer.writeTag(CONST_TAG_EXPONENT);
      writer.writeLength(CONST_LENGTH_EXPONENT);

      outOffset = writer.getOffset();
      outOffset += ((RSAPublicKey) publicKey).getExponent(outBuffer, outOffset);
      writer.setOffset(outOffset); // Move the current position forward

      // Done, return the response length
      return writer.finish();
    } catch (CardRuntimeException ex) {
      // At this point we are in a nondeterministic state so we will
      // clear both the public and private keys if they exist
      clear();
      CardRuntimeException.throwIt(ex.getReason());
      return (short) 0; // Keep compiler happy
    } finally {
      // We new'd the keyPair, so we make sure the memory is freed up once it is out of scope.
      runGc();
    }
  }

  /** @return the block length of the key. */
  @Override
  public short getBlockLength() {
    // RSA blocks are the same length as their keys
    return getKeyLengthBytes();
  }

  /** @return The length, in bytes, of the key */
  @Override
  public short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
      case PIV.ID_ALG_RSA_1024:
        return KeyBuilder.LENGTH_RSA_1024;

      case PIV.ID_ALG_RSA_2048:
        return KeyBuilder.LENGTH_RSA_2048;

      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return (short) 0; // Keep compiler happy
    }
  }
}
