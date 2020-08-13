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

import javacard.security.*;

public abstract class PIVKeyObjectPKI extends PIVKeyObject {
  public static final byte ELEMENT_CLEAR = (byte) 0xFF;
  public final short CONST_TAG_RESPONSE = (short) 0x7F49;
  protected PrivateKey privateKey;
  protected PublicKey publicKey;

  protected PIVKeyObjectPKI(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
    super(id, modeContact, modeContactless, mechanism, role);
  }

  /** @return true */
  @Override
  public boolean isAsymmetric() {
    return true;
  }

  /**
   * Clears the keypair elements if they exist and frees the ref to the private key.
   *
   * <p>Note: If the card does not support ObjectDeletion, repeatedly calling this method may
   * exhaust NV RAM.
   */
  @Override
  public void clear() {
    clearPrivate();
    clearPublic();
  }

  /** @return true if the privateKey exists and is initialized. */
  @Override
  public boolean isInitialised() {
    return (privateKey != null && privateKey.isInitialized());
  }

  /**
   * Clears any existing keys and allocates new public and private key objects. The publicKey object
   * is reused if it exists and is of the same type and length as that being requested. Otherwise it
   * is cleared and recreated.
   *
   * <p>Note: If the card does not support Object deletion, repeatedly calling this method may
   * exhaust NV RAM.
   *
   * @param publicKeyType the type of public key to generate from KeyBuilder.Type_ ...
   * @param privateKeyType the type of private key to generate from KeyBuilder.Type_ ...
   * @param keyLength the length of key to generate in bits from KeyBuilder.LENGTH_ ...
   */
  protected void allocate(byte publicKeyType, byte privateKeyType, short keyLength) {
    allocatePrivate(privateKeyType, keyLength);
    allocatePublic(publicKeyType, keyLength);
  }

  /**
   * Clears and reallocates a private key.
   *
   * @param privateKeyType the type of private key to generate from KeyBuilder.Type_ ...
   * @param keyLength the length of key to generate in bits from KeyBuilder.LENGTH_ ...
   */
  protected void allocatePrivate(byte privateKeyType, short keyLength) {
    clearPrivate();
    privateKey = (PrivateKey) KeyBuilder.buildKey(privateKeyType, keyLength, false);
  }

  /**
   * Clears and if necessary reallocates a public key.
   *
   * @param publicKeyType the type of private key to generate from KeyBuilder.Type_ ...
   * @param keyLength the length of key to generate in bits from KeyBuilder.LENGTH_ ...
   */
  protected void allocatePublic(byte publicKeyType, short keyLength) {
    clearPublic();
    publicKey = (PublicKey) KeyBuilder.buildKey(publicKeyType, keyLength, false);
  }

  /**
   * Generates a new random keypair.
   *
   * <p>Note: If the card does not support Object deletion, repeatedly calling this method may
   * exhaust NV RAM.
   */
  public short generate(byte[] scratch, short offset) {
    allocate();

    // Normally we only "new" objects in a constructor but in this case
    // we cannot new the generator until the privateKey and publicKey
    // objects exist which happens in allocate which is called outside the
    // context of any constructor.
    new KeyPair(publicKey, privateKey).genKeyPair();

    short length = marshalPublic(scratch, offset);

    // There is generally no reason to keep a public key around other
    // than in an X.509 certificate.
    //
    // If the use case requires that it be kept the user can simply write
    // it back to the card.
    clearPublic();
    return length;
  }

  /** Clears and dereferences the private key */
  private void clearPrivate() {
    if (privateKey != null) {
      privateKey.clearKey();
      privateKey = null;
      runGc();
    }
  }

  /** Clears the public key */
  private void clearPublic() {
    if (publicKey != null) {
      publicKey.clearKey();
      publicKey = null;
      runGc();
    }
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param csp the csp that will do the signing.
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  public abstract short sign(
      Object csp,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset);

  /**
   * Performs a key agreement
   *
   * @param csp the csp to do the key agreement.
   * @param inBuffer the public key of the other party
   * @param inOffset the the location of first byte of the public key
   * @param inLength the length of the public key
   * @param outBuffer the computed secret
   * @param outOffset the location of the first byte of the computed secret
   * @return the length of the computed secret
   */
  public abstract short keyAgreement(
      KeyAgreement csp,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset);

  /**
   * Marshals a public key
   *
   * @param scratch the buffer to marshal the key to
   * @param offset the location of the first byte of the marshalled key
   * @return the length of the marshalled public key
   */
  protected abstract short marshalPublic(byte[] scratch, short offset);
}
