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

import javacard.security.PrivateKey;
import javacard.security.PublicKey;

public abstract class PIVKeyObjectPKI extends PIVKeyObject {

  protected static final short CONST_TAG_RESPONSE = (short) 0x7F49;

  protected PrivateKey privateKey = null;
  protected PublicKey publicKey = null;

  protected PIVKeyObjectPKI(
      byte id, byte modeContact, byte modeContactless, byte mechanism, byte role, byte attributes) {
    super(id, modeContact, modeContactless, mechanism, role, attributes);
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
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

  /**
   * Performs a key agreement
   *
   * @param csp the csp to do the key agreement.
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  public abstract short keyAgreement(
      byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset);

  /**
   * Generates a new asymmetric key pair and returns the public component.
   *
   * @param scratch the output buffer to hold the generated public component
   * @param offset the starting position of the output buffer
   */
  public abstract short generate(byte[] outBuffer, short outOffset);
}
