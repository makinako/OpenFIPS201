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
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

final class PIVKeyRSA extends PIVKeyPKI {

  // RSA Modulus Element
  private static final byte ELEMENT_RSA_N = (byte) 0x81;

  // RSA Public Exponent
  private static final byte ELEMENT_RSA_E = (byte) 0x82;

  // RSA Private Exponent
  private static final byte ELEMENT_RSA_D = (byte) 0x83;

  // RSA Prime Exponent P
  private static final byte ELEMENT_RSA_P = (byte) 0x90;

  // RSA Prime Exponent Q
  private static final byte ELEMENT_RSA_Q = (byte) 0x91;

  // RSA D mod P - 1
  private static final byte ELEMENT_RSA_DP = (byte) 0x92;

  // RSA D mod Q - 1
  private static final byte ELEMENT_RSA_DQ = (byte) 0x93;

  // RSA Inverse Q
  private static final byte ELEMENT_RSA_PQ = (byte) 0x94;

  // The list of ASN.1 tags for the public components written in the generate
  // response
  private static final byte CONST_TAG_MODULUS = (byte) 0x81; // RSA - The modulus
  private static final byte CONST_TAG_EXPONENT = (byte) 0x82; // RSA - The public exponent
  private static final short CONST_LENGTH_EXPONENT = (short) 3; // RSA - The public exponent length

  // PERSISTENT - The key store
  private KeyPair keyPair;

  PIVKeyRSA(int id, byte modeContact, byte modeContactless, byte adminKey, byte mechanism,
      byte role, byte attributes) {
    super(id, modeContact, modeContactless, adminKey, mechanism, role, attributes);
    // Attribute Check - The ROLE_SIGN role must not be set for RSA_1024 keys
    if ((mechanism == Constants.ID_ALG_RSA_1024)
        && (role & ROLE_SIGN) != 0) {
      ISOException.throwIt(ISO7816.SW_WRONG_DATA);
    }
  }

  /**
   * Updates the elements of the keypair with new values.
   *
   * <p>
   * Notes:
   * <ul>
   * <li>If the card does not support ObjectDeletion, repeatedly calling this method may exhaust NV
   * RAM.
   * <li>Updating only one element may render the card in a non-deterministic state
   * </ul>
   *
   * @param element the element to update
   * @param buffer  containing the updated element
   * @param offset  first byte of the element in the buffer
   * @param length  the length og the element
   */
  // @Override
  @Override
  void update(byte element, byte[] buffer, short offset, short length) throws ISOException {

    // PRE-CONDITION 1 - If the key is initialised, it must be explicitly cleared
    // first
    if (isInitialised() && element != ELEMENT_CLEAR) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    } else {
      // Ensure that the key objects are allocated
      // NOTE: Even if an invalid element is supplied, any call to updateElement()
      // will result
      // in the allocation of memory for the key object.
      allocate();
    }

    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

    if (keyPair.getPrivate() instanceof RSAPrivateCrtKey) {
      // RSA-CRT
      RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyPair.getPrivate();

      switch (element) {

      // RSA Modulus Element
      case ELEMENT_RSA_N:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        publicKey.setModulus(buffer, offset, length);
        break;

      // RSA Public Exponent
      case ELEMENT_RSA_E:
        if (length != CONST_LENGTH_EXPONENT) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        publicKey.setExponent(buffer, offset, length);
        break;

      // RSA Prime Exponent P
      case ELEMENT_RSA_P:
        if (length != (short) (getKeyLengthBytes() / 2)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setP(buffer, offset, length);
        break;

      // RSA Prime Exponent Q
      case ELEMENT_RSA_Q:
        if (length != (short) (getKeyLengthBytes() / 2)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setQ(buffer, offset, length);
        break;

      // RSA D mod P - 1
      case ELEMENT_RSA_DP:
        if (length != (short) (getKeyLengthBytes() / 2)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setDP1(buffer, offset, length);
        break;

      // RSA D mod Q - 1
      case ELEMENT_RSA_DQ:
        if (length != (short) (getKeyLengthBytes() / 2)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setDQ1(buffer, offset, length);
        break;

      // RSA Inverse Q
      case ELEMENT_RSA_PQ:
        if (length != (short) (getKeyLengthBytes() / 2)) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setPQ(buffer, offset, length);
        break;

      default:
        // Fall back
        super.update(element, buffer, offset, length);
        break;
      }
    } else {
      // RSA
      RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

      switch (element) {

      // RSA Modulus Element
      case ELEMENT_RSA_N:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // NOTE: We don't worry about transactions here since if this is torn between
        // writes, the caller can send it again
        privateKey.setModulus(buffer, offset, length);
        publicKey.setModulus(buffer, offset, length);
        break;

      // RSA Public Exponent
      case ELEMENT_RSA_E:
        if (length != CONST_LENGTH_EXPONENT) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        publicKey.setExponent(buffer, offset, length);
        break;

      // RSA Private Exponent
      case ELEMENT_RSA_D:
        if (length != getKeyLengthBytes()) {
          ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        privateKey.setExponent(buffer, offset, length);
        break;

      default:
        // Fall back
        super.update(element, buffer, offset, length);
        break;
      }

    }
  }

  /***
   * Allocates memory for the private and public key parts
   */
  private void allocate() {
    if (keyPair == null) {
      // Generate the key based on our configuration
      RSAPublicKey publicKey = (RSAPublicKey) Platform.Cryptography.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, getKeyLengthBits());
      if (hasAttribute(ATTR_RSA_CRT)) {
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) Platform.Cryptography.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, getKeyLengthBits());
        keyPair = new KeyPair(publicKey, privateKey);
      } else {
        RSAPrivateKey privateKey = (RSAPrivateKey) Platform.Cryptography.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, getKeyLengthBits());
        keyPair = new KeyPair(publicKey, privateKey);
      }
    }
  }

  /**
   * @return true if the privateKey exists and is initialized.
   */
  @Override
  boolean isInitialised() {
    return (keyPair != null && keyPair.getPrivate().isInitialized()
        && keyPair.getPublic().isInitialized());
  }

  @Override
  void clear() {
    if (keyPair == null) {
      return;
    }

    keyPair.getPrivate().clearKey();
    keyPair.getPublic().clearKey();
    keyPair = null;

    Platform.requestObjectDeletion();
  }

  @Override
  short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
    // PRE-CONDITION 1 - The length must be equal to the block length
    if (inLength != getBlockLength()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // EXECUTION
    return Platform.Cryptography.computeRSADP1(keyPair.getPrivate(), inBuffer, inOffset, inLength,
        outBuffer, outOffset);
  }

  @Override
  short keyEstablish(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
      short outOffset) {
    // NOTE: For RSA both sign() and keyEstablish() only perform the RSADP1
    // primitive
    return sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  @Override
  short generate(byte[] outBuffer, short outOffset) throws CardRuntimeException {

    try {
      // Clear and allocate the key objects
      clear();
      allocate();
      keyPair.genKeyPair();

      TLVWriter writer = TLVWriter.getInstance();

      // Create the TLV response with the appropriate expected length for public key +
      // header
      if (getMechanism() == Constants.ID_ALG_RSA_1024) {
        // We can fit within a 2-byte length (128-255)
        writer.init(outBuffer, outOffset, TLV.LENGTH_2BYTE_MAX, CONST_TAG_RESPONSE);
      } else { // Mechanism == Config.ID_ALG_RSA_2048 ||
        // Mechanism == Config.ID_ALG_RSA_3072 ||
        // Mechanism == Config.ID_ALG_RSA_4096 ||
        // We require a 3-byte length (255-32767)
        writer.init(outBuffer, outOffset, TLV.LENGTH_3BYTE_MAX, CONST_TAG_RESPONSE);
      }

      RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

      // Modulus
      writer.writeTagByte(CONST_TAG_MODULUS);
      writer.writeLength(getKeyLengthBytes());

      // The modulus data must be written manually because of how RSAPublicKey works
      outOffset = writer.getOffset();
      outOffset += publicKey.getModulus(outBuffer, outOffset);
      writer.setOffset(outOffset); // Move the current position forward

      // Exponent
      writer.writeTagByte(CONST_TAG_EXPONENT);
      writer.writeLength(CONST_LENGTH_EXPONENT);

      //
      // FIPS140:
      // This PSP is zeroised when the PIVAPDU buffer is reset once it has sent.
      outOffset = writer.getOffset();
      outOffset += publicKey.getExponent(outBuffer, outOffset);
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
      // We new'd the keyPair, so we make sure the memory is freed up once it is out
      // of scope.
      Platform.requestObjectDeletion();
    }
  }

  /**
   * @return the block length of the key.
   */
  // @Override
  @Override
  short getBlockLength() {
    // RSA blocks are the same length as their keys
    return getKeyLengthBytes();
  }

  /**
   * @return The length, in bits, of the key
   */
  // @Override
  @Override
  short getKeyLengthBits() throws ISOException {
    switch (getMechanism()) {
    case Constants.ID_ALG_RSA_1024:
      return KeyBuilder.LENGTH_RSA_1024;

    case Constants.ID_ALG_RSA_2048:
      return KeyBuilder.LENGTH_RSA_2048;

    case Constants.ID_ALG_RSA_3072:
      return (short)3072; // Constant doesn't exist in 3.0.4

    case Constants.ID_ALG_RSA_4096:
      return KeyBuilder.LENGTH_RSA_4096;

    default:
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      return (short) 0; // Keep compiler happy
    }
  }
}
