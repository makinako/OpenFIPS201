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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

final class PIVCrypto {

  private PIVCrypto() {}

  //
  // Goals of this class:
  // - Provide a simple way to to access the required PIV crypto operations
  // - Provide simple de-coupling between 3.0.4 and 3.0.5 JCRE
  // - Prevent encryption keys from being generally exposed to the PIV application
  // - Prevent the need for static access to crypto primitives that could be misused (i.e. start an
  // operation, switch applets, abuse the crypto mid-operation)
  // - Fix the applet instance deletion problem identified by @dmercer

  //
  // Crypto Constants
  //
  static final short LENGTH_BLOCK_AES = (short) 16;
  static final short LENGTH_BLOCK_TDEA = (short) 8;

  static final short LENGTH_PUBLIC_EC_256 = (short) 65;
  static final short LENGTH_PUBLIC_EC_384 = (short) 97;

  static final byte CONST_EC_POINT_UNCOMPRESSED = (byte) 4;

  //
  // Crypto Providers
  //
  private static Cipher cspTDEA;
  private static Cipher cspRSA;
  private static Cipher cspAES;

  private static MessageDigest cspSHA256;
  private static MessageDigest cspSHA384;

  private static KeyAgreement cspECDH;

  private static Signature cspECCSHA1;
  private static Signature cspECCSHA256;
  private static Signature cspECCSHA384;
  private static Signature cspECCSHA512;

  private static RandomData cspRNG;

  static void terminate() {
    cspRNG = null;
    cspTDEA = null;
    cspAES = null;
    cspRSA = null;
    cspECDH = null;
    cspECCSHA1 = null;
    cspECCSHA256 = null;
    cspECCSHA384 = null;
    cspECCSHA512 = null;
    cspSHA256 = null;
    cspSHA384 = null;

    JCSystem.requestObjectDeletion();
  }

  static void init() {
    // Create all CSP's

    // Mandatory - RNG
    try {
      cspRNG = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    } catch (CryptoException ex) {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }

    try {
      cspTDEA = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
    } catch (CryptoException ex) {
      // We couldn't create this algorithm, the card may not support it!
      cspTDEA = null;
    }

    try {
      cspAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    } catch (CryptoException ex) {
      // We couldn't create this algorithm, the card may not support it!
      cspAES = null;
    }

    if (cspRSA == null) {
      try {
        cspRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
      } catch (CryptoException ex) {
        // We couldn't create this algorithm, the card may not support it!
        cspRSA = null;
      }
    }

    if (cspECDH == null) {
      try {
        cspECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
      } catch (CryptoException ex) {
        cspECDH = null;
      }
    }

    if (cspECCSHA1 == null) {
      try {
        cspECCSHA1 = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
      } catch (CryptoException ex) {
        cspECCSHA1 = null;
      }
    }

    if (cspECCSHA256 == null) {
      try {
        cspECCSHA256 = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
      } catch (CryptoException ex) {
        cspECCSHA256 = null;
      }
    }

    if (cspECCSHA384 == null) {
      try {
        cspECCSHA384 = Signature.getInstance(Signature.ALG_ECDSA_SHA_384, false);
      } catch (CryptoException ex) {
        cspECCSHA384 = null;
      }
    }

    if (cspECCSHA512 == null) {
      try {
        cspECCSHA512 = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
      } catch (CryptoException ex) {
        cspECCSHA512 = null;
      }
    }

    if (cspSHA256 == null) {
      try {
        cspSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
      } catch (CryptoException ex) {
        cspSHA256 = null;
      }
    }

    if (cspSHA384 == null) {
      try {
        cspSHA384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
      } catch (CryptoException ex) {
        cspSHA384 = null;
      }
    }
  }

  static boolean supportsMechanism(byte mechanism) {

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
        return (cspTDEA != null);

      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return (cspAES != null);

      case PIV.ID_ALG_RSA_1024:
      case PIV.ID_ALG_RSA_2048:
        return (cspRSA != null);

      case PIV.ID_ALG_ECC_P256:
      case PIV.ID_ALG_ECC_P384:
        return ((cspECCSHA1 != null)
            || (cspECCSHA256 != null)
            || (cspECCSHA384 != null)
            || (cspECCSHA512 != null)
            || (cspECDH != null));

      case PIV.ID_ALG_ECC_CS2:
        return (cspECDH != null && cspSHA256 != null);

      case PIV.ID_ALG_ECC_CS7:
        return (cspECDH != null && cspSHA384 != null);

      default:
        return false;
    }
  }

  static boolean isSymmetricMechanism(byte mechanism) {

    switch (mechanism) {
      case PIV.ID_ALG_DEFAULT:
      case PIV.ID_ALG_TDEA_3KEY:
      case PIV.ID_ALG_AES_128:
      case PIV.ID_ALG_AES_192:
      case PIV.ID_ALG_AES_256:
        return true;

      default:
        return false;
    }
  }

  /**
   * Performs a symmetric encryption operation on the supplied data
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the encrypted block
   */
  static short doEncrypt(
      SecretKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset)
      throws ISOException {

    // PRE-CONDITION 1 - If the input and output buffers are equal, we must not clobber the input
    // From the Javacard Cipher documentation:
    // When using block-aligned data (multiple of block size), if the input buffer, inBuff and
    // the output buffer, outBuff are the same array, then the output data area must not
    // partially overlap the input data area such that the input data is modified before it is
    // used; if inBuff==outBuff and inOffset < outOffset < inOffset+inLength, incorrect output
    // may result.
    if ((inBuffer == outBuffer)
        && (inOffset < outOffset)
        && (outOffset < (short) (inOffset + inLength))) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    Cipher cipher = null;

    // If the mechanism was incorrect, or the cipher was not instantiated then fail
    if (theKey instanceof AESKey) {
      cipher = cspAES;
    } else if (theKey instanceof DESKey) {
      cipher = cspTDEA;
    } else {
      ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
      return (short) 0;
    }

    cipher.init(theKey, Cipher.MODE_ENCRYPT);
    return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs the passed precomputed hash
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  static short doSign(
      ECPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    Signature signer = null;

    switch (inLength) {
      case MessageDigest.LENGTH_SHA:
        signer = cspECCSHA1;
        break;
      case MessageDigest.LENGTH_SHA_256:
        signer = cspECCSHA256;
        break;
      case MessageDigest.LENGTH_SHA_384:
        signer = cspECCSHA384;
        break;
      case MessageDigest.LENGTH_SHA_512:
        signer = cspECCSHA512;
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return (short) 0; // Keep compiler happy
    }

    signer.init(theKey, Signature.MODE_SIGN);
    return signer.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs a pre-formatted block of data using an RSA CRT private key operation.
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  static short doSign(
      RSAPrivateCrtKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
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
    cspRSA.init(theKey, Cipher.MODE_ENCRYPT);
    return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Signs a pre-formatted block of data using an RSA private key operation.
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer contains the precomputed hash
   * @param inOffset the location of the first byte of the hash
   * @param inLength the length og the computed hash
   * @param outBuffer the buffer to contain the signature
   * @param outOffset the location of the first byte of the signature
   * @return the length of the signature
   */
  static short doSign(
      RSAPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
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
    cspRSA.init(theKey, Cipher.MODE_ENCRYPT);
    return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
  }

  /**
   * Performs a key agreement operation
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  static short doKeyAgreement(
      ECPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {

    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // TODO: If there is something that specifies the JCVM/JCRE must check the length then we
    // can ditch these checks
    if (((theKey.getSize() == KeyBuilder.LENGTH_EC_FP_256) && (inLength != LENGTH_PUBLIC_EC_256))
        || ((theKey.getSize() == KeyBuilder.LENGTH_EC_FP_384)
            && (inLength != LENGTH_PUBLIC_EC_384))) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      return (short) 0; // Keep compiler happy
    } else {
      cspECDH.init(theKey);
      return cspECDH.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }
  }

  /**
   * Performs an RSA Key Transport operation, which is effectively a decryption of a pre-formatted
   * RSA block with the private key.
   *
   * @param theKey The key to perform the operation with
   * @param inBuffer the input to the key agreement operation
   * @param inOffset the the location of first byte of the key agreement input
   * @param inLength the length of the key agreement input
   * @param outBuffer the key agreement output
   * @param outOffset the location of the first byte of the key agreement output
   * @return the length of the key agreement output
   */
  static short doKeyTransport(
      RSAPrivateKey theKey,
      byte[] inBuffer,
      short inOffset,
      short inLength,
      byte[] outBuffer,
      short outOffset) {
    short comparisonLength = (short) (theKey.getSize() >> (short) 3); // divide by 8
    // TODO: If there is something that specifies the JCVM/JCRE must check the length
    // then we can ditch these checks.
    if (inLength != comparisonLength) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      return (short) 0; // Keep compiler happy
    } else {
      cspRSA.init(theKey, Cipher.MODE_DECRYPT);
      return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }
  }

  /**
   * Generates a number of random bytes using the SECURE_RANDOM generator
   *
   * @param buffer The buffer to write the random data to
   * @param offset The starting offset to write the random data
   * @param length The number of bytes to generate
   */
  static void doGenerateRandom(byte[] buffer, short offset, short length) {
    cspRNG.generateData(buffer, offset, length);
  }
}
