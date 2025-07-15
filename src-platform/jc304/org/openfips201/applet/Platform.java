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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.PrivateKey;
import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/*
 * Provides an abstraction to specific implementations of the JCRE and specific hardware
 * capabilities of each platform. This can either target generic JCRE's or specific manufacturers.
 *
 */
class Platform {

  /////////////////////////////////////////////////////////////////////////////
  // PLATFORM: Generic JCRE 3.0.4 compatibility
  /////////////////////////////////////////////////////////////////////////////
  //
  // Platform abstraction is intended to allow OpenFIPS201 to easily map to the particular
  // implementation details of difference Java Card runtime environments, such as:
  // - JavaCard 3.0.4
  // - JavaCard 3.0.5u1-4
  // - NXP P71D600 (Based on Java Card 3.0.5u4)
  // - NXP P60SECID (Based on Java Card 3.0.4)
  // - and more
  //
  // This is not a generically re-usable platform abstraction, but rather the functionality
  // in this interface specifically targets targeted in this interface is anything required by
  // OpenFIPS201, such as:
  // - Crypto primitive implementations (AES_CMAC_128, PIV SM, etc)
  // - Crypto primitive instances vs One Shot API
  // - PIN implementations (setRetryLimit, sensitiveResult usage)
  // - Applet.reselectingApplet

  private Platform() {

  }

  private static final byte[] APPLICATION_LABEL = { 'O', 'p', 'e', 'n', 'F', 'I', 'P', 'S', '2', '0', '1', '-', 'J',
      'C', '3', '0', '4', '-', 'F', 'I', 'P', 'S' };

  /*
   * Returns the platform-specific application label for use in the GET VERSION
   * command
   */
  static byte[] getPlatformLabel() {
    return APPLICATION_LABEL;
  }

  /*
   * Returns the platform-specific application label for use in the GET VERSION
   * command
   */
  static short getPlatformLabelLength() {
    // Return the length to either include or exclude the '-FIPS' component of the
    // label

    if (Config.FIPS_APPROVED_MODE) {
      return (short) (APPLICATION_LABEL.length - 5); // Truncase the _FIPS
    } else {
      return (short) APPLICATION_LABEL.length;
    }
  }

  static void init() {
    Cryptography.init();
  }

  static void terminate() {
    Cryptography.terminate();
  }

  static void beginTransaction() throws TransactionException {
    JCSystem.beginTransaction();
  }

  static void commitTransaction() throws TransactionException {
    JCSystem.commitTransaction();
  }

  static void abortTransaction() throws TransactionException {
    JCSystem.abortTransaction();
  }

  static void requestObjectDeletion() {
    if (JCSystem.isObjectDeletionSupported()) {
      JCSystem.requestObjectDeletion();
    }
  }

  static OwnerPIN createPIN(byte tryLimit, byte maxPINSize) {
    return new OwnerPIN(tryLimit, maxPINSize);
  }

  /**
   * Performs a 3-pass erasure of the target buffer with 00/FF/00
   *
   * @param buffer The buffer to clear
   * @param offset The starting offset of the buffer
   * @param length The length within the buffer to clear
   */
  static void zeroise(byte[] buffer, short offset, short length) {
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0xFF);
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);
  }

  /**
   * Performs a constant-time comparison of two arrays.
   * @param a
   * @param offsetA
   * @param b
   * @param offsetB
   * @param length
   * @return
   */
  static boolean arrayCompare(byte[] a, short offsetA, byte[] b, short offsetB, short length) {
    // Ensure that the offsets and length are within the bounds of both arrays
    if ((short) (offsetA + length) > (short) a.length || (short) (offsetB + length) > (short) b.length) {
      return false;
    }

    byte result = 0;
    for (short i = 0; i < length; i++) {
      result |= (a[(short) (offsetA + i)] ^ b[(short) (offsetB + i)]);
    }

    return result == 0;
  }

  static boolean isContactless() {
    byte media = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
    return (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B);
  }

  static class Cryptography {

    //
    // Crypto implementation instances
    //

    // KeyAgreement is the only generic crypto class that has no OneShot implementation in JCRE
    private static Cipher cspAES;
    private static Cipher cspTDEA;
    private static Cipher cspRSA;
    private static Signature cspECDSA;
    private static Signature cspCMAC;
    private static KeyAgreement cspECDH;
    private static MessageDigest cspSHA256;
    private static MessageDigest cspSHA384;
    private static RandomData cspRandom;

    private Cryptography() {
    }

    private static void init() {

      try {
        if (cspAES == null) {
          cspAES = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspAES = null;
      }

      try {
        if (cspTDEA == null) {
          cspTDEA = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspTDEA = null;
      }

      try {
        if (cspRSA == null) {
          cspRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspRSA = null;
      }

      try {
        if (cspECDSA == null) {
          cspECDSA = Signature.getInstance(Signature.SIG_CIPHER_ECDSA, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspECDSA = null;
      }

      try {
        if (cspCMAC == null) {
          cspCMAC = getCMAC();
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspCMAC = null;
      }

      try {
        if (cspECDH == null) {
          cspECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspECDH = null;
      }

      try {
        if (cspSHA256 == null) {
          cspSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspSHA256 = null;
      }

      try {
        if (cspSHA384 == null) {
          cspSHA384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspSHA384 = null;
      }

      try {
        if (cspRandom == null) {
          cspRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        }
      } catch (Exception ex) {
        // Just fall-through if it isn't supported
        cspRandom = null;
      }

    }

    private static void terminate() {
      cspAES = null;
      cspTDEA = null;
      cspRSA = null;
      cspECDSA = null;
      cspCMAC = null;
      cspECDH = null;
      cspSHA256 = null;
      cspSHA384 = null;
      cspRandom = null;
      requestObjectDeletion();
    }

    static boolean supportsMechanism(byte mechanism) {

      switch (mechanism) {

      // Supported Algorithms
      case Constants.ID_ALG_DEFAULT:
      case Constants.ID_ALG_TDEA_3KEY:
        // FIPS: Disabled in Approved mode
        return (!Config.FIPS_APPROVED_MODE && cspTDEA != null);

      case Constants.ID_ALG_AES_128:
      case Constants.ID_ALG_AES_192:
      case Constants.ID_ALG_AES_256:
        return (cspAES != null);

      case Constants.ID_ALG_RSA_1024:
        // FIPS: Disabled in Approved mode
        return (!Config.FIPS_APPROVED_MODE && cspRSA != null);

      case Constants.ID_ALG_RSA_2048:
        //case Constants.ID_ALG_RSA_3072:
        //case Constants.ID_ALG_RSA_4096:
        return (cspRSA != null);

      case Constants.ID_ALG_ECC_P256:
      case Constants.ID_ALG_ECC_P384:
        //case Constants.ID_ALG_ECC_CS2:
        //case Constants.ID_ALG_ECC_CS7:
        return (cspECDSA != null && cspECDH != null);

      default:
        return false;
      }
    }

    static MessageDigest getMessageDigest(byte algorithm) {
      switch (algorithm) {
      case MessageDigest.ALG_SHA_256:
        cspSHA256.reset();
        return cspSHA256;
      case MessageDigest.ALG_SHA_384:
        cspSHA256.reset();
        return cspSHA384;
      default:
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return null; // Keep compiler happy
      }
    }

    static Signature getCMAC() {
      //final byte SIG_CIPHER_AES_CMAC16 = (byte) 0x67; // From P60 UGAM      
      //return Signature.getInstance(MessageDigest.ALG_NULL, SIG_CIPHER_AES_CMAC16, Cipher.PAD_NOPAD, false);
      return null;
    }

    static short computeCMAC(AESKey key, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {
      cspCMAC.init(key, Signature.MODE_SIGN);
      return cspCMAC.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    static boolean verifyCMAC(AESKey key, byte[] inBuffer, short inOffset, short inLength, byte[] sigBuffer,
        short sigOffset, short sigLength) {
      cspCMAC.init(key, Signature.MODE_VERIFY);
      return cspCMAC.verify(inBuffer, inOffset, inLength, sigBuffer, sigOffset, sigLength);
    }

    static Key buildKey(byte algorithm, short length) {

      switch (algorithm) {

      case KeyBuilder.TYPE_AES:
      case KeyBuilder.TYPE_DES:
      case KeyBuilder.TYPE_RSA_PUBLIC:
      case KeyBuilder.TYPE_RSA_PRIVATE:
      case KeyBuilder.TYPE_RSA_CRT_PRIVATE:
        return KeyBuilder.buildKey(algorithm, length, false);

      case KeyBuilder.ALG_TYPE_EC_FP_PRIVATE:
      case KeyBuilder.TYPE_EC_FP_PRIVATE:
      case KeyBuilder.ALG_TYPE_EC_FP_PUBLIC:
      case KeyBuilder.TYPE_EC_FP_PUBLIC:
        ECKey key = (ECKey) KeyBuilder.buildKey(algorithm, length, false);
        if (length == KeyBuilder.LENGTH_EC_FP_256) {
          key.setA(PIVKeyECC.ECParamsP256.A, (short) 0, (short) PIVKeyECC.ECParamsP256.A.length);
          key.setB(PIVKeyECC.ECParamsP256.B, (short) 0, (short) PIVKeyECC.ECParamsP256.B.length);
          key.setG(PIVKeyECC.ECParamsP256.G, (short) 0, (short) PIVKeyECC.ECParamsP256.G.length);
          key.setR(PIVKeyECC.ECParamsP256.N, (short) 0, (short) PIVKeyECC.ECParamsP256.N.length);
          key.setFieldFP(PIVKeyECC.ECParamsP256.P, (short) 0, (short) PIVKeyECC.ECParamsP256.P.length);
          key.setK(PIVKeyECC.ECParamsP256.H);
        } else if (length == KeyBuilder.LENGTH_EC_FP_384) {
          key.setA(PIVKeyECC.ECParamsP384.A, (short) 0, (short) PIVKeyECC.ECParamsP384.A.length);
          key.setB(PIVKeyECC.ECParamsP384.B, (short) 0, (short) PIVKeyECC.ECParamsP384.B.length);
          key.setG(PIVKeyECC.ECParamsP384.G, (short) 0, (short) PIVKeyECC.ECParamsP384.G.length);
          key.setR(PIVKeyECC.ECParamsP384.N, (short) 0, (short) PIVKeyECC.ECParamsP384.N.length);
          key.setFieldFP(PIVKeyECC.ECParamsP384.P, (short) 0, (short) PIVKeyECC.ECParamsP384.P.length);
          key.setK(PIVKeyECC.ECParamsP384.H);
        } else {
          ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        return (Key) key;

      default:
        return null;
      }

    }

    /**
     * Performs a symmetric encryption operation on the supplied data, which must be
     * block-aligned (i.e. no padding is performed).
     *
     * @param keyObject The key to perform the operation with
     * @param inBuffer  contains the data to encrypt
     * @param inOffset  the location of the first byte of the data to encrypt
     * @param inLength  the length of the data to encrypt
     * @param outBuffer the buffer to contain the signature
     * @param outOffset the location of the first byte of the signature
     * @return the length of the encrypted block
     */
    static short encipher(SecretKey secretKey, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {

      // PRE-CONDITION 1 - If the input and output buffers are equal, we must not
      // clobber the input
      //
      // From the Java Card Cipher documentation:
      // When using block-aligned data (multiple of block size), if the input buffer,
      // inBuff and
      // the output buffer, outBuff are the same array, then the output data area must
      // not
      // partially overlap the input data area such that the input data is modified
      // before it is
      // used; if inBuff==outBuff and inOffset < outOffset < inOffset+inLength,
      // incorrect output
      // may result.
      if ((inBuffer == outBuffer) && (inOffset < outOffset) && (outOffset < (short) (inOffset + inLength))) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }

      Cipher cipher;

      switch (secretKey.getType()) {
      case KeyBuilder.TYPE_DES:
      case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
        cipher = cspTDEA;
        break;

      case KeyBuilder.TYPE_AES:
      case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
        cipher = cspAES;
        break;

      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0; // Keep compiler happy
      }

      cipher.init(secretKey, Cipher.MODE_ENCRYPT);
      return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    /**
     * Signs the passed pre-computed hash
     *
     * @param keyObject The key to perform the operation with
     * @param inBuffer  contains the pre-computed hash
     * @param inOffset  the location of the first byte of the hash
     * @param inLength  the length of the computed hash
     * @param outBuffer the buffer to contain the signature
     * @param outOffset the location of the first byte of the signature
     * @return the length of the signature
     */
    static short sign(ECPrivateKey privateKey, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {

      //
      // FROM FIPS 186-5 6.1.1:
      // URL: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
      //
      // "It is recommended that the security strength associated with the bit length
      // of n and
      // the security strength of the hash function be the same unless an agreement
      // has been
      // made between participating entities to use a stronger hash function. A hash
      // function
      // that provides a lower security strength than is associated with the bit
      // length of n
      // shall not be used. If the length of the output of the hash function is
      // greater than
      // the bit length of n, then the leftmost len(n) bits of the hash function
      // output block shall be used in any calculation using the hash function output during the
      // generation or verification of a digital signature."
      //

      switch (inLength) {
      case MessageDigest.LENGTH_SHA:
        //
        // FIPS: SHA-1 is not permitted in the Approved mode for Digital Signature
        // operations
        if (Config.FIPS_APPROVED_MODE) {
          ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        // NOTE:
        // Because this is a non-approved algorithm and would only be used in a legacy
        // situation anyway, we permit it for any length as it is not strong enough for
        // even P256 (80bits vs 128bits effective strength)
        break;

      case MessageDigest.LENGTH_SHA_256: // Effective strength 128bits
        if (privateKey.getSize() == KeyBuilder.LENGTH_EC_FP_384) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        break;

      case MessageDigest.LENGTH_SHA_384: // Effective strength 192 bits
      case MessageDigest.LENGTH_SHA_512: // Effective strength 256 bits
        // Do nothing, these are valid in all cases
        break;

      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return (short) 0; // Keep compiler happy
      }

      cspECDSA.init(privateKey, Signature.MODE_SIGN);
      return cspECDSA.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    /**
     * Signs a pre-formatted block of data using an RSA private key operation.
     *
     * @param keyObject The key to perform the operation with
     * @param inBuffer  contains the pre-computed hash
     * @param inOffset  the location of the first byte of the hash
     * @param inLength  the length of the computed hash
     * @param outBuffer the buffer to contain the signature
     * @param outOffset the location of the first byte of the signature
     * @return the length of the signature
     */
    static short computeRSADP1(PrivateKey privateKey, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {

      //
      // IMPLEMENTATION NOTE:
      // If you think the operation below looks strange, that's OK. This requires
      // explanation. The PIV standard implements RSA digital signatures in a way that
      // does not force you to choose a specific padding scheme (though they recommend
      // PKCS#1.5, PSS or OAEP). This means the client does not send the data to be
      // signed, or even just the hash value. Instead, it sends a fully-formatted block
      // including the hash and all padding. 
      // The problem here is that the Java Card Signature object can only sign in two
      // ways.
      // 1) Pass all data to update() and/or sign() which generates the hash, pads and
      // encrypts.
      // 2) Pass the hash to signPreComputedHash() which validates the length, pads
      // and encrypts.
      //
      // Neither of the above is suited to taking a fully-formed block, so we are left
      // with the only remaining option, which is to perform a private key decryption
      // operation, which makes us feel awkward and wrong.
      //
      cspRSA.init(privateKey, Cipher.MODE_DECRYPT);
      return cspRSA.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    /**
     * Performs a key agreement operation
     *
     * @param theKey    The key to perform the operation with
     * @param inBuffer  the input to the key agreement operation
     * @param inOffset  the the location of first byte of the key agreement input
     * @param inLength  the length of the key agreement input
     * @param outBuffer the key agreement output
     * @param outOffset the location of the first byte of the key agreement output
     * @return the length of the key agreement output
     */
    static short computeECDH(ECPrivateKey privateKey, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {

      // NOTE: The Java Card implementation of generateSecret() performs sufficient buffer state and
      // length checking that we don't double-up here.

      cspECDH.init(privateKey);
      return cspECDH.generateSecret(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    /**
     * Generates a number of random bytes using the SECURE_RANDOM generator
     *
     * @param buffer The buffer to write the random data to
     * @param offset The starting offset to write the random data
     * @param length The number of bytes to generate
     */
    static short generateRandom(byte[] buffer, short offset, short length) {

      if (Config.DEBUG_FIXED_RANDOM) {
        for (short i = 0; i < length; i++) {
          buffer[(short) (offset + i)] = (byte) (i % 256);
        }
      } else {
        cspRandom.generateData(buffer, offset, length);
      }

      return (short) (offset + length);
    }
  }
}