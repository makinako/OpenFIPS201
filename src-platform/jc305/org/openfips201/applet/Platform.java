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
  // PLATFORM: NXP P71D600 JCOP 4.5
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

  private static final byte[] APPLICATION_LABEL = { 'O', 'p', 'e', 'n', 'F', 'I', 'P', 'S', '2', '0', '1', '-', 'P',
      '7', '1', 'D', '6', '0', '0', '-', 'F', 'I', 'P', 'S' };

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
      return (short) 24;
    } else {
      return (short) 19;
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
   * Performs a destructive erasure of the target buffer
   *
   * @param buffer The buffer to clear
   * @param offset The starting offset of the buffer
   * @param length The length within the buffer to clear
   */
  static void zeroise(byte[] buffer, short offset, short length) {
    Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);

    // FIPS: Increase the single-pass to a 3-pass.
    // NOTE: This is not actually required as-per FIPS, but other certifications do and so for the
    // FIPS_APPROVED version we add this anyway as a higher standard.
    if (Config.FIPS_APPROVED_MODE) {
      Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0xFF);
      Util.arrayFillNonAtomic(buffer, offset, length, (byte) 0x00);      
    }
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
    return (media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_A || media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_B
        || media == APDU.PROTOCOL_MEDIA_CONTACTLESS_TYPE_F);
  }
    
  static class Cryptography {

    //
    // Crypto implementation instances
    //

    // KeyAgreement is the only generic crypto class that has no OneShot implementation in JCRE
    private static KeyAgreement cspECDH;
    private static MessageDigest cspSHA256;
    private static MessageDigest cspSHA384;

    // PERSISTENT - Common EC domain parameters
    private static ECKey ecParamsP256 = null;
    private static ECKey ecParamsP384 = null;

    private Cryptography() {
    }

    private static void init() {
      if (cspECDH == null) {
        // We know this primitive is supported by P71D600
        cspECDH = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
      }

      if (ecParamsP256 == null) {
        ecParamsP256 = (ECKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS,
            JCSystem.MEMORY_TYPE_PERSISTENT, KeyBuilder.LENGTH_EC_FP_256, false);
        ecParamsP256.setA(PIVKeyECC.ECParamsP256.A, (short) 0, (short) PIVKeyECC.ECParamsP256.A.length);
        ecParamsP256.setB(PIVKeyECC.ECParamsP256.B, (short) 0, (short) PIVKeyECC.ECParamsP256.B.length);
        ecParamsP256.setG(PIVKeyECC.ECParamsP256.G, (short) 0, (short) PIVKeyECC.ECParamsP256.G.length);
        ecParamsP256.setR(PIVKeyECC.ECParamsP256.N, (short) 0, (short) PIVKeyECC.ECParamsP256.N.length);
        ecParamsP256.setFieldFP(PIVKeyECC.ECParamsP256.P, (short) 0, (short) PIVKeyECC.ECParamsP256.P.length);
        ecParamsP256.setK(PIVKeyECC.ECParamsP256.H);
      }
      if (ecParamsP384 == null) {
        ecParamsP384 = (ECKey) KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS,
            JCSystem.MEMORY_TYPE_PERSISTENT, KeyBuilder.LENGTH_EC_FP_384, false);
        ecParamsP384.setA(PIVKeyECC.ECParamsP384.A, (short) 0, (short) PIVKeyECC.ECParamsP384.A.length);
        ecParamsP384.setB(PIVKeyECC.ECParamsP384.B, (short) 0, (short) PIVKeyECC.ECParamsP384.B.length);
        ecParamsP384.setG(PIVKeyECC.ECParamsP384.G, (short) 0, (short) PIVKeyECC.ECParamsP384.G.length);
        ecParamsP384.setR(PIVKeyECC.ECParamsP384.N, (short) 0, (short) PIVKeyECC.ECParamsP384.N.length);
        ecParamsP384.setFieldFP(PIVKeyECC.ECParamsP384.P, (short) 0, (short) PIVKeyECC.ECParamsP384.P.length);
        ecParamsP384.setK(PIVKeyECC.ECParamsP384.H);
      }

      if (cspSHA256 == null) {
        cspSHA256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
      }
      if (cspSHA384 == null) {
        cspSHA384 = MessageDigest.getInstance(MessageDigest.ALG_SHA_384, false);
      }
    }

    private static void terminate() {
      cspECDH = null;
      cspSHA256 = null;
      cspSHA384 = null;
      ecParamsP256 = null;
      ecParamsP384 = null;
      requestObjectDeletion();
    }

    static boolean supportsMechanism(byte mechanism) {

      switch (mechanism) {

      // Supported Algorithms (Only in non-FIPS_APPROVED mode)
      case Constants.ID_ALG_DEFAULT:
      case Constants.ID_ALG_TDEA_3KEY:
      case Constants.ID_ALG_RSA_1024:
        return !Config.FIPS_APPROVED_MODE;
      
      // Supported Algorithms
      case Constants.ID_ALG_AES_128:
      case Constants.ID_ALG_AES_192:
      case Constants.ID_ALG_AES_256:
      case Constants.ID_ALG_RSA_2048:
      case Constants.ID_ALG_RSA_3072:
      case Constants.ID_ALG_RSA_4096:
      case Constants.ID_ALG_ECC_P256:
      case Constants.ID_ALG_ECC_P384:
      case Constants.ID_ALG_ECC_CS2:
      case Constants.ID_ALG_ECC_CS7:
        return true;

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
      return Signature.getInstance(Signature.SIG_CIPHER_AES_CMAC128, false);
    }

    static short computeCMAC(AESKey key, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer,
        short outOffset) {
      Signature.OneShot cmac;
      cmac = Signature.OneShot.open(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_AES_CMAC128, Cipher.PAD_ISO9797_M2);

      try {
        cmac.init(key, Signature.MODE_SIGN);
        return cmac.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
      } finally {
        cmac.close();
        cmac = null;
      }
    }

    static boolean verifyCMAC(AESKey key, byte[] inBuffer, short inOffset, short inLength, byte[] sigBuffer,
        short sigOffset, short sigLength) {
      Signature.OneShot cmac;
      cmac = Signature.OneShot.open(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_AES_CMAC128, Cipher.PAD_ISO9797_M2);

      try {
        cmac.init(key, Signature.MODE_VERIFY);
        return cmac.verify(inBuffer, inOffset, inLength, sigBuffer, sigOffset, sigLength);
      } finally {
        cmac.close();
        cmac = null;
      }
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
      case KeyBuilder.ALG_TYPE_EC_FP_PUBLIC:
      case KeyBuilder.TYPE_EC_FP_PRIVATE:
      case KeyBuilder.TYPE_EC_FP_PUBLIC:
        if (length == KeyBuilder.LENGTH_EC_FP_256) {
          return KeyBuilder.buildKeyWithSharedDomain(algorithm, JCSystem.MEMORY_TYPE_PERSISTENT, (Key) ecParamsP256,
              false);
        } else if (length == KeyBuilder.LENGTH_EC_FP_384) {
          return KeyBuilder.buildKeyWithSharedDomain(algorithm, JCSystem.MEMORY_TYPE_PERSISTENT, (Key) ecParamsP384,
              false);
        } else {
          ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }

        return null;

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

      Cipher.OneShot cipher;

      switch (secretKey.getType()) {
      case KeyBuilder.TYPE_DES:
      case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
        cipher = Cipher.OneShot.open(Cipher.CIPHER_DES_ECB, Cipher.PAD_NOPAD);
        break;

      case KeyBuilder.TYPE_AES:
      case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
      case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
        cipher = Cipher.OneShot.open(Cipher.CIPHER_AES_ECB, Cipher.PAD_NOPAD);
        break;

      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return 0; // Keep compiler happy
      }

      try {
        cipher.init(secretKey, Cipher.MODE_ENCRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
      } finally {
        cipher.close();
        cipher = null;
      }
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
      Signature.OneShot signer = null;

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

        signer = Signature.OneShot.open(MessageDigest.ALG_SHA, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
        break;

      case MessageDigest.LENGTH_SHA_256: // Effective strength 128bits
        if (privateKey.getSize() == KeyBuilder.LENGTH_EC_FP_384) {
          ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
        break;
      case MessageDigest.LENGTH_SHA_384: // Effective strength 192 bits
        signer = Signature.OneShot.open(MessageDigest.ALG_SHA_384, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
        break;
      case MessageDigest.LENGTH_SHA_512: // Effective strength 256 bits
        signer = Signature.OneShot.open(MessageDigest.ALG_SHA_512, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
        break;
      default:
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        return (short) 0; // Keep compiler happy
      }

      try {
        signer.init(privateKey, Signature.MODE_SIGN);
        return signer.signPreComputedHash(inBuffer, inOffset, inLength, outBuffer, outOffset);
      } finally {
        signer.close();
        signer = null;
      }
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
      // signed,
      // or even just the hash value. Instead, it sends a fully-formatted block
      // including
      // the hash and all padding.
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
      Cipher.OneShot cipher = Cipher.OneShot.open(Cipher.CIPHER_RSA, Cipher.PAD_NOPAD);
      try {
        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
      } finally {
        cipher.close();
      }
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

      // NOTE:
      // All RandomData modes utilise the same RNG source on the PD71D600, however
      // ALG_KEYGENERATION forces a reseed of the internal state on every call to
      // nextBytes. We have opted not to make use of this, and so we use ALG_TRNG.
      RandomData.OneShot cspRNG = null;

      if (Config.DEBUG_FIXED_RANDOM) {
        for (short i = 0; i < length; i++) {
          buffer[(short) (offset + i)] = (byte) (i % 256);
        }
      } else {
        cspRNG = RandomData.OneShot.open(RandomData.ALG_TRNG);
        try {
          cspRNG.nextBytes(buffer, offset, length);
        } finally {
          cspRNG.close();
        }
      }

      return (short) (offset + length);
    }
  }
}
