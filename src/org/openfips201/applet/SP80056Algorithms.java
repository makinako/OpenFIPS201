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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

final class SP80056KDAOneStep {

  //
  // CONSTANTS - Known Answer Test (KAT) values
  //

  // The SP800-56 OneStep KDF KAT values
  //
  private static final byte KAT_SP800_56_KDA_ALGORITHM = MessageDigest.ALG_SHA_256;
  private static final short KAT_INPUT_OFFSET_Z = (short) 0;
  private static final short KAT_INPUT_LENGTH_Z = (short) 32;
  private static final short KAT_INPUT_OFFSET_U = (short) 32;
  private static final short KAT_INPUT_LENGTH_U = (short) 16;
  private static final short KAT_INPUT_OFFSET_V = (short) 48;
  private static final short KAT_INPUT_LENGTH_V = (short) 16;

  private static final byte[] KAT_INPUT = new byte[] {
      // Z (Offset = 0, Length = 32)
      (byte) 0x8D, (byte) 0x5A, (byte) 0xF9, (byte) 0x2A, (byte) 0x22, (byte) 0x6F, (byte) 0x1F, (byte) 0x12,
      (byte) 0x3E, (byte) 0x8A, (byte) 0x5D, (byte) 0x7A, (byte) 0x89, (byte) 0x69, (byte) 0x64, (byte) 0x49,
      (byte) 0x4C, (byte) 0x83, (byte) 0xF6, (byte) 0x1C, (byte) 0x66, (byte) 0x35, (byte) 0x3B, (byte) 0x4F,
      (byte) 0x6A, (byte) 0xF1, (byte) 0xB0, (byte) 0x7F, (byte) 0xAC, (byte) 0xE5, (byte) 0x3D, (byte) 0x20,

      // uPartyInfo (Offset = 32, length = 16)
      (byte) 0x10, (byte) 0x00, (byte) 0x3E, (byte) 0x8E, (byte) 0x0D, (byte) 0x63, (byte) 0x25, (byte) 0x31,
      (byte) 0x48, (byte) 0x5F, (byte) 0x13, (byte) 0xA2, (byte) 0x42, (byte) 0x19, (byte) 0x33, (byte) 0xED,

      // vPartyInfo (Offset = 48, length = 16)
      (byte) 0xE0, (byte) 0x56, (byte) 0x3F, (byte) 0xCE, (byte) 0x41, (byte) 0x5F, (byte) 0x99, (byte) 0xA6,
      (byte) 0xB3, (byte) 0xC2, (byte) 0x52, (byte) 0x1C, (byte) 0x26, (byte) 0x0E, (byte) 0x81, (byte) 0x8E };

  private static final short KAT_OUTPUT_LENGTH = (short) 32;

  private static final byte[] KAT_OUTPUT = new byte[] {
      // DKM (32 bytes)
      (byte) 0x9A, (byte) 0xDA, (byte) 0xCA, (byte) 0xB3, (byte) 0x33, (byte) 0x1E, (byte) 0xE0, (byte) 0x8D,
      (byte) 0x0C, (byte) 0x6A, (byte) 0x41, (byte) 0x90, (byte) 0xCE, (byte) 0x12, (byte) 0x13, (byte) 0xC0,
      (byte) 0xEF, (byte) 0x1A, (byte) 0x4A, (byte) 0x24, (byte) 0x57, (byte) 0x6C, (byte) 0x81, (byte) 0xB4,
      (byte) 0x6F, (byte) 0x46, (byte) 0xF1, (byte) 0xCB, (byte) 0xA1, (byte) 0x5E, (byte) 0x0B, (byte) 0xB9 };

  private static final byte[] ALG_ID_SHA256 = new byte[] { (byte) 0x04, (byte) 0x09, (byte) 0x09, (byte) 0x09,
      (byte) 0x09 };
  private static final byte[] ALG_ID_SHA384 = new byte[] { (byte) 0x04, (byte) 0x0D, (byte) 0x0D, (byte) 0x0D,
      (byte) 0x0D };

  //
  // We pass in implementations to re-use them and reduce RAM usage.
  private SP80056KDAOneStep() {
  }

  /***
   * Computes the output of the OneStep KDF according to SP800-56Cr2 with the following 
   * limitations:
   * - It supports the 'responder' KAS role only.
   * - It supports 'unilateral' direction only from party V (card) to party U (host)
   * - It internally prepends the required Algorithm Id. 
   * - All input elements must be supplied in the same input buffer array.
   * SPEC: https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-kdf-onestep.html
   */
  static short doFinal(byte algorithm, byte[] inBuffer, short zOffset, short zLength, short uOffset, short uLength,
      short vOffset, short vLength, byte[] outBuffer, short outOffset, short outLength) {

    //
    // INPUT FORMAT:
    // Counter | Z | OtherInfo (AlgorithmId | PartyUInfo | PartyVInfo)
    // Where:
    // - Counter is an internally generated 32-bit MSB value starting at 1
    // - Z is the shared secret generated from a previous ECDH operation
    // - AlgorithmId is an internally generated 5-byte value, depending on the hash function
    //   used.
    // - PartyUInfo is the host-supplied binding info (IDsh | cbH | qeH for PIV-SM)
    // - PartyVInfo is the applet-supplied binding info (IDsICC | Nonce | cbICC for PIV-SM)
    // 

    //
    // NOTE:
    // This method behaves badly and may clobber more bytes in outBuffer than outLength requires.
    // An example of this is Cipher Suite 7, which requires 4 * AES256 derived keys (128 bytes). 
    // This requires a minimum of 3*SHA384 operations and generates 144 bytes, writing an 
    // additional 16 bytes that are superflous to the KDF and never used.      
    //
    // We allow this because it saves us allocating extra buffers and because it is an internal 
    // function with strictly controlled usage, but it is naughty and we feel bad about it.
    final short KDF_COUNTER_LENGTH = (short) 4;

    // Track the remaining bytes
    short remaining = outLength;

    // Ensure the digest state is reset from any previous operation
    MessageDigest digest = Platform.Cryptography.getMessageDigest(algorithm);
    digest.reset();

    byte counter = (byte) 1;
    while (remaining > 0) {

      // Update the counter
      // NOTE: Since we are about to clobber it, use the first 4 bytes of outBuffer[outOffset] 
      // as the counter. 
      Util.arrayFillNonAtomic(outBuffer, outOffset, KDF_COUNTER_LENGTH, (byte) 0);
      // Set counter and increment
      outBuffer[(short) (outOffset + 3)] = counter++;

      // Counter (Internally constructed)
      digest.update(outBuffer, outOffset, KDF_COUNTER_LENGTH);

      // Z
      digest.update(inBuffer, zOffset, zLength);

      // OtherInfo - Algorithm Id (Internally constructed
      switch (algorithm) {
      case MessageDigest.ALG_SHA_256:
        digest.update(ALG_ID_SHA256, (short) 0, (short) ALG_ID_SHA256.length);
        break;
      case MessageDigest.ALG_SHA_384:
        digest.update(ALG_ID_SHA384, (short) 0, (short) ALG_ID_SHA384.length);
        break;
      default:
        // Insane condition
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        break;
      }

      // OtherInfo - Party U
      digest.update(inBuffer, uOffset, uLength);

      // OtherInfo - Party V
      short hashLength = digest.doFinal(inBuffer, vOffset, vLength, outBuffer, outOffset);

      // Decrement the remaining bytes
      remaining -= hashLength;
      outOffset += hashLength;
    }

    // Return the number of bytes of keying material we provided
    // NOTE: This does not include the superfluous bytes written
    return outLength;
  }

  /*
   * This method satisfies the FIPS pre-operational, conditional and periodic tests by executing
   * the KDA and KC algorithms with known inputs and comparing the result to known outputs.
   * 
   * NOTES:
   * - This must be executed prior to the first call to the KDA or KC algorithms each power cycle
   * - A failure causes the applet to prevent selection until a card reset (cold or warm) occurs
   */
  static void doSelfTests(byte[] outBuffer, short outOffset) {

    if (Config.FIPS_APPROVED_MODE) {
      //
      // Algorithm: "KDA OneStep Sp800-56Cr2"
      // ACVP Url: https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-kdf-onestep.html
      try {
        doFinal(KAT_SP800_56_KDA_ALGORITHM, KAT_INPUT, KAT_INPUT_OFFSET_Z, KAT_INPUT_LENGTH_Z, KAT_INPUT_OFFSET_U,
            KAT_INPUT_LENGTH_U, KAT_INPUT_OFFSET_V, KAT_INPUT_LENGTH_V, outBuffer, outOffset, KAT_OUTPUT_LENGTH);

        //
        // TEST CODE: Induces a deliberate failure in the output, causing a CAST failure.
        //
        if (Config.DEBUG_FIPS_FAIL_CAST) {
          Util.arrayFillNonAtomic(outBuffer, outOffset, KAT_OUTPUT_LENGTH, (byte) 0);
        }

        // KDA Comparison
        if (!Platform.arrayCompare(outBuffer, outOffset, KAT_OUTPUT, (short) 0, KAT_OUTPUT_LENGTH)) {
          ISOException.throwIt(Constants.SW_CAST_FAILURE);
        }
      } catch (Exception ex) {
        // Any error in this method results in a CAST failure
        ISOException.throwIt(Constants.SW_CAST_FAILURE);
      } finally {
        // Always clear the output buffer regardless of the outcome
        Platform.zeroise(outBuffer, outOffset, KAT_OUTPUT_LENGTH);
      }
    }
  }
}

final class SP80056KasKc {

  //
  // CONSTANTS - Known Answer Test (KAT) values
  //

  private SP80056KasKc() {

  }

  private static final byte[] KAT_INPUT = new byte[] {
      // MacKey (AES128 and AES256, Length = 32)
      (byte) 0x02, (byte) 0x8B, (byte) 0x2B, (byte) 0xC9, (byte) 0x19, (byte) 0xE3, (byte) 0xCC, (byte) 0x1A,
      (byte) 0xF9, (byte) 0x5B, (byte) 0x78, (byte) 0xE7, (byte) 0x8C, (byte) 0x5E, (byte) 0xF7, (byte) 0xCE,
      (byte) 0xCE, (byte) 0xB5, (byte) 0xCC, (byte) 0x75, (byte) 0x7B, (byte) 0x12, (byte) 0x66, (byte) 0x37,
      (byte) 0xEC, (byte) 0xC9, (byte) 0xF7, (byte) 0x98, (byte) 0x72, (byte) 0x97, (byte) 0x7F, (byte) 0xB1,

      // uPartyInfo (Offset = 0, length = 16)
      (byte) 0x82, (byte) 0x3D, (byte) 0xF4, (byte) 0xEF, (byte) 0x37, (byte) 0xF8, (byte) 0x78, (byte) 0xAD,
      (byte) 0x23, (byte) 0xAC, (byte) 0xB1, (byte) 0x91, (byte) 0xD0, (byte) 0x3B, (byte) 0x45, (byte) 0xA1,

      // vPartyInfo (Offset = 16, length = 16)
      (byte) 0x5D, (byte) 0x96, (byte) 0x51, (byte) 0xE9, (byte) 0x55, (byte) 0x18, (byte) 0x6E, (byte) 0x68,
      (byte) 0x97, (byte) 0x46, (byte) 0x8B, (byte) 0x82, (byte) 0xC4, (byte) 0xC0, (byte) 0x8E, (byte) 0x88

  };

  private static final byte[] KAT_OUTPUT_AES128 = new byte[] {
      // MagTag (16 bytes)
      (byte) 0xB8, (byte) 0x3B, (byte) 0x94, (byte) 0xCA, (byte) 0x24, (byte) 0xB5, (byte) 0x2D, (byte) 0x7A,
      (byte) 0xE0, (byte) 0xA1, (byte) 0x2B, (byte) 0xA7, (byte) 0x99, (byte) 0x44, (byte) 0x8E, (byte) 0x1D };

  private static final byte[] KAT_OUTPUT_AES256 = new byte[] {
      // MagTag (16 bytes)
      (byte) 0x6B, (byte) 0x5C, (byte) 0x98, (byte) 0xA9, (byte) 0x3D, (byte) 0x23, (byte) 0xA0, (byte) 0x63,
      (byte) 0xF3, (byte) 0xA3, (byte) 0xFA, (byte) 0xA1, (byte) 0x82, (byte) 0x3B, (byte) 0xD5, (byte) 0x88 };

  private static final short KAT_INPUT_OFFSET_K = (short) 0;
  private static final short KAT_INPUT_OFFSET_U = (short) 32;
  private static final short KAT_INPUT_LENGTH_U = (short) 16;
  private static final short KAT_INPUT_OFFSET_V = (short) 48;
  private static final short KAT_INPUT_LENGTH_V = (short) 16;

  // Represents the Key Confirmation CMAC constant input 'KC_1_V'
  private static final byte[] KCModeUniPartyV = { 'K', 'C', '_', '1', '_', 'V' };

  //
  // Key references for CMAC, so that key data can just be passed through.
  // NOTE: This ended up being the best way, since there were 3 different callers to this
  // functionality:
  // 1) The PIV SM functionality
  // 2) The CAST self-tests
  // 3) The debug-mode ACVP test functionality
  // 

  static short doFinal(Signature cmac, AESKey key, byte[] inBuffer, short idP, short idPLength, short idR,
      short idRLength, short qeP, short qePLength, byte[] outBuffer, short outOffset) {

    //
    // CMAC INPUT FORMAT: 
    // message_stringP | vPartyInfo | uPartyInfo
    // where:
    // - message_stringP is a static prefix to indicate unilateral / party V provides ("KC_1_V")
    // - vPartyInfo is the concatenation of the providing party id and ephemereal data
    // - rPartyInfo is the recieving party's id
    //

    //
    // NOTE:
    // The function expects a CMAC already initialised with the correct key value.
    //

    // Execute the KC
    try {
      short outLength = 0;

      cmac.init(key, Signature.MODE_SIGN);

      // Append message_stringP
      cmac.update(KCModeUniPartyV, (short) 0, (short) KCModeUniPartyV.length);

      // Append idP, idR
      cmac.update(inBuffer, idP, idPLength);

      if (qeP >= 0) {
        cmac.update(inBuffer, idR, idRLength);

        // Append qeP and compute the final CMAC
        outLength = cmac.sign(inBuffer, qeP, qePLength, outBuffer, outOffset);
      } else {
        // We skip qeP and just return the CMAC after updating idR
        outLength = cmac.sign(inBuffer, idR, idRLength, outBuffer, outOffset);
      }

      return outLength;
    } finally {
      key.clearKey();
    }
  }

  /*
   * This method satisfies the FIPS pre-operational, conditional and periodic tests by executing
   * the KDA and KC algorithms with known inputs and comparing the result to known outputs.
   * 
   * NOTES:
   * - This must be executed prior to the first call to the KDA or KC algorithms each power cycle
   * - A failure must cause the applet to prevent selection until a card reset (cold or warm) 
   *   occurs.
   */
  static void doSelfTests(Signature cmac, AESKey key, byte[] buffer, short offset) {

    if (Config.FIPS_APPROVED_MODE) {
      // Set the key value
      key.setKey(KAT_INPUT, KAT_INPUT_OFFSET_K);

      short kcLength = 0;
      try {
        //
        // Algorithm: "KAS KC Sp800-56 (Component)"
        // ACVP Url: https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-kc-sp800-56.html

        kcLength = doFinal(cmac, key, KAT_INPUT, KAT_INPUT_OFFSET_V, KAT_INPUT_LENGTH_V, // V
            KAT_INPUT_OFFSET_U, KAT_INPUT_LENGTH_U, // U  
            // NOTE: We don't supply the qeH parameter for the self-test
            (short) -1, (short) 0, buffer, offset);

        //
        // TEST CODE: Induces a deliberate failure in the output, causing a CAST failure.
        //
        if (Config.DEBUG_FIPS_FAIL_CAST) {
          Util.arrayFillNonAtomic(buffer, offset, kcLength, (byte) 0);
        }

        // Comparison
        byte[] comparison;
        if (key.getSize() == KeyBuilder.LENGTH_AES_128) {
          comparison = KAT_OUTPUT_AES128;
        } else {
          comparison = KAT_OUTPUT_AES256;          
        }
        if (!Platform.arrayCompare(buffer, offset, comparison, (short) 0, kcLength)) {
          ISOException.throwIt(Constants.SW_CAST_FAILURE);
        }
      } catch (Exception ex) {
        // Any error in this method results in a CAST failure
        ISOException.throwIt(Constants.SW_CAST_FAILURE);
      } finally {
        key.clearKey();
        Platform.zeroise(buffer, offset, kcLength);
      }
    }
  }
}
