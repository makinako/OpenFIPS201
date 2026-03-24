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

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

final class ChannelSCP {

  private static final byte CLA_MASK_SECURE_MESSAGING = (byte) 0x0C;
  private static final byte CLA_FLAG_SCP = (byte) 0x04;

  private static final byte REQUIRED_LEVEL = SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION
      | SecureChannel.C_MAC;

  ChannelSCP() {
    // NOTE: We don't create the SCP here because it cannot be called from the applet constructo
  }

  void init() {
  }

  short initializeUpdate(APDU apdu) {
    // Force reset
    SecureChannel scp = GPSystem.getSecureChannel();
    scp.resetSecurity();

    return scp.processSecurity(apdu);
  }

  short externalAuthenticate(APDU apdu) {
    SecureChannel scp = GPSystem.getSecureChannel();

    short length = scp.processSecurity(apdu);

    if ((scp.getSecurityLevel() & REQUIRED_LEVEL) != REQUIRED_LEVEL) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return length;
  }

  boolean isEstablished() {
    return ((scp.getSecurityLevel() & REQUIRED_LEVEL) == REQUIRED_LEVEL);
  }

  static boolean isSecureChannel(byte cla) {
    // We always require C_DECRYPTION and C_MAC, so any SCP-wrapped APDU must be unwrapped
    return (cla & CLA_MASK_SECURE_MESSAGING) == CLA_FLAG_SCP;
  }

  boolean isResponseWrapped() {
    return ((scp.getSecurityLevel() & (SecureChannel.R_ENCRYPTION | SecureChannel.R_MAC)) != 0);
  }

  short unwrap(byte[] buffer, short offset, short length) {
    //
    // Global Platform SCP03 Rules (GP Secure Channel Protocol '03' - Public Release v1.1.2):
    // If a Secure Channel Session is active (i.e. Current Security Level at least set to 
    // AUTHENTICATED), the security of the incoming command shall be checked according to the 
    // Current Security Level regardless of the command secure messaging indicator:
    // - When the security of the command does not match (nor exceeds) the Current Security Level, 
    //   the command shall be rejected with a security error, the Secure Channel Session aborted and 
    //   the Current Security Level reset to NO_SECURITY_LEVEL.
    // - If a security error is found, the command shall be rejected with a security error, the 
    //   Secure Channel Session aborted and the Current Security Level reset to NO_SECURITY_LEVEL.
    // - In all other cases, the Secure Channel Session shall remain active and the Current Security 
    //   Level unmodified. The Application is responsible for further processing the command.
    //

    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: If the APDU is NOT wrapped and we are not established, do nothing
    if (!isSecureChannel(buffer[offset]) && !isEstablished()) {
      return length;
    }

    // PRE-CONDITION: If the APDU is wrapped and we are NOT established, fail
    // PRE-CONDITION: If the APDU is NOT wrapped and we are established, fail
    if (isSecureChannel(buffer[offset]) != isEstablished()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // We can now unwrap
    try {
      SecureChannel scp = GPSystem.getSecureChannel();
      length = scp.unwrap(buffer, offset, length);
    } catch (ISOException ex) {
      reset();
      ISOException.throwIt(ex.getReason());
    } catch (Exception ex) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return length;
  }

  /***
   * Returns the maximum size of a data frame that can be wrapped in this session
   * @return
   */
  short getMaxWrapLength() {
    // Begin with the maximum amount when no wrapping is enabled
    short result = (short) 256;

    SecureChannel scp = GPSystem.getSecureChannel();
    if ((scp.getSecurityLevel() & SecureChannel.R_ENCRYPTION) == SecureChannel.R_ENCRYPTION) {
      // R_ENCRYPTION + R_MAC is enabled
      result = (short) 240; // 256 bytes - 8 byte R_MAC value = 248. Nearest multiple of 16 is 240. 
    } else if ((scp.getSecurityLevel() & SecureChannel.R_MAC) == SecureChannel.R_MAC) {
      // Only R_MAC is enabled
      result = (short) 248; // 256 bytes - 8 byte R_MAC value 
    }

    return result;
  }

  short wrap(byte[] buffer, short offset, short length) {
    //
    // PRE-CONDITIONS
    //

    // PRE-CONDITION: If the current security level does NOT require wrapping, do nothing
    if (!isResponseWrapped()) {
      return length;
    } else if (!isEstablished()) {
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    // PRE-CONDITION

    // We can now wrap
    try {
      SecureChannel scp = GPSystem.getSecureChannel();
      length = scp.wrap(buffer, offset, length);
    } catch (ISOException ex) {
      reset();
      ISOException.throwIt(ex.getReason());
    } catch (Exception ex) {
      reset();
      ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
    }

    return length;
  }

  void reset() {
    SecureChannel scp = GPSystem.getSecureChannel();
    scp.resetSecurity();
  }
}
