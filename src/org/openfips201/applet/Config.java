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

/**
 * Defines all configurable elements of the PIV applet in one place. This allows customisation of
 * the data and key file system as well as controlling the behaviour of the applet.
 */
final class Config {

  /////////////////////////////////////////////////////////////////////////////////////////////////
  //
  // This class is made up of two distinct configuration types:
  //
  // # Static Configuration
  // This refers to constant values that are used throughout the applet. These are are baked-in
  // during compilation and are therefore immutable without a new applet version being released.
  //
  // # Dynamic Configuration
  // This refers to values that can be are also used to drive applet behaviour, but can be set via
  // an administrative command (PUT DATA ADMIN).
  //
  /////////////////////////////////////////////////////////////////////////////////////////////////

  /////////////////////////////////////
  //
  // STATIC CONFIGURATION
  //
  /////////////////////////////////////

  //
  // BUILD CONFIGURATION
  //
  // This information is updated prior to release build. It is not updated
  // automatically yet and has no causal relationship with commits, so the
  // value should only be trusted when read from a release.
  //
  static final byte VERSION_MAJOR = (byte) 2;
  static final byte VERSION_MINOR = (byte) 0;
  static final byte VERSION_REVISION = (byte) 0;

  //
  // FIPS-140 Approve Mode flag
  // NOTE: If this flag is set to true, the applet is compiled with baked-in rules that enforce
  // the minimum requirements to maintain the applet in the Approve Mode for FIPS 140 certification.
  //
  static final boolean FIPS_APPROVED_MODE = true;

  // If this value is non-zero, the executable is considered to be a test build
  // and MUST NOT be used for production purposes
  static final boolean VERSION_DEBUG = false;

  //
  // DEBUG - FIPS-140 flag to support access to the SP800 KDA and KC algorithms for
  // ACVP testing purposes.
  // NOTE: The applet will fail to install if this is true and VERSION_DEBUG is set to false. 
  //
  static final boolean DEBUG_FIPS_RUN_ACVP = false;

  //
  // DEBUG - FIPS-140 flag to deliberately cause a failure in the Cryptographic Algorithm
  // Self-Test routine.
  // NOTE: The applet will fail to install if this is true and VERSION_DEBUG is set to false. 
  //
  static final boolean DEBUG_FIPS_FAIL_CAST = false;

  // DEBUG - Flag to return fixed data for all calls to the generateRandom() method
  // NOTE: The applet will fail to install if this is true and VERSION_DEBUG is set to false. 
  static final boolean DEBUG_FIXED_RANDOM = false;

  // ----------------------------
  // TRANSIENT MEMORY ALLOCATION
  // ----------------------------
  // The amount of memory to allocate to the applet RAM buffer.

  // This dictates the maximum APDU size that can be received with chaining and
  // is largely based on the need to support RSA-4096 key/block lengths, in particular
  // a General Authenticate request with a pre-formatted signature block and a request
  // for a response.
  //
  // The structure of this would be:
  // [T:7C] [L:82 04 06] [V:82 00 81 82 04 00 .. 512 bytes ..]
  // = 10 + 512 bytes = 522 bytes
  // + PIVSM Wrapping = 8782nnnn01[DATA][ISO9797-M2-PADDING][STATUS-TLV][RMAC-TLV]
  // = 5 + 522 + 10 + 4 + 10 = 551
  // + Round to nearest 16-bye boundary
  // = 551 + 9 = 560
  // NOTE:
  // - Neither SCP03 nor PIV-SM affect this as they are unwrapped/processed against the card's
  // APDU buffer and the result is copied to our own internal buffer.
  //
  static final short LENGTH_PIV_APDU_BUFFER = (short) 560;

  // The default key reference for PIV Administration
  static final byte DEFAULT_ADMIN_KEY = (byte) 0x9B;

  // The default key reference for PIV Secure Messaging
  static final byte DEFAULT_PIVSM_KEY = (byte) 0x04;

  // The default value for the special DISCOVERY object
  static final byte[] TEMPLATE_DISCOVERY = new byte[] {

      /// 2 bytes - Discovery Object (TAG '7E')
      (byte) 0x7E, (byte) 0x12, //

      // 2 + 11 bytes - PIV Card Application AID (TAG '4F')
      (byte) 0x4F, (byte) 0x0B, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00,
      (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00,

      // 3 + 2 bytes - PIN Usage Policy
      (byte) 0x5F, (byte) 0x2F, (byte) 0x02,

      // The remaining 2 policy bytes are set dynamically when the discovery object is read
      (byte) 0x00, (byte) 0x00 };

  // Application Property Template (TAG '61')
  static final byte APT_TAG = (byte) 0x61;

  // Application identifier of application (TAG '4F')
  static final byte APT_AID_TAG = (byte) 0x4F;
  static final byte[] APT_AID_DATA = { (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte) 0x00,
      (byte) 0x00, (byte) 0x10, (byte) 0x00, (byte) 0x01, (byte) 0x00 };

  // Coexistent Tag Allocation Authority (TAG '79')
  static final byte APT_CTAA_TAG = (byte) 0x79;
  static final byte[] APT_CTAA_DATA = { (byte) 0x4F, (byte) 0x05, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03,
      (byte) 0x08 };

  // 2 + 11 bytes - Application label (TAG '50')
  static final byte APT_LABEL_TAG = (byte) 0x50;

  static final byte[] APT_LABEL_DATA = { 'O', 'p', 'e', 'n', 'F', 'I', 'P', 'S', '2', '0', '1' };

  // Uniform resource locator (TAG '5F50')
  // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
  static final short APT_URL_TAG = (short) 0x5F50;
  static final byte[] APT_URL_DATA = { 'h', 't', 't', 'p', ':', '/', '/', 'n', 'v', 'l', 'p', 'u', 'b', 's', '.', 'n',
      'i', 's', 't', '.', 'g', 'o', 'v', '/', 'n', 'i', 's', 't', 'p', 'u', 'b', 's', '/', 'S', 'p', 'e', 'c', 'i', 'a',
      'l', 'P', 'u', 'b', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', 's', '/', 'N', 'I', 'S', 'T', '.', 'S', 'P', '.', '8',
      '0', '0', '-', '7', '3', '-', '4', '.', 'p', 'd', 'f' };

  // 2 + 6 - Cryptographic Algorithm Identifier Template (Tag 'AC')
  static final byte APT_AC_TAG = (byte) 0xAC;
  static final byte[] APT_AC_DATA_CS2 = { (byte) 0x80, (byte) 0x01, (byte) 0x27, (byte) 0x06, (byte) 0x01,
      (byte) 0x00 };
  static final byte[] APT_AC_DATA_CS7 = { (byte) 0x80, (byte) 0x01, (byte) 0x2E, (byte) 0x06, (byte) 0x01,
      (byte) 0x00 };

  //
  // DYNAMIC CONFIGURATION DEFINITIONS
  //
  // This static section defines all configurable parameters within the OpenFIPS201
  // applet. The numbering system here defines the internal storage (array offset)
  // for each parameter, not the ASN.1 definitions
  //
  // The takeaway from this is, don't rely at all on the integer value of these
  // constants to provide meaning across versions, use the ASN.1 instead!
  //

  // The number of records in the configuration table.
  private static final short LENGTH_CONFIG = (short) 5;

  // ASN1_BOOLEAN - If set to TRUE, the applet may not be selected over the contactless interface
  // Default: FALSE
  static final byte CONFIG_RESTRICT_CONTACTLESS_GLOBAL = (byte) 0;

  // ASN1_BOOLEAN - If TRUE, admin functions are disabled over the contactless interface 
  // Default: FALSE
  static final byte CONFIG_RESTRICT_CONTACTLESS_ADMIN = (byte) 1;

  // ASN1_BOOLEAN - If TRUE, object listing functionality is disabled 
  // Default: FALSE
  static final byte CONFIG_RESTRICT_ENUMERATION = (byte) 2;

  // ASN1_BOOLEAN - If TRUE, object listing functionality is disabled 
  // Default: FALSE
  static final byte CONFIG_RESTRICT_GET_RANDOM = (byte) 3;

  // ASN1_BOOLEAN - If TRUE, all contactless operations are permitted over VCI as if contact. 
  // Default: FALSE
  static final byte CONFIG_VCI_COMPATIBILITY_MODE = (byte) 4;

  //
  // ASN.1 TAGS - Primitive (Elements)
  //
  private static final byte TAG_RESTRICT_CONTACTLESS_GLOBAL = (byte) 0x80;
  private static final byte TAG_RESTRICT_CONTACTLESS_ADMIN = (byte) 0x81;
  private static final byte TAG_RESTRICT_ENUMERATION = (byte) 0x82;
  private static final byte TAG_RESTRICT_GET_RANDOM = (byte) 0x83;
  private static final byte TAG_VCI_COMPATIBILITY_MODE = (byte) 0x84;

  /////////////////////////////////////
  //
  // DYNAMIC CONFIGURATION
  //
  /////////////////////////////////////

  // PERSISTENT - Internal configuration table
  private final byte[] parameters;

  Config() {
    parameters = new byte[LENGTH_CONFIG];
  }

  boolean readFlag(byte address) {
    return (parameters[address] != (byte) 0);
  }

  private void setFlag(byte address, byte value) {
    parameters[address] = (value == (byte) 0 ? TLV.FALSE : TLV.TRUE);
  }

  short getConfig(TLVWriter writer) {
    writer.write(TAG_RESTRICT_CONTACTLESS_GLOBAL, parameters[CONFIG_RESTRICT_CONTACTLESS_GLOBAL]);
    writer.write(TAG_RESTRICT_CONTACTLESS_ADMIN, parameters[CONFIG_RESTRICT_CONTACTLESS_ADMIN]);
    writer.write(TAG_RESTRICT_ENUMERATION, parameters[CONFIG_RESTRICT_ENUMERATION]);
    writer.write(TAG_RESTRICT_GET_RANDOM, parameters[CONFIG_RESTRICT_GET_RANDOM]);
    writer.write(TAG_VCI_COMPATIBILITY_MODE, parameters[CONFIG_VCI_COMPATIBILITY_MODE]);
    return writer.finish();
  }
  
  void update(TLVReader reader) {

    // NOTES:
    // - Due to all configuration parameters being optional, pre-conditions are evaluated in each
    // section on-the-fly rather than all prior to execution.
    // - To save on validation code, any boolean value is just stored as a byte and any non-zero
    // value is considered True.
    // - No transaction management is implemented here, so it must be managed by the caller instead

    // Sanity check for empty constructed tag
    if (reader.isNull()) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }

    // Restrict Contactless - Global
    if (reader.match(TAG_RESTRICT_CONTACTLESS_GLOBAL)) {
      setFlag(CONFIG_RESTRICT_CONTACTLESS_GLOBAL, reader.toByte());
      reader.moveNext();
    }

    // Restrict Contactless - Admin
    if (reader.match(TAG_RESTRICT_CONTACTLESS_ADMIN)) {
      setFlag(CONFIG_RESTRICT_CONTACTLESS_ADMIN, reader.toByte());
      reader.moveNext();
    }

    // Restrict Enumeration
    if (reader.match(TAG_RESTRICT_ENUMERATION)) {
      setFlag(CONFIG_RESTRICT_ENUMERATION, reader.toByte());
      reader.moveNext();
    }

    // Restrict Enumeration
    if (reader.match(TAG_RESTRICT_GET_RANDOM)) {
      setFlag(CONFIG_RESTRICT_GET_RANDOM, reader.toByte());
      reader.moveNext();
    }

    // Restrict Enumeration
    if (reader.match(TAG_VCI_COMPATIBILITY_MODE)) {
      setFlag(CONFIG_VCI_COMPATIBILITY_MODE, reader.toByte());
      reader.moveNext();
    }
  }
}
