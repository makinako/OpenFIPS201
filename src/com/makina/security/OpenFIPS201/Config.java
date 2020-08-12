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

/**
 * Defines all configurable elements of the PIV applet in one place. This allows customisation of
 * the data and key file system as well as controlling the behaviour of the applet.
 */
public abstract class Config {

  ///////////////////////////////////////////////////////////////////////////
  //
  // APPLET CONFIGURATION
  //
  // NOTE: These flags describe various features that can enable optional functionality
  // within the PIV standard or to govern applet behaviour. Care must be taken when setting
  // these as there can be serious security and functional repercussions for incorrect values.
  // Because these are all marked as 'static final', the compiler should remove any code relating
  // to disabled features as an optimisation (if code optimisation is used).
  //
  // Any change to these features should be considered a software change and re-testing should
  // then apply.
  //
  ///////////////////////////////////////////////////////////////////////////

  /// !!!!!!! WARNING !!!!!!!
  /// This must only be enabled for protocol debugging and analysis, as this forces the applet
  /// to use FIXED values for cryptographic nonces and will cripple security.
  /// !!!!!!! WARNING !!!!!!!
  /// SP800-73-4 Requirement: Must be set to false
  public static final boolean FEATURE_PIV_TEST_VECTORS = false;

  /// Indicates that the mandatory PIV Card Application PIN satisfies the PIV Access Control
  /// Rules (ACRs) for command execution and data object access.
  /// NOTE: This also sets the corresponding bit in the Discovery object
  /// (See SP800-73-4 Part1 - 3.3.2 Discovery Object)
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PIN_CARD_ENABLED = true;

  /// Indicates that the optional Global PIN feature of PIV is enabled
  /// NOTE: This also sets the corresponding bit in the default Discovery object
  /// (See SP800-73-4 Part1 - 3.3.2 Discovery Object)
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PIN_GLOBAL_ENABLED = false;

  /// Indicates that the Global PIN is the primary PIN used to satisfy the
  /// PIV ACRs for command execution and object access.
  ///
  /// NOTE: This ONLY sets the the default value in the default Discovery object
  /// and DOES NOT prevent this being overwritten by a CMS
  /// (See SP800-73-4 Part1 - 3.3.2 Discovery Object)
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PIN_GLOBAL_PREFERRED = false;

  /// Indicates that the Global PIN may be updated by the PIV applet.
  /// NOTE: If enabled the applet must be installed with the GlobalPlatform CVM MANAGEMENT
  /// flag set, or the functionality will not work.
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PIN_GLOBAL_CHANGE = false;

  /// Indicates that the PIN will be set to a random value at applet instantiation.
  /// If this is not set, the PIN will be initialised to a default value
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PIN_INIT_RANDOM = true;

  /// Indicates that the PUK may be updated by the PIV applet.
  /// (See SP800-73-4 Part2 - 3.2.2 CHANGE REFERENCE DATA Card Command)
  /// NOTE: Regardless of this setting, the PUK can be changed via a GP SCP session
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PUK_CHANGE = true;

  /// Indicates that the PUK will be set to a random value at applet instantiation.
  /// If this is not set, the PUK will be initialised to a default value
  /// SP800-73-4 Requirement: Issuer-defined
  public static final boolean FEATURE_PUK_INIT_RANDOM = true;

  /// Permits the PIN to be used over contactless without the need for the VCI condition.
  /// SP800-73-4 Requirement: Must be set to false
  public static final boolean FEATURE_PIN_OVER_CONTACTLESS = false;

  /// Permits the PUK to be used over contactless without the need for the VCI condition.
  /// SP800-73-4 Requirement: Must be set to false
  public static final boolean FEATURE_PUK_OVER_CONTACTLESS = false;

  /// If set to true, authentication to GlobalPlatform will fail on the contactless
  /// interface.
  /// NOTE: This does not restrict the usage of keys with the ROLE_ADMIN role set (i.e. 9B),
  ///		 which must be configured individually during pre-personalization.
  /// SP800-73-4 Requirement: Must be set to true
  public static final boolean FEATURE_RESTRICT_SCP_TO_CONTACT = true;

  /// If set to true, a call to GET DATA for an object that exists in the file system,
  /// but which has not been initialised with data will result in SW_FILE_NOT_FOUND.
  /// If set to false, it will return an empty data field with SW_OK.
  /// SP800-73-4 Requirement: Not clearly defined, suggest true
  public static final boolean FEATURE_ERROR_ON_EMPTY_DATA_OBJECT = true;

  /// If set to true, when the discovery object is created it will automatically
  /// be populated with a default value based on the configured parameters (specifically
  /// the PIN policy element dynamic elements).
  /// NOTE: This does not prevent the card management system from overwriting this
  /// object, including with an incorrect value
  /// SP800-73-4 Requirement: Not specified under PIV (extension functionality)
  public static final boolean FEATURE_DISCOVERY_OBJECT_DEFAULT = true;

  // If set to true, the applet will return SW_LAST_COMMAND_EXPECTED if a chained APDU is
  // not completed. The implication of this is that if a chained INCOMING or OUTGOING
  // APDU is cancelled by the host by starting a new APDU, an error will be produced.
  //
  /// SP800-73-4 Requirement: Not specified under PIV (extension functionality)
  public static final boolean FEATURE_STRICT_APDU_CHAINING = false;

  ///////////////////////////////////////////////////////////////////////////
  //
  // PIN and PUK CONFIGURATION
  //
  ///////////////////////////////////////////////////////////////////////////

  /// The number of retries before the PIN object is blocked
  /// SP800-73-4 Requirement: Issuer-defined
  public static final byte PIN_RETRIES = (byte) 6;

  /// The number of retries that the PIN object will not be permitted to go below over
  /// the contactless interface. Setting to zero effectively disables this option.
  /// SP800-73-4 Requirement: Issuer-defined
  public static final byte PIN_RETRIES_INTERMEDIATE = (byte) 1;

  /// The number of retries before the PUK object is blocked
  /// SP800-73-4 Requirement: Issuer-defined
  public static final byte PUK_RETRIES = (byte) 6;

  /// The number of retries that the PUK object will not be permitted to go below over
  /// the contactless interface. Setting to zero effectively disables this option.
  /// SP800-73-4 Requirement: Issuer-defined
  public static final byte PUK_RETRIES_INTERMEDIATE = (byte) 1;

  /// The minimum length of the PIN value (SP800-73-4 default is '6')
  /// NOTE: Changing this value from its default will break PIV compliance
  /// SP800-73-4 Requirement: Must be set to 6
  public static final byte PIN_LENGTH_MIN = (byte) 6;

  /// The maximum length of the PIN value (SP800-73-4 default is '8')
  /// NOTE: Changing this value from its default will break PIV compliance
  /// SP800-73-4 Requirement: Must be set to 8
  public static final byte PIN_LENGTH_MAX = (byte) 8;

  ///////////////////////////////////////////////////////////////////////////
  //
  // PIV CONSTANT DEFINITIONS
  //
  // This section defines the PIV constant values for a number of different
  // data objects. They should be generally not changed, or changed with
  // great care.
  //
  ///////////////////////////////////////////////////////////////////////////

  /// If FEATURE_PIN_INIT_RANDOM is not set, this will be the default value for the Card PIN object
  protected static final byte[] DEFAULT_PIN =
      new byte[] {
        (byte) 0x31,
        (byte) 0x32,
        (byte) 0x33,
        (byte) 0x34,
        (byte) 0x35,
        (byte) 0x36,
        (byte) 0xFF,
        (byte) 0xFF
      };

  /// If FEATURE_PUK_INIT_RANDOM is not set, this will be the default value for the Card PUK object
  protected static final byte[] DEFAULT_PUK =
      new byte[] {
        (byte) 0x31,
        (byte) 0x32,
        (byte) 0x33,
        (byte) 0x34,
        (byte) 0x35,
        (byte) 0x36,
        (byte) 0x37,
        (byte) 0x38
      };

  /// Holds pre-defined random data for use when FEATURE_PIV_TEST_VECTOR is enabled
  protected static final byte[] TEST_VECTOR_RANDOM =
      new byte[] {
        (byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06,
            (byte) 0x07,
        (byte) 0x08, (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C, (byte) 0x0D, (byte) 0x0E,
            (byte) 0x0F,
        (byte) 0x10, (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16,
            (byte) 0x17,
        (byte) 0x18, (byte) 0x19, (byte) 0x1A, (byte) 0x1B, (byte) 0x1C, (byte) 0x1D, (byte) 0x1E,
            (byte) 0x1F
      };

  protected static final byte[] TEST_P256_CARD_AUTH_PRIVATE_KEY =
      new byte[] {
        (byte) 0x69, (byte) 0x93, (byte) 0x4B, (byte) 0x97, (byte) 0x01, (byte) 0x01, (byte) 0x91,
            (byte) 0x39,
        (byte) 0x0D, (byte) 0x8B, (byte) 0xB0, (byte) 0xA1, (byte) 0xEA, (byte) 0x31, (byte) 0x9D,
            (byte) 0x88,
        (byte) 0x57, (byte) 0x9D, (byte) 0xE2, (byte) 0xC6, (byte) 0x93, (byte) 0x63, (byte) 0x88,
            (byte) 0x0F,
        (byte) 0xF8, (byte) 0x09, (byte) 0x8E, (byte) 0x72, (byte) 0x14, (byte) 0x84, (byte) 0xEF,
            (byte) 0x28
      };

  protected static final byte[] TEST_P256_CARD_AUTH_PUBLIC_KEY =
      new byte[] {
        (byte) 0x04, (byte) 0x48, (byte) 0x7C, (byte) 0xB4, (byte) 0xCA, (byte) 0xBE, (byte) 0xCF,
            (byte) 0x15,
        (byte) 0x14, (byte) 0x1E, (byte) 0x89, (byte) 0x60, (byte) 0x0A, (byte) 0x88, (byte) 0x3C,
            (byte) 0x7D,
        (byte) 0xB6, (byte) 0x70, (byte) 0xE7, (byte) 0x7B, (byte) 0xCA, (byte) 0x84, (byte) 0xEE,
            (byte) 0xBB,
        (byte) 0x03, (byte) 0x57, (byte) 0x31, (byte) 0x33, (byte) 0x55, (byte) 0x19, (byte) 0x2E,
            (byte) 0x02,
        (byte) 0x16, (byte) 0xDF, (byte) 0x65, (byte) 0xA9, (byte) 0x6E, (byte) 0x13, (byte) 0x2B,
            (byte) 0xA3,
        (byte) 0xF2, (byte) 0xB8, (byte) 0x95, (byte) 0xD9, (byte) 0xE7, (byte) 0xA0, (byte) 0xDB,
            (byte) 0x38,
        (byte) 0xE3, (byte) 0x8D, (byte) 0x48, (byte) 0x59, (byte) 0xB0, (byte) 0x99, (byte) 0x4E,
            (byte) 0x5A,
        (byte) 0xE3, (byte) 0xD4, (byte) 0x42, (byte) 0xD8, (byte) 0x96, (byte) 0x08, (byte) 0xF4,
            (byte) 0xB7,
        (byte) 0x84
      };

  protected static final byte[] TEST_P256_CARD_AUTH_CERTIFICATE =
      new byte[] {
        (byte) 0x30, (byte) 0x82, (byte) 0x03, (byte) 0x49, (byte) 0x30, (byte) 0x82, (byte) 0x02,
            (byte) 0xf0,
        (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x01,
            (byte) 0x04,
        (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0xce,
        (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x55, (byte) 0x31,
            (byte) 0x0b,
        (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06,
            (byte) 0x13,
        (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x06, (byte) 0x47,
            (byte) 0x6f,
        (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x0f, (byte) 0x30,
            (byte) 0x0d,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x13, (byte) 0x06,
            (byte) 0x50,
        (byte) 0x68, (byte) 0x79, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x31, (byte) 0x24,
            (byte) 0x30,
        (byte) 0x22, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13,
            (byte) 0x1b,
        (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20,
            (byte) 0x54,
        (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72,
            (byte) 0x64,
        (byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x69, (byte) 0x6e,
            (byte) 0x67,
        (byte) 0x20, (byte) 0x43, (byte) 0x41, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d,
            (byte) 0x31,
        (byte) 0x38, (byte) 0x30, (byte) 0x35, (byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x30,
            (byte) 0x30,
        (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x33,
            (byte) 0x32,
        (byte) 0x31, (byte) 0x31, (byte) 0x33, (byte) 0x30, (byte) 0x32, (byte) 0x33, (byte) 0x35,
            (byte) 0x39,
        (byte) 0x35, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x5e, (byte) 0x31, (byte) 0x0b,
            (byte) 0x30,
        (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
            (byte) 0x02,
        (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
            (byte) 0x03,
        (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x06, (byte) 0x47, (byte) 0x6f,
            (byte) 0x6f,
        (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x13, (byte) 0x06, (byte) 0x50,
            (byte) 0x68,
        (byte) 0x79, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x31, (byte) 0x2d, (byte) 0x30,
            (byte) 0x2b,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x05, (byte) 0x13, (byte) 0x24,
            (byte) 0x62,
        (byte) 0x65, (byte) 0x31, (byte) 0x32, (byte) 0x37, (byte) 0x65, (byte) 0x61, (byte) 0x30,
            (byte) 0x2d,
        (byte) 0x64, (byte) 0x31, (byte) 0x38, (byte) 0x30, (byte) 0x2d, (byte) 0x31, (byte) 0x32,
            (byte) 0x34,
        (byte) 0x64, (byte) 0x2d, (byte) 0x65, (byte) 0x30, (byte) 0x34, (byte) 0x34, (byte) 0x2d,
            (byte) 0x30,
        (byte) 0x30, (byte) 0x30, (byte) 0x66, (byte) 0x32, (byte) 0x30, (byte) 0x32, (byte) 0x62,
            (byte) 0x32,
        (byte) 0x33, (byte) 0x35, (byte) 0x61, (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13,
            (byte) 0x06,
        (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02,
            (byte) 0x01,
        (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
            (byte) 0x03,
        (byte) 0x01, (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0x48,
            (byte) 0x7c,
        (byte) 0xb4, (byte) 0xca, (byte) 0xbe, (byte) 0xcf, (byte) 0x15, (byte) 0x14, (byte) 0x1e,
            (byte) 0x89,
        (byte) 0x60, (byte) 0x0a, (byte) 0x88, (byte) 0x3c, (byte) 0x7d, (byte) 0xb6, (byte) 0x70,
            (byte) 0xe7,
        (byte) 0x7b, (byte) 0xca, (byte) 0x84, (byte) 0xee, (byte) 0xbb, (byte) 0x03, (byte) 0x57,
            (byte) 0x31,
        (byte) 0x33, (byte) 0x55, (byte) 0x19, (byte) 0x2e, (byte) 0x02, (byte) 0x16, (byte) 0xdf,
            (byte) 0x65,
        (byte) 0xa9, (byte) 0x6e, (byte) 0x13, (byte) 0x2b, (byte) 0xa3, (byte) 0xf2, (byte) 0xb8,
            (byte) 0x95,
        (byte) 0xd9, (byte) 0xe7, (byte) 0xa0, (byte) 0xdb, (byte) 0x38, (byte) 0xe3, (byte) 0x8d,
            (byte) 0x48,
        (byte) 0x59, (byte) 0xb0, (byte) 0x99, (byte) 0x4e, (byte) 0x5a, (byte) 0xe3, (byte) 0xd4,
            (byte) 0x42,
        (byte) 0xd8, (byte) 0x96, (byte) 0x08, (byte) 0xf4, (byte) 0xb7, (byte) 0x84, (byte) 0xa3,
            (byte) 0x82,
        (byte) 0x01, (byte) 0xa6, (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0xa2, (byte) 0x30,
            (byte) 0x1d,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16,
            (byte) 0x04,
        (byte) 0x14, (byte) 0x8d, (byte) 0x7c, (byte) 0xbe, (byte) 0x73, (byte) 0x88, (byte) 0xc8,
            (byte) 0x2d,
        (byte) 0xf6, (byte) 0xac, (byte) 0x5f, (byte) 0x9c, (byte) 0xcc, (byte) 0x94, (byte) 0x7a,
            (byte) 0x7c,
        (byte) 0x89, (byte) 0x06, (byte) 0x0c, (byte) 0xb9, (byte) 0xf7, (byte) 0x30, (byte) 0x1f,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x18, (byte) 0x30,
            (byte) 0x16,
        (byte) 0x80, (byte) 0x14, (byte) 0x3f, (byte) 0x07, (byte) 0x9e, (byte) 0xe5, (byte) 0x85,
            (byte) 0x4c,
        (byte) 0xc7, (byte) 0x6a, (byte) 0x02, (byte) 0xda, (byte) 0x70, (byte) 0xfe, (byte) 0x20,
            (byte) 0x2e,
        (byte) 0x36, (byte) 0x2b, (byte) 0x6c, (byte) 0x5b, (byte) 0x42, (byte) 0xf8, (byte) 0x30,
            (byte) 0x0e,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01, (byte) 0x01,
            (byte) 0xff,
        (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x07, (byte) 0x80, (byte) 0x30,
            (byte) 0x38,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x11, (byte) 0x04, (byte) 0x31,
            (byte) 0x30,
        (byte) 0x2f, (byte) 0x86, (byte) 0x2d, (byte) 0x75, (byte) 0x72, (byte) 0x6e, (byte) 0x3a,
            (byte) 0x75,
        (byte) 0x75, (byte) 0x69, (byte) 0x64, (byte) 0x3a, (byte) 0x62, (byte) 0x65, (byte) 0x31,
            (byte) 0x32,
        (byte) 0x37, (byte) 0x65, (byte) 0x61, (byte) 0x30, (byte) 0x2d, (byte) 0x64, (byte) 0x31,
            (byte) 0x38,
        (byte) 0x30, (byte) 0x2d, (byte) 0x31, (byte) 0x32, (byte) 0x34, (byte) 0x64, (byte) 0x2d,
            (byte) 0x65,
        (byte) 0x30, (byte) 0x34, (byte) 0x34, (byte) 0x2d, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x66,
        (byte) 0x32, (byte) 0x30, (byte) 0x32, (byte) 0x62, (byte) 0x32, (byte) 0x33, (byte) 0x35,
            (byte) 0x61,
        (byte) 0x30, (byte) 0x56, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x1f,
            (byte) 0x04,
        (byte) 0x4f, (byte) 0x30, (byte) 0x4d, (byte) 0x30, (byte) 0x4b, (byte) 0xa0, (byte) 0x49,
            (byte) 0xa0,
        (byte) 0x47, (byte) 0x86, (byte) 0x45, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x3a,
        (byte) 0x2f, (byte) 0x2f, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70, (byte) 0x2e,
            (byte) 0x61,
        (byte) 0x70, (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x2e,
        (byte) 0x63, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66, (byte) 0x70,
            (byte) 0x6b,
        (byte) 0x69, (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e, (byte) 0x67,
            (byte) 0x6f,
        (byte) 0x76, (byte) 0x2f, (byte) 0x63, (byte) 0x72, (byte) 0x6c, (byte) 0x73, (byte) 0x2f,
            (byte) 0x49,
        (byte) 0x43, (byte) 0x41, (byte) 0x4d, (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x43,
        (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e,
            (byte) 0x69,
        (byte) 0x6e, (byte) 0x67, (byte) 0x43, (byte) 0x41, (byte) 0x2e, (byte) 0x63, (byte) 0x72,
            (byte) 0x6c,
        (byte) 0x30, (byte) 0x18, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x20,
            (byte) 0x04,
        (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06, (byte) 0x0b,
            (byte) 0x60,
        (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x02, (byte) 0x01,
            (byte) 0x30,
        (byte) 0x81, (byte) 0x79, (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x06, (byte) 0x08,
            (byte) 0x2b,
        (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x01, (byte) 0x01,
            (byte) 0x04,
        (byte) 0x81, (byte) 0x96, (byte) 0x30, (byte) 0x81, (byte) 0x93, (byte) 0x30, (byte) 0x5d,
            (byte) 0x06,
        (byte) 0x08, (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
            (byte) 0x30,
        (byte) 0x02, (byte) 0x86, (byte) 0x51, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x3a,
        (byte) 0x2f, (byte) 0x2f, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70, (byte) 0x2e,
            (byte) 0x61,
        (byte) 0x70, (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x2e,
        (byte) 0x63, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66, (byte) 0x70,
            (byte) 0x6b,
        (byte) 0x69, (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e, (byte) 0x67,
            (byte) 0x6f,
        (byte) 0x76, (byte) 0x2f, (byte) 0x61, (byte) 0x69, (byte) 0x61, (byte) 0x2f, (byte) 0x63,
            (byte) 0x65,
        (byte) 0x72, (byte) 0x74, (byte) 0x73, (byte) 0x49, (byte) 0x73, (byte) 0x73, (byte) 0x75,
            (byte) 0x65,
        (byte) 0x64, (byte) 0x54, (byte) 0x6f, (byte) 0x49, (byte) 0x43, (byte) 0x41, (byte) 0x4d,
            (byte) 0x54,
        (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64,
            (byte) 0x53,
        (byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x43,
            (byte) 0x41,
        (byte) 0x2e, (byte) 0x70, (byte) 0x37, (byte) 0x63, (byte) 0x30, (byte) 0x32, (byte) 0x06,
            (byte) 0x08,
        (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x30,
            (byte) 0x01,
        (byte) 0x86, (byte) 0x26, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70, (byte) 0x3a,
            (byte) 0x2f,
        (byte) 0x2f, (byte) 0x6f, (byte) 0x63, (byte) 0x73, (byte) 0x70, (byte) 0x2e, (byte) 0x61,
            (byte) 0x70,
        (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x2e,
            (byte) 0x63,
        (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66, (byte) 0x70, (byte) 0x6b,
            (byte) 0x69,
        (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e, (byte) 0x67, (byte) 0x6f,
            (byte) 0x76,
        (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0xce,
        (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x47, (byte) 0x00,
            (byte) 0x30,
        (byte) 0x44, (byte) 0x02, (byte) 0x20, (byte) 0x42, (byte) 0x56, (byte) 0x22, (byte) 0x0e,
            (byte) 0x81,
        (byte) 0xf9, (byte) 0xb1, (byte) 0xf4, (byte) 0x15, (byte) 0x88, (byte) 0x0d, (byte) 0x27,
            (byte) 0xd8,
        (byte) 0x39, (byte) 0x2b, (byte) 0x3f, (byte) 0x50, (byte) 0x12, (byte) 0xd0, (byte) 0x49,
            (byte) 0x9c,
        (byte) 0x4a, (byte) 0x0f, (byte) 0xd6, (byte) 0x93, (byte) 0x33, (byte) 0xab, (byte) 0x68,
            (byte) 0xae,
        (byte) 0x3c, (byte) 0xfd, (byte) 0x33, (byte) 0x02, (byte) 0x20, (byte) 0x34, (byte) 0xec,
            (byte) 0x0e,
        (byte) 0x26, (byte) 0x3d, (byte) 0x25, (byte) 0xa1, (byte) 0x7e, (byte) 0xef, (byte) 0x41,
            (byte) 0x20,
        (byte) 0x91, (byte) 0x6e, (byte) 0xcc, (byte) 0xf5, (byte) 0x50, (byte) 0x24, (byte) 0x38,
            (byte) 0x27,
        (byte) 0x70, (byte) 0x68, (byte) 0xa0, (byte) 0xb3, (byte) 0x2f, (byte) 0x5c, (byte) 0x50,
            (byte) 0x68,
        (byte) 0x91, (byte) 0x86, (byte) 0x1d, (byte) 0xe5, (byte) 0xcc
      };

  protected static final byte[] TEST_P256_PIV_AUTH_PRIVATE_KEY =
      new byte[] {
        (byte) 0x6C, (byte) 0xBD, (byte) 0x2B, (byte) 0x88, (byte) 0xE1, (byte) 0x89, (byte) 0xE2,
            (byte) 0xBB,
        (byte) 0x5D, (byte) 0x6B, (byte) 0xAC, (byte) 0x65, (byte) 0xCB, (byte) 0xD5, (byte) 0x0E,
            (byte) 0x91,
        (byte) 0xA7, (byte) 0x82, (byte) 0x47, (byte) 0x4B, (byte) 0xE2, (byte) 0x0F, (byte) 0x39,
            (byte) 0x55,
        (byte) 0x76, (byte) 0x02, (byte) 0xD3, (byte) 0xDA, (byte) 0x3D, (byte) 0x98, (byte) 0x10,
            (byte) 0x03
      };

  protected static final byte[] TEST_P256_PIV_AUTH_PUBLIC_KEY =
      new byte[] {
        (byte) 0x04, (byte) 0xBF, (byte) 0x0A, (byte) 0xF1, (byte) 0xC1, (byte) 0xFA, (byte) 0x28,
            (byte) 0xAC,
        (byte) 0x00, (byte) 0xE3, (byte) 0xD1, (byte) 0x28, (byte) 0x42, (byte) 0xDB, (byte) 0x99,
            (byte) 0x64,
        (byte) 0xD3, (byte) 0xBA, (byte) 0x1A, (byte) 0x53, (byte) 0xE2, (byte) 0x8B, (byte) 0x69,
            (byte) 0x7F,
        (byte) 0xCE, (byte) 0x0F, (byte) 0xE3, (byte) 0xFD, (byte) 0xAE, (byte) 0xC5, (byte) 0xE5,
            (byte) 0x51,
        (byte) 0xF2, (byte) 0xBE, (byte) 0x8F, (byte) 0xA2, (byte) 0x7B, (byte) 0x9A, (byte) 0xE9,
            (byte) 0xB8,
        (byte) 0x1E, (byte) 0xB8, (byte) 0xD5, (byte) 0x0E, (byte) 0x48, (byte) 0xE4, (byte) 0x1C,
            (byte) 0x23,
        (byte) 0x5F, (byte) 0x30, (byte) 0xA7, (byte) 0xB6, (byte) 0x23, (byte) 0xF2, (byte) 0x1F,
            (byte) 0xBB,
        (byte) 0x6E, (byte) 0x1D, (byte) 0x4A, (byte) 0xA8, (byte) 0x1B, (byte) 0x5B, (byte) 0x3D,
            (byte) 0xB3,
        (byte) 0xC2
      };

  protected static final byte[] TEST_P256_PIV_AUTH_CERTIFICATE =
      new byte[] {
        (byte) 0x30, (byte) 0x82, (byte) 0x03, (byte) 0x74, (byte) 0x30, (byte) 0x82, (byte) 0x03,
            (byte) 0x19,
        (byte) 0xa0, (byte) 0x03, (byte) 0x02, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x01,
            (byte) 0x05,
        (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0xce,
        (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x30, (byte) 0x55, (byte) 0x31,
            (byte) 0x0b,
        (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06,
            (byte) 0x13,
        (byte) 0x02, (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x06, (byte) 0x47,
            (byte) 0x6f,
        (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x0f, (byte) 0x30,
            (byte) 0x0d,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x13, (byte) 0x06,
            (byte) 0x50,
        (byte) 0x68, (byte) 0x79, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x31, (byte) 0x24,
            (byte) 0x30,
        (byte) 0x22, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13,
            (byte) 0x1b,
        (byte) 0x47, (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20,
            (byte) 0x54,
        (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72,
            (byte) 0x64,
        (byte) 0x20, (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x69, (byte) 0x6e,
            (byte) 0x67,
        (byte) 0x20, (byte) 0x43, (byte) 0x41, (byte) 0x30, (byte) 0x1e, (byte) 0x17, (byte) 0x0d,
            (byte) 0x31,
        (byte) 0x38, (byte) 0x30, (byte) 0x35, (byte) 0x32, (byte) 0x36, (byte) 0x30, (byte) 0x30,
            (byte) 0x30,
        (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x5a, (byte) 0x17, (byte) 0x0d, (byte) 0x33,
            (byte) 0x32,
        (byte) 0x31, (byte) 0x31, (byte) 0x32, (byte) 0x39, (byte) 0x32, (byte) 0x33, (byte) 0x35,
            (byte) 0x39,
        (byte) 0x35, (byte) 0x39, (byte) 0x5a, (byte) 0x30, (byte) 0x66, (byte) 0x31, (byte) 0x0b,
            (byte) 0x30,
        (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
            (byte) 0x02,
        (byte) 0x55, (byte) 0x53, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
            (byte) 0x03,
        (byte) 0x55, (byte) 0x04, (byte) 0x0a, (byte) 0x13, (byte) 0x06, (byte) 0x47, (byte) 0x6f,
            (byte) 0x6f,
        (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x31, (byte) 0x0f, (byte) 0x30, (byte) 0x0d,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0b, (byte) 0x13, (byte) 0x06, (byte) 0x50,
            (byte) 0x68,
        (byte) 0x79, (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x31, (byte) 0x35, (byte) 0x30,
            (byte) 0x33,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x2c,
            (byte) 0x47,
        (byte) 0x6f, (byte) 0x6f, (byte) 0x67, (byte) 0x6c, (byte) 0x65, (byte) 0x20, (byte) 0x54,
            (byte) 0x65,
        (byte) 0x73, (byte) 0x74, (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64,
            (byte) 0x20,
        (byte) 0x47, (byte) 0x65, (byte) 0x6e, (byte) 0x31, (byte) 0x2d, (byte) 0x32, (byte) 0x20,
            (byte) 0x50,
        (byte) 0x49, (byte) 0x56, (byte) 0x2d, (byte) 0x49, (byte) 0x20, (byte) 0x41, (byte) 0x75,
            (byte) 0x74,
        (byte) 0x68, (byte) 0x65, (byte) 0x6e, (byte) 0x74, (byte) 0x69, (byte) 0x63, (byte) 0x61,
            (byte) 0x74,
        (byte) 0x69, (byte) 0x6f, (byte) 0x6e, (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13,
            (byte) 0x06,
        (byte) 0x07, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d, (byte) 0x02,
            (byte) 0x01,
        (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86, (byte) 0x48, (byte) 0xce, (byte) 0x3d,
            (byte) 0x03,
        (byte) 0x01, (byte) 0x07, (byte) 0x03, (byte) 0x42, (byte) 0x00, (byte) 0x04, (byte) 0xbf,
            (byte) 0x0a,
        (byte) 0xf1, (byte) 0xc1, (byte) 0xfa, (byte) 0x28, (byte) 0xac, (byte) 0x00, (byte) 0xe3,
            (byte) 0xd1,
        (byte) 0x28, (byte) 0x42, (byte) 0xdb, (byte) 0x99, (byte) 0x64, (byte) 0xd3, (byte) 0xba,
            (byte) 0x1a,
        (byte) 0x53, (byte) 0xe2, (byte) 0x8b, (byte) 0x69, (byte) 0x7f, (byte) 0xce, (byte) 0x0f,
            (byte) 0xe3,
        (byte) 0xfd, (byte) 0xae, (byte) 0xc5, (byte) 0xe5, (byte) 0x51, (byte) 0xf2, (byte) 0xbe,
            (byte) 0x8f,
        (byte) 0xa2, (byte) 0x7b, (byte) 0x9a, (byte) 0xe9, (byte) 0xb8, (byte) 0x1e, (byte) 0xb8,
            (byte) 0xd5,
        (byte) 0x0e, (byte) 0x48, (byte) 0xe4, (byte) 0x1c, (byte) 0x23, (byte) 0x5f, (byte) 0x30,
            (byte) 0xa7,
        (byte) 0xb6, (byte) 0x23, (byte) 0xf2, (byte) 0x1f, (byte) 0xbb, (byte) 0x6e, (byte) 0x1d,
            (byte) 0x4a,
        (byte) 0xa8, (byte) 0x1b, (byte) 0x5b, (byte) 0x3d, (byte) 0xb3, (byte) 0xc2, (byte) 0xa3,
            (byte) 0x82,
        (byte) 0x01, (byte) 0xc7, (byte) 0x30, (byte) 0x82, (byte) 0x01, (byte) 0xc3, (byte) 0x30,
            (byte) 0x1d,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0e, (byte) 0x04, (byte) 0x16,
            (byte) 0x04,
        (byte) 0x14, (byte) 0x69, (byte) 0xb7, (byte) 0x6b, (byte) 0x3d, (byte) 0xfb, (byte) 0x5c,
            (byte) 0x16,
        (byte) 0x63, (byte) 0x74, (byte) 0x0c, (byte) 0x06, (byte) 0x10, (byte) 0xca, (byte) 0xa6,
            (byte) 0x46,
        (byte) 0x60, (byte) 0x73, (byte) 0x9f, (byte) 0x16, (byte) 0xa9, (byte) 0x30, (byte) 0x1f,
            (byte) 0x06,
        (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x23, (byte) 0x04, (byte) 0x18, (byte) 0x30,
            (byte) 0x16,
        (byte) 0x80, (byte) 0x14, (byte) 0x3f, (byte) 0x07, (byte) 0x9e, (byte) 0xe5, (byte) 0x85,
            (byte) 0x4c,
        (byte) 0xc7, (byte) 0x6a, (byte) 0x02, (byte) 0xda, (byte) 0x70, (byte) 0xfe, (byte) 0x20,
            (byte) 0x2e,
        (byte) 0x36, (byte) 0x2b, (byte) 0x6c, (byte) 0x5b, (byte) 0x42, (byte) 0xf8, (byte) 0x30,
            (byte) 0x0e,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x0f, (byte) 0x01, (byte) 0x01,
            (byte) 0xff,
        (byte) 0x04, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x07, (byte) 0x80, (byte) 0x30,
            (byte) 0x1f,
        (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x25, (byte) 0x04, (byte) 0x18,
            (byte) 0x30,
        (byte) 0x16, (byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05,
            (byte) 0x05,
        (byte) 0x07, (byte) 0x03, (byte) 0x02, (byte) 0x06, (byte) 0x0a, (byte) 0x2b, (byte) 0x06,
            (byte) 0x01,
        (byte) 0x04, (byte) 0x01, (byte) 0x82, (byte) 0x37, (byte) 0x14, (byte) 0x02, (byte) 0x02,
            (byte) 0x30,
        (byte) 0x38, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d, (byte) 0x11, (byte) 0x04,
            (byte) 0x31,
        (byte) 0x30, (byte) 0x2f, (byte) 0x86, (byte) 0x2d, (byte) 0x75, (byte) 0x72, (byte) 0x6e,
            (byte) 0x3a,
        (byte) 0x75, (byte) 0x75, (byte) 0x69, (byte) 0x64, (byte) 0x3a, (byte) 0x62, (byte) 0x65,
            (byte) 0x31,
        (byte) 0x32, (byte) 0x37, (byte) 0x65, (byte) 0x61, (byte) 0x30, (byte) 0x2d, (byte) 0x64,
            (byte) 0x31,
        (byte) 0x38, (byte) 0x30, (byte) 0x2d, (byte) 0x31, (byte) 0x32, (byte) 0x34, (byte) 0x64,
            (byte) 0x2d,
        (byte) 0x65, (byte) 0x30, (byte) 0x34, (byte) 0x34, (byte) 0x2d, (byte) 0x30, (byte) 0x30,
            (byte) 0x30,
        (byte) 0x66, (byte) 0x32, (byte) 0x30, (byte) 0x32, (byte) 0x62, (byte) 0x32, (byte) 0x33,
            (byte) 0x35,
        (byte) 0x61, (byte) 0x30, (byte) 0x56, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
            (byte) 0x1f,
        (byte) 0x04, (byte) 0x4f, (byte) 0x30, (byte) 0x4d, (byte) 0x30, (byte) 0x4b, (byte) 0xa0,
            (byte) 0x49,
        (byte) 0xa0, (byte) 0x47, (byte) 0x86, (byte) 0x45, (byte) 0x68, (byte) 0x74, (byte) 0x74,
            (byte) 0x70,
        (byte) 0x3a, (byte) 0x2f, (byte) 0x2f, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x2e,
        (byte) 0x61, (byte) 0x70, (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73,
            (byte) 0x74,
        (byte) 0x2e, (byte) 0x63, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66,
            (byte) 0x70,
        (byte) 0x6b, (byte) 0x69, (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e,
            (byte) 0x67,
        (byte) 0x6f, (byte) 0x76, (byte) 0x2f, (byte) 0x63, (byte) 0x72, (byte) 0x6c, (byte) 0x73,
            (byte) 0x2f,
        (byte) 0x49, (byte) 0x43, (byte) 0x41, (byte) 0x4d, (byte) 0x54, (byte) 0x65, (byte) 0x73,
            (byte) 0x74,
        (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x53, (byte) 0x69, (byte) 0x67,
            (byte) 0x6e,
        (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x43, (byte) 0x41, (byte) 0x2e, (byte) 0x63,
            (byte) 0x72,
        (byte) 0x6c, (byte) 0x30, (byte) 0x18, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1d,
            (byte) 0x20,
        (byte) 0x04, (byte) 0x11, (byte) 0x30, (byte) 0x0f, (byte) 0x30, (byte) 0x0d, (byte) 0x06,
            (byte) 0x0b,
        (byte) 0x60, (byte) 0x86, (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03, (byte) 0x02,
            (byte) 0x01,
        (byte) 0x30, (byte) 0x81, (byte) 0x78, (byte) 0x30, (byte) 0x81, (byte) 0xa3, (byte) 0x06,
            (byte) 0x08,
        (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07, (byte) 0x01,
            (byte) 0x01,
        (byte) 0x04, (byte) 0x81, (byte) 0x96, (byte) 0x30, (byte) 0x81, (byte) 0x93, (byte) 0x30,
            (byte) 0x5d,
        (byte) 0x06, (byte) 0x08, (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05,
            (byte) 0x07,
        (byte) 0x30, (byte) 0x02, (byte) 0x86, (byte) 0x51, (byte) 0x68, (byte) 0x74, (byte) 0x74,
            (byte) 0x70,
        (byte) 0x3a, (byte) 0x2f, (byte) 0x2f, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x2e,
        (byte) 0x61, (byte) 0x70, (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73,
            (byte) 0x74,
        (byte) 0x2e, (byte) 0x63, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66,
            (byte) 0x70,
        (byte) 0x6b, (byte) 0x69, (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e,
            (byte) 0x67,
        (byte) 0x6f, (byte) 0x76, (byte) 0x2f, (byte) 0x61, (byte) 0x69, (byte) 0x61, (byte) 0x2f,
            (byte) 0x63,
        (byte) 0x65, (byte) 0x72, (byte) 0x74, (byte) 0x73, (byte) 0x49, (byte) 0x73, (byte) 0x73,
            (byte) 0x75,
        (byte) 0x65, (byte) 0x64, (byte) 0x54, (byte) 0x6f, (byte) 0x49, (byte) 0x43, (byte) 0x41,
            (byte) 0x4d,
        (byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x43, (byte) 0x61, (byte) 0x72,
            (byte) 0x64,
        (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6e, (byte) 0x69, (byte) 0x6e, (byte) 0x67,
            (byte) 0x43,
        (byte) 0x41, (byte) 0x2e, (byte) 0x70, (byte) 0x37, (byte) 0x63, (byte) 0x30, (byte) 0x32,
            (byte) 0x06,
        (byte) 0x08, (byte) 0x2b, (byte) 0x06, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x07,
            (byte) 0x30,
        (byte) 0x01, (byte) 0x86, (byte) 0x26, (byte) 0x68, (byte) 0x74, (byte) 0x74, (byte) 0x70,
            (byte) 0x3a,
        (byte) 0x2f, (byte) 0x2f, (byte) 0x6f, (byte) 0x63, (byte) 0x73, (byte) 0x70, (byte) 0x2e,
            (byte) 0x61,
        (byte) 0x70, (byte) 0x6c, (byte) 0x2d, (byte) 0x74, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x2e,
        (byte) 0x63, (byte) 0x69, (byte) 0x74, (byte) 0x65, (byte) 0x2e, (byte) 0x66, (byte) 0x70,
            (byte) 0x6b,
        (byte) 0x69, (byte) 0x2d, (byte) 0x6c, (byte) 0x61, (byte) 0x62, (byte) 0x2e, (byte) 0x67,
            (byte) 0x6f,
        (byte) 0x76, (byte) 0x30, (byte) 0x0a, (byte) 0x06, (byte) 0x08, (byte) 0x2a, (byte) 0x86,
            (byte) 0x48,
        (byte) 0xce, (byte) 0x3d, (byte) 0x04, (byte) 0x03, (byte) 0x02, (byte) 0x03, (byte) 0x49,
            (byte) 0x00,
        (byte) 0x30, (byte) 0x46, (byte) 0x02, (byte) 0x21, (byte) 0x00, (byte) 0xca, (byte) 0xb7,
            (byte) 0xe9,
        (byte) 0x2b, (byte) 0xed, (byte) 0xc8, (byte) 0x8c, (byte) 0x51, (byte) 0x50, (byte) 0x78,
            (byte) 0x27,
        (byte) 0x0b, (byte) 0x4a, (byte) 0x9e, (byte) 0xef, (byte) 0x64, (byte) 0x48, (byte) 0xc8,
            (byte) 0xdf,
        (byte) 0x10, (byte) 0x83, (byte) 0xd5, (byte) 0xeb, (byte) 0xdd, (byte) 0x43, (byte) 0x74,
            (byte) 0x43,
        (byte) 0xb9, (byte) 0xda, (byte) 0xaf, (byte) 0x4c, (byte) 0xaa, (byte) 0x02, (byte) 0x21,
            (byte) 0x00,
        (byte) 0xba, (byte) 0x36, (byte) 0xee, (byte) 0x42, (byte) 0x12, (byte) 0x68, (byte) 0x0c,
            (byte) 0x1c,
        (byte) 0x64, (byte) 0x0a, (byte) 0x31, (byte) 0xca, (byte) 0xc9, (byte) 0x07, (byte) 0x90,
            (byte) 0x79,
        (byte) 0x98, (byte) 0xa0, (byte) 0x91, (byte) 0xa8, (byte) 0x15, (byte) 0x0d, (byte) 0x48,
            (byte) 0xe8,
        (byte) 0x6e, (byte) 0x69, (byte) 0xca, (byte) 0x13, (byte) 0xb1, (byte) 0x76, (byte) 0xf2,
            (byte) 0xd1
      };

  /// The default value for the special DISCOVERY object
  protected static final byte[] DEFAULT_DISCOVERY =
      new byte[] {

        /// 2 bytes - Discovery Object (TAG '7E')
        (byte) 0x7E,
        (byte) 0x12,

        // 2 + 11 bytes - PIV Card Application AID (TAG '4F')
        (byte) 0x4F,
        (byte) 0x0B,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x10,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,

        // 3 + 2 bytes - PIN Usage Policy
        (byte) 0x5F,
        (byte) 0x2F,
        (byte) 0x02,

        // Tag 0x5F2F encodes the PIN Usage Policy in two bytes:

        // FIRST BYTE
        // -----------------------------

        // Bit 8 of the first byte shall be set to zero

        // Bit 7 is set to 1 to indicate that the mandatory PIV Card Application PIN
        // satisfies the PIV Access Control Rules (ACRs) for command
        // execution and data object access.
        (FEATURE_PIN_CARD_ENABLED ? (byte) (1 << 6) : (byte) 0)
            |

            // Bit 6 indicates whether the optional Global PIN satisfies the PIV ACRs for
            // command execution and PIV data object access.
            (FEATURE_PIN_GLOBAL_ENABLED ? (byte) (1 << 5) : (byte) 0)
            |

            // Bit 5 indicates whether the optional OCC satisfies the PIV ACRs for
            // command execution and PIV data object access
            (byte) (0 << 4)
            |

            // Bit 4 indicates whether the optional VCI is implemented
            (byte) (0 << 3)
            |

            // Bit 3 is set to zero if the pairing code is required to establish a VCI and is
            // set to one if a VCI is established without pairing code
            (byte) (0 << 2)
            |

            // Bits 2 and 1 of the first byte shall be set to zero
            (byte) (0 << 1)
            | (byte) (0 << 0),

        // SECOND BYTE
        // -----------------------------
        // The second byte of the PIN Usage Policy encodes the cardholder's PIN preference for
        // PIV Cards with both the PIV Card Application PIN and the Global PIN enabled:

        // 0x10 indicates that the PIV Card Application PIN is the primary PIN used
        // 	 	to satisfy the PIV ACRs for command execution and object access.
        // 0x20 indicates that the Global PIN is the primary PIN used to satisfy the
        // 		PIV ACRs for command execution and object access.
        (FEATURE_PIN_GLOBAL_PREFERRED ? (byte) 0x20 : (byte) 0x10)
      };

  /// The default value for the PIV Application Property Template (APT), which is returned
  /// when the applet is selected (this represents the FCI parameter as per ISO-7816)
  protected static final byte[] DEFAULT_APT =
      new byte[] {

        // 2 bytes - Application Property Template (TAG '61')
        (byte) 0x61,
        (byte) 0x81,
        (byte) 0x8F,

        // 2 + 11 bytes - Application identifier of application (TAG '4F')
        (byte) 0x4F,
        (byte) 0x0B,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x10,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,

        // 2 + 7 bytes - Coexistent Tag Allocation Authority (TAG '79')
        (byte) 0x79,
        (byte) 0x07,
        (byte) 0x4F,
        (byte) 0x05,
        (byte) 0xA0,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x03,
        (byte) 0x08,

        // 2 + 11 bytes - Application label
        // OpenFIPS201
        (byte) 0x50,
        (byte) 0x0B,
        'O',
        'p',
        'e',
        'n',
        'F',
        'I',
        'P',
        'S',
        '2',
        '0',
        '1',

        // 3 + 73 bytes - Uniform resource locator
        // http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf
        (byte) 0x5F,
        (byte) 0x50,
        (byte) 0x49,
        'h',
        't',
        't',
        'p',
        ':',
        '/',
        '/',
        'n',
        'v',
        'l',
        'p',
        'u',
        'b',
        's',
        '.',
        'n',
        'i',
        's',
        't',
        '.',
        'g',
        'o',
        'v',
        '/',
        'n',
        'i',
        's',
        't',
        'p',
        'u',
        'b',
        's',
        '/',
        'S',
        'p',
        'e',
        'c',
        'i',
        'a',
        'l',
        'P',
        'u',
        'b',
        'l',
        'i',
        'c',
        'a',
        't',
        'i',
        'o',
        'n',
        's',
        '/',
        'N',
        'I',
        'S',
        'T',
        '.',
        'S',
        'P',
        '.',
        '8',
        '0',
        '0',
        '-',
        '7',
        '3',
        '-',
        '4',
        '.',
        'p',
        'd',
        'f',

        // 2 + 24 - Cryptographic Algorithm Identifier Template (Tag 'AC')
        (byte) 0xAC,
        (byte) 0x1E,

        // Supported mechanisms
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_DEFAULT,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_TDEA_3KEY,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_128,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_192,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_AES_256,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_RSA_1024,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_RSA_2048,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_ECC_P256,
        (byte) 0x80,
        (byte) 0x01,
        PIV.ID_ALG_ECC_P384,

        // Object identifier
        (byte) 0x06,
        (byte) 0x01,
        (byte) 0x00
      };
}
