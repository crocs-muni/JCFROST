package jcfrost;

public class Consts {
    public static final byte CLA_JCFROST = (byte) 0x00;
    public static final byte INS_INITIALIZE = (byte) 0x00;
    public static final byte INS_SETUP = (byte) 0x01;
    public static final byte INS_COMMIT = (byte) 0x02;
    public static final byte INS_COMMITMENT = (byte) 0x03;
    public static final byte INS_SIGN = (byte) 0x04;

    public static final byte INS_RESET = (byte) 0x05;
    public static final byte INS_GROUP_KEY = (byte) 0x06;

    public final static short E_ALREADY_INITIALIZED = (short) 0xee00;
    public final static short E_UNINITIALIZED = (short) 0xee01;
    public final static short E_DEBUG_DISABLED = (short) 0xee02;
    public final static short E_UNKNOWN_HASH = (short) 0xee03;
    public final static short E_TOO_MANY_PARTIES = (short) 0xee04;
    public final static short E_TOO_MANY_COMMITMENTS = (short) 0xee05;
    public final static short E_IDENTIFIER_ORDERING = (short) 0xee06;
    public final static short E_NOT_ENOUGH_COMMITMENTS = (short) 0xee07;
    public final static short E_IDENTIFIER_NOT_INCLUDED = (short) 0xee08;
    public final static short E_COMMITMENT_MISMATCH = (short) 0xee09;

    public final static short SW_Exception = (short) 0xff01;
    public final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public final static short SW_ArithmeticException = (short) 0xff03;
    public final static short SW_ArrayStoreException = (short) 0xff04;
    public final static short SW_NullPointerException = (short) 0xff05;
    public final static short SW_NegativeArraySizeException = (short) 0xff06;
    public final static short SW_CryptoException_prefix = (short) 0xf100;
    public final static short SW_SystemException_prefix = (short) 0xf200;
    public final static short SW_PINException_prefix = (short) 0xf300;
    public final static short SW_TransactionException_prefix = (short) 0xf400;
    public final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    // "FROST-secp256k1-SHA256-v1";
    final static byte[] CONTEXT_STRING = {(byte) 0x46, (byte) 0x52, (byte) 0x4f, (byte) 0x53, (byte) 0x54, (byte) 0x2d, (byte) 0x73, (byte) 0x65, (byte) 0x63, (byte) 0x70, (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x6b, (byte) 0x31, (byte) 0x2d, (byte) 0x53, (byte) 0x48, (byte) 0x41, (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x2d, (byte) 0x76, (byte) 0x31};
    final static byte[] H1_TAG = {(byte) 0x72, (byte) 0x68, (byte) 0x6f};
    final static byte[] H2_TAG = {(byte) 0x63, (byte) 0x68, (byte) 0x61, (byte) 0x6c};
    final static byte[] H3_TAG = {(byte) 0x6e, (byte) 0x6f, (byte) 0x6e, (byte) 0x63, (byte) 0x65};
    final static byte[] H4_TAG = {(byte) 0x6d, (byte) 0x73, (byte) 0x67};
    final static byte[] H5_TAG = {(byte) 0x63, (byte) 0x6f, (byte) 0x6d};
    final static byte[] ZPAD = {(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0};
    final static byte[] HELPER = {(byte) 0x00, (byte) 0x30};
    final static byte[] ZERO = {(byte) 0x00};
    final static byte[] ONE = {(byte) 0x01};
    final static byte[] TWO = {(byte) 0x02};
    final static byte MAX_PARTIES = (byte) 12;
}
