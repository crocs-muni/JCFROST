package jcfrost;

import javacard.framework.*;
import javacard.security.*;
import jcfrost.jcmathlib.*;

public class JCFROST extends Applet {
    public final static boolean DEBUG = false;
    public final static short POINT_SIZE = 65;
    public final static byte[] DEBUG_RANDOMNESS = new byte[64];
    public static short DEBUG_RANDOMNESS_OFFSET = 0;

    public static ECConfig ecc;
    public static ECCurve curve;
    public static HashToField hasher;

    public static byte minParties, maxParties, identifier;
    public static BigNat secret;
    public static ECPoint groupPublic;

    private FrostSession frost;

    private boolean initialized = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCFROST(bArray, bOffset, bLength);
    }

    public JCFROST(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);
        if(!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_JCFROST)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        if(!initialized) {
            initialize();
        }

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_INITIALIZE:
                    initialize();
                    break;
                case Consts.INS_SETUP:
                    setup(apdu);
                    break;
                case Consts.INS_COMMIT:
                    commit(apdu);
                    break;
                case Consts.INS_COMMITMENT:
                    commitment(apdu);
                    break;
                case Consts.INS_SIGN:
                    sign(apdu);
                    break;
                case Consts.INS_RESET:
                    reset(apdu);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select(boolean b) {
        ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {}

    private void initialize() {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        ecc = new ECConfig((short) 256);
        curve = new ECCurve(false, SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r);
        secret = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
        groupPublic = new ECPoint(curve, ecc.rm);

        hasher = new HashToField();
        frost = new FrostSession();

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        minParties = apduBuffer[ISO7816.OFFSET_P1];
        maxParties = apduBuffer[ISO7816.OFFSET_P2];
        if(maxParties > Consts.MAX_PARTIES) {
            ISOException.throwIt(Consts.E_TOO_MANY_PARTIES);
        }
        identifier = apduBuffer[ISO7816.OFFSET_CDATA];
        Util.arrayCopyNonAtomic(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 1), secret.as_byte_array(), (short) 0, (short) 32);
        groupPublic.decode(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 33), POINT_SIZE);
        if (DEBUG) {
            apduBuffer[0] = minParties;
            apduBuffer[1] = maxParties;
            apduBuffer[2] = identifier;
            Util.arrayCopyNonAtomic(secret.as_byte_array(), (short) 0, apduBuffer, (short) 3, secret.length());
            groupPublic.encode(apduBuffer, (short) (3 + secret.length()), true);
            apdu.setOutgoingAndSend((short) 0, (short) (3 + secret.length() + 33));
        } else {
            apdu.setOutgoing();
        }
    }

    private void commit(APDU apdu) {
        if(DEBUG) {
            short len = (short) (apdu.getBuffer()[ISO7816.OFFSET_P1] & 0xff);
            DEBUG_RANDOMNESS_OFFSET = 0;
            Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, DEBUG_RANDOMNESS, (short) 0, len);
        }
        apdu.setOutgoingAndSend((short) 0, frost.commit(apdu.getBuffer(), (short) 0));
    }

    private void commitment(APDU apdu) {
        frost.commitment(apdu.getBuffer()[ISO7816.OFFSET_P1], apdu.getBuffer(), ISO7816.OFFSET_CDATA);
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        frost.sign(apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer[ISO7816.OFFSET_P1], apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    private void reset(APDU apdu) {
        frost.reset();
        apdu.setOutgoing();
    }
}
