package jcfrost;

import javacard.framework.*;
import javacard.security.*;
import jcfrost.jcmathlib.*;

public class JCFROST extends Applet implements MultiSelectable {
    private ECConfig ecc;
    private ECCurve curve;
    private MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private BigNat largeScalar;
    private BigNat testScalar;
    private byte[] ramArray = JCSystem.makeTransientByteArray((short) (3 * 32 + 1), JCSystem.CLEAR_ON_RESET);
    private byte[] nonceBuffer = JCSystem.makeTransientByteArray((short) (2 * 32), JCSystem.CLEAR_ON_RESET);
    private RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    private byte[] secret = new byte[32];

    private BigNat numerator, denominator, tmp;
    private BigNat hidingNonce, bindingNonce;
    private ECPoint groupPublic;
    private ECPoint groupCommitment;
    private ECPoint tmpPoint;
    private ECPoint tmpPoint2;
    private ECPoint hidingPoint, bindingPoint;

    // Commitments
    private BigNat[] identifiers;
    private byte[][] hidingCommitments;
    private byte[][] bindingCommitments;
    private BigNat[] bindingFactors;
    private BigNat lambda;
    private short index;

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

                // Unit tests
                case Consts.INS_TEST_HASH:
                    testHash(apdu);
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
        largeScalar = new BigNat((short) 48, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        testScalar = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        rng.nextBytes(secret, (short) 0, (short) secret.length);
        numerator = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        denominator = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        tmp = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        hidingNonce = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        bindingNonce = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.rm);
        hidingPoint = new ECPoint(curve, ecc.rm);
        bindingPoint = new ECPoint(curve, ecc.rm);
        groupPublic = new ECPoint(curve, ecc.rm);
        groupCommitment = new ECPoint(curve, ecc.rm);
        tmpPoint = new ECPoint(curve, ecc.rm);
        tmpPoint2 = new ECPoint(curve, ecc.rm);

        identifiers = new BigNat[5];
        hidingCommitments = new byte[65][5];
        bindingCommitments = new byte[65][5];
        bindingFactors = new BigNat[5];
        lambda = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
        for(short i = 0; i < (short) bindingFactors.length; ++i) {
            identifiers[i] = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
            bindingFactors[i] = new BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.rm);
        }

        initialized = true;
    }

    private void computeBindingFactors(byte[] msg) {
        byte[] msgHash = new byte[32];
        h4(msg, (short) 0, (short) msg.length, msgHash, (short) 0);
        byte[] encodedCommitmentHash = new byte[32];
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(Consts.H5_TAG, (short) 0, (short) Consts.H5_TAG.length);
        for(short j = 0; j < (short) bindingFactors.length; ++j) {
            hasher.update(identifiers[j].as_byte_array(), (short) 0, (short) identifiers[j].as_byte_array().length);
            hasher.update(hidingCommitments[j], (short) 0, (short) hidingCommitments[j].length);
            hasher.update(bindingCommitments[j], (short) 0, (short) bindingCommitments[j].length);
        }
        hasher.doFinal(new byte[0], (short) 0, (short) 0, encodedCommitmentHash, (short) 0);

        byte[] rho_input = new byte[(short) (3 * 32)];
        Util.arrayCopyNonAtomic(msgHash, (short) 0, rho_input, (short) 0, (short) msgHash.length);
        Util.arrayCopyNonAtomic(encodedCommitmentHash, (short) 0, rho_input, (short) 32, (short) encodedCommitmentHash.length);
        for(short j = 0; j < (short) bindingFactors.length; ++j) {
            Util.arrayCopyNonAtomic(identifiers[j].as_byte_array(), (short) 0, rho_input, (short) 64, (short) identifiers[j].as_byte_array().length);
            h1(rho_input, (short) 0, (short) rho_input.length, bindingFactors[j]);
        }
    }

    private void computeGroupCommitment() {
        tmpPoint.setW(bindingCommitments[0], (short) 0, (short) bindingCommitments[0].length);
        tmpPoint2.setW(hidingCommitments[0], (short) 0, (short) hidingCommitments[0].length);
        tmpPoint.multAndAdd(bindingFactors[0], tmpPoint2);
        groupCommitment.copy(tmpPoint);
        for(int j = 1; j < (short) bindingFactors.length; ++j) {
            tmpPoint.setW(bindingCommitments[0], (short) 0, (short) bindingCommitments[0].length);
            tmpPoint2.setW(hidingCommitments[0], (short) 0, (short) hidingCommitments[0].length);
            tmpPoint.multAndAdd(bindingFactors[0], tmpPoint2);
            groupCommitment.add(tmpPoint);
        }
    }

    private void commit() {
        hidingPoint.setW(SecP256k1.G, (short) 0, (short) SecP256k1.G.length);
        hidingPoint.setW(SecP256k1.G, (short) 0, (short) SecP256k1.G.length);
        nonceGenerate(hidingNonce);
        nonceGenerate(bindingNonce);
        hidingPoint.multiplication(hidingNonce);
        bindingPoint.multiplication(bindingNonce);
    }

    private void sign(byte[] msg) {
        computeBindingFactors(msg);
        computeGroupCommitment();
        computeLambda();
    }

    private void computeLambda() {
        // TODO identifiers have to contain unique values - check when building identifiers
        // TODO index has to correspond to identifier of this device - verify
        numerator.one();
        denominator.one();
        for(short j = 0; j < (short) identifiers.length; ++j) {
            if(j == index) {
                continue;
            }
            numerator.mod_mult(numerator, identifiers[j], curve.rBN);
            tmp.clone(identifiers[j]);
            tmp.mod_sub(identifiers[index], curve.rBN);
            denominator.mod_mult(denominator, tmp, curve.rBN);
        }
        denominator.mod_inv(curve.rBN);
        lambda.mod_mult(numerator, denominator, curve.rBN);
    }

    private void nonceGenerate(BigNat outputNonce) {
        rng.nextBytes(nonceBuffer, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(secret, (short) 0, nonceBuffer, (short) 32, (short) 32); // TODO can be preloaded in RAM
        h3(nonceBuffer, (short) 0, (short) nonceBuffer.length, outputNonce);
    }

    private void testHash(APDU apdu) {
        short p1 = apdu.getBuffer()[ISO7816.OFFSET_P1];
        short p2 = apdu.getBuffer()[ISO7816.OFFSET_P2];
        switch (p1) {
            case 1:
                h1(apdu.getBuffer(), ISO7816.OFFSET_CDATA, p2, testScalar);
                testScalar.copy_to_buffer(apdu.getBuffer(), (short) 0);
                break;
            case 2:
                h2(apdu.getBuffer(), ISO7816.OFFSET_CDATA, p2, testScalar);
                testScalar.copy_to_buffer(apdu.getBuffer(), (short) 0);
                break;
            case 3:
                h3(apdu.getBuffer(), ISO7816.OFFSET_CDATA, p2, testScalar);
                testScalar.copy_to_buffer(apdu.getBuffer(), (short) 0);
                break;
            case 4:
                h4(apdu.getBuffer(), ISO7816.OFFSET_CDATA, p2, apdu.getBuffer(), (short) 0);
                break;
            case 5:
                h5(apdu.getBuffer(), ISO7816.OFFSET_CDATA, p2, apdu.getBuffer(), (short) 0);
                break;
            default:
                ISOException.throwIt(Consts.E_UNKNOWN_HASH);
        }
        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    private void h1(byte[] msg, short msgOffset, short msgLen, BigNat outputScalar) {
        hash_to_field(msg, msgOffset, msgLen, Consts.H1_TAG, outputScalar);
    }

    private void h2(byte[] msg, short msgOffset, short msgLen, BigNat outputScalar) {
        hash_to_field(msg, msgOffset, msgLen, Consts.H2_TAG, outputScalar);
    }

    private void h3(byte[] msg, short msgOffset, short msgLen, BigNat outputScalar) {
        hash_to_field(msg, msgOffset, msgLen, Consts.H3_TAG, outputScalar);
    }

    private void h4(byte[] msg, short msgOffset, short msgLen, byte[] output, short outputOffset) {
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(Consts.H4_TAG, (short) 0, (short) Consts.H4_TAG.length);
        hasher.doFinal(msg, msgOffset, msgLen, output, outputOffset);
    }

    private void h5(byte[] msg, short msgOffset, short msgLen, byte[] output, short outputOffset) {
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(Consts.H5_TAG, (short) 0, (short) Consts.H5_TAG.length);
        hasher.doFinal(msg, msgOffset, msgLen, output, outputOffset);
    }

    // hash_to_field https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
    private void hash_to_field(byte[] msg, short msgOffset, short msgLen, byte[] tag, BigNat outputScalar) {
        short L = 48;
        short BLOCK = 32;
        // ramArray = b0 (BLOCK) || b1 (BLOCK) || b2 (BLOCK) || CONTEXT_STRING_LEN (BYTE)

        ramArray[(3 * BLOCK)] = (byte) (Consts.CONTEXT_STRING.length + tag.length);

        hasher.update(Consts.ZPAD, (short) 0, (short) Consts.ZPAD.length);
        hasher.update(msg, msgOffset, msgLen);
        hasher.update(Consts.HELPER, (short) 0, (short) Consts.HELPER.length);
        hasher.update(Consts.ZERO, (short) 0, (short) Consts.ZERO.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(ramArray, (short) (3 * BLOCK), (short) 1, ramArray, (short) 0);

        hasher.update(ramArray, (short) 0, BLOCK);
        hasher.update(Consts.ONE, (short) 0, (short) Consts.ONE.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(ramArray, (short) (3 * BLOCK), (short) 1, ramArray, BLOCK);

        // use b0 for temporary result of xor(b0, b1)
        for(short i = 0; i < BLOCK; ++i) {
            ramArray[64 + i] = (byte) (ramArray[i] ^ ramArray[32 + i]);
        }

        hasher.update(ramArray, (short) (2 * BLOCK), BLOCK);
        hasher.update(Consts.TWO, (short) 0, (short) Consts.TWO.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(ramArray, (short) (3 * BLOCK), (short) 1, ramArray, (short) (2 * BLOCK));

        // take the first 48 B and compute mod r
        Util.arrayCopyNonAtomic(ramArray, BLOCK, largeScalar.as_byte_array(), (short) 0, BLOCK);
        Util.arrayCopyNonAtomic(ramArray, (short) (2 * BLOCK), largeScalar.as_byte_array(), BLOCK, (short) (L - BLOCK));
        largeScalar.mod(curve.rBN);
        Util.arrayCopyNonAtomic(largeScalar.as_byte_array(), (short) 16, outputScalar.as_byte_array(), (short) 0, (short) 32);
        outputScalar.set_size((short) 32);
    }
}
