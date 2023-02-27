package jcfrost;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.RandomData;
import jcfrost.jcmathlib.*;

import static jcfrost.JCFROST.secret;

public class FrostSession {
    private RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);

    private short storedCommitments = 0;
    private short index = -1;

    private BigNat hidingNonce = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private BigNat bindingNonce = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private ECPoint hidingPoint = new ECPoint(JCFROST.curve, JCFROST.ecc.rm);
    private ECPoint bindingPoint = new ECPoint(JCFROST.curve, JCFROST.ecc.rm);

    private FrostCommitment[] commitments = new FrostCommitment[Consts.MAX_PARTIES];

    // Computation-only (TODO consider sharing with other instances)
    private BigNat identifierBuffer = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private byte[] nonceBuffer = JCSystem.makeTransientByteArray((short) (2 * 32), JCSystem.CLEAR_ON_RESET);
    private byte[] ramArray = JCSystem.makeTransientByteArray((short) (3 * 32 + 1), JCSystem.CLEAR_ON_RESET);
    private BigNat numerator = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private BigNat denominator = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private BigNat challenge = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private BigNat lambda = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private BigNat tmp = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private ECPoint groupCommitment = new ECPoint(JCFROST.curve, JCFROST.ecc.rm);
    private ECPoint tmpPoint = new ECPoint(JCFROST.curve, JCFROST.ecc.rm);
    private ECPoint tmpPoint2 = new ECPoint(JCFROST.curve, JCFROST.ecc.rm);
    private byte[] rhoBuffer = JCSystem.makeTransientByteArray((short) (3 * 32), JCSystem.CLEAR_ON_RESET);
    private BigNat[] bindingFactors = new BigNat[Consts.MAX_PARTIES];

    public FrostSession() {
        for(short i = 0; i < (short) Consts.MAX_PARTIES; ++i) {
            commitments[i] = new FrostCommitment();
            bindingFactors[i] = new BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
        }
    }

    public short commit(byte[] output, short offset) {
        hidingPoint.setW(SecP256k1.G, (short) 0, (short) SecP256k1.G.length);
        bindingPoint.setW(SecP256k1.G, (short) 0, (short) SecP256k1.G.length);
        nonceGenerate(hidingNonce);
        nonceGenerate(bindingNonce);
        hidingPoint.multiplication(hidingNonce);
        bindingPoint.multiplication(bindingNonce);
        hidingPoint.encode(output, offset, true);
        bindingPoint.encode(output, (short) (offset + 33), true);
        reset();
        return (short) 66;
    }

    public void commitment(byte party_identifier, byte[] data, short offset) {
        if(storedCommitments >= JCFROST.maxParties) {
            reset();
            ISOException.throwIt(Consts.E_TOO_MANY_COMMITMENTS);
        }
        commitments[storedCommitments].identifier = party_identifier;
        if(storedCommitments > 0 && party_identifier <= commitments[(short) (storedCommitments - 1)].identifier) {
            reset();
            ISOException.throwIt(Consts.E_IDENTIFIER_ORDERING);
        }
        if(commitments[storedCommitments].identifier == JCFROST.identifier) {
            index = storedCommitments;
            // TODO check if provided commitments match local commitments
        }
        Util.arrayCopyNonAtomic(data, offset, commitments[storedCommitments].hiding, (short) 0, (short) 33);
        Util.arrayCopyNonAtomic(data, (short) (offset + 33), commitments[storedCommitments].binding, (short) 0, (short) 33);
        ++storedCommitments;
    }

    public void sign(byte[] msg, short msgOffset, short msgLength, byte[] output, short outputOffset) {
        if(storedCommitments < JCFROST.minParties) {
            reset(); // TODO keep it?
            ISOException.throwIt(Consts.E_NOT_ENOUGH_COMMITMENTS);
        }
        if(index == -1) {
            reset();
            ISOException.throwIt(Consts.E_IDENTIFIER_NOT_INCLUDED);
        }
        computeBindingFactors(msg, msgOffset, msgLength);
        computeGroupCommitment();
        computeLambda();
        computeChallenge(msg, msgOffset, msgLength);
        challenge.mod_mult(challenge, lambda, JCFROST.curve.rBN);
        challenge.mod_mult(challenge, secret, JCFROST.curve.rBN);
        tmp.mod_mult(bindingNonce, bindingFactors[index], JCFROST.curve.rBN);
        tmp.mod_add(hidingNonce, JCFROST.curve.rBN);
        tmp.mod_add(challenge, JCFROST.curve.rBN);
        tmp.copy_to_buffer(output, outputOffset);
    }

    public void reset() {
        storedCommitments = 0;
        index = -1;
    }

    private void nonceGenerate(BigNat outputNonce) {
        rng.nextBytes(nonceBuffer, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(secret.as_byte_array(), (short) 0, nonceBuffer, (short) 32, (short) 32); // TODO can be preloaded in RAM
        JCFROST.hasher.h3(nonceBuffer, (short) 0, (short) nonceBuffer.length, outputNonce);
    }

    private void computeLambda() {
        numerator.one();
        denominator.one();
        for(short j = 0; j < storedCommitments; ++j) {
            if(j == index) {
                continue;
            }
            identifierBuffer.as_byte_array()[31] = commitments[j].identifier;
            numerator.mod_mult(numerator, identifierBuffer, JCFROST.curve.rBN);
            tmp.clone(identifierBuffer);
            identifierBuffer.as_byte_array()[31] = commitments[index].identifier;
            tmp.mod_sub(identifierBuffer, JCFROST.curve.rBN);
            denominator.mod_mult(denominator, tmp, JCFROST.curve.rBN);
        }
        denominator.mod_inv(JCFROST.curve.rBN);
        lambda.mod_mult(numerator, denominator, JCFROST.curve.rBN);
    }

    private void computeChallenge(byte[] msg, short msgOffset, short msgLen) {
        JCFROST.hasher.update(Consts.ZPAD, (short) 0, (short) Consts.ZPAD.length);
        groupCommitment.encode(ramArray, (short) 0, true);
        JCFROST.hasher.update(ramArray, (short) 0, (short) 33);
        JCFROST.groupPublic.encode(ramArray, (short) 0, true);
        JCFROST.hasher.update(ramArray, (short) 0, (short) 33);
        JCFROST.hasher.update(msg, msgOffset, msgLen);
        JCFROST.hasher.hash_to_field_internal(Consts.H2_TAG, challenge);
    }

    private void computeBindingFactors(byte[] msg, short msgOffset, short msgLen) {
        JCFROST.hasher.h4(msg, msgOffset, msgLen, rhoBuffer, (short) 0);
        JCFROST.hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        JCFROST.hasher.update(Consts.H5_TAG, (short) 0, (short) Consts.H5_TAG.length);
        for(short j = 0; j < storedCommitments; ++j) {
            identifierBuffer.as_byte_array()[31] = commitments[j].identifier; // TODO check whether the rest of the array is all zeros
            JCFROST.hasher.update(identifierBuffer.as_byte_array(), (short) 0, identifierBuffer.length());
            JCFROST.hasher.update(commitments[j].hiding, (short) 0, (short) 33);
            JCFROST.hasher.update(commitments[j].binding, (short) 0, (short) 33);
        }
        JCFROST.hasher.doFinal(ramArray, (short) 0, (short) 0, rhoBuffer, (short) 32);

        Util.arrayFillNonAtomic(rhoBuffer, (short) 64, (short) 31, (byte) 0);
        for(short j = 0; j < storedCommitments; ++j) {
            rhoBuffer[95] = commitments[j].identifier;
            JCFROST.hasher.h1(rhoBuffer, (short) 0, (short) rhoBuffer.length, bindingFactors[j]);
        }
    }

    private void computeGroupCommitment() {
        tmpPoint.decode(commitments[0].binding, (short) 0, (short) 33);
        tmpPoint2.decode(commitments[0].hiding, (short) 0, (short) 33);
        tmpPoint.multAndAdd(bindingFactors[0], tmpPoint2);
        groupCommitment.copy(tmpPoint);
        for(short j = 1; j < storedCommitments; ++j) {
            tmpPoint.decode(commitments[j].binding, (short) 0, (short) 33);
            tmpPoint2.decode(commitments[j].hiding, (short) 0, (short) 33);
            tmpPoint.multAndAdd(bindingFactors[j], tmpPoint2);
            groupCommitment.add(tmpPoint);
        }
    }

}
