package jcfrost;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import jcfrost.jcmathlib.*;

public class HashToField {
    private BigNat largeScalar = new BigNat((short) 48, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, JCFROST.ecc.rm);
    private MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private byte[] hashBuffer = JCSystem.makeTransientByteArray((short) (3 * 32 + 1), JCSystem.CLEAR_ON_RESET);

    public void update(byte[] data, short offset, short len) {
        hasher.update(data, offset, len);
    }

    public void doFinal(byte[] data, short offset, short len, byte[] output, short outputOffset) {
        hasher.doFinal(data, offset, len, output, outputOffset);
    }

    public void h1(byte[] msg, short msgOffset, short msgLen, BigNat outputScalar) {
        hash_to_field(msg, msgOffset, msgLen, Consts.H1_TAG, outputScalar);
    }

    public void h3(byte[] msg, short msgOffset, short msgLen, BigNat outputScalar) {
        hash_to_field(msg, msgOffset, msgLen, Consts.H3_TAG, outputScalar);
    }

    public void h4(byte[] msg, short msgOffset, short msgLen, byte[] output, short outputOffset) {
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(Consts.H4_TAG, (short) 0, (short) Consts.H4_TAG.length);
        hasher.doFinal(msg, msgOffset, msgLen, output, outputOffset);
    }

    // hash_to_field https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
    public void hash_to_field(byte[] msg, short msgOffset, short msgLen, byte[] tag, BigNat outputScalar) {
        hasher.update(Consts.ZPAD, (short) 0, (short) Consts.ZPAD.length);
        hasher.update(msg, msgOffset, msgLen);
        hash_to_field_internal(tag, outputScalar);
    }

    public void hash_to_field_internal(byte[] tag, BigNat outputScalar) {
        short L = 48;
        short BLOCK = 32;
        // hashBuffer = b0 (BLOCK) || b1 (BLOCK) || b2 (BLOCK) || CONTEXT_STRING_LEN (BYTE)

        hashBuffer[(short) (3 * BLOCK)] = (byte) (Consts.CONTEXT_STRING.length + tag.length);
        hasher.update(Consts.HELPER, (short) 0, (short) Consts.HELPER.length);
        hasher.update(Consts.ZERO, (short) 0, (short) Consts.ZERO.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(hashBuffer, (short) (3 * BLOCK), (short) 1, hashBuffer, (short) 0);

        hasher.update(hashBuffer, (short) 0, BLOCK);
        hasher.update(Consts.ONE, (short) 0, (short) Consts.ONE.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(hashBuffer, (short) (3 * BLOCK), (short) 1, hashBuffer, BLOCK);

        // use b0 for temporary result of xor(b0, b1)
        for(short i = 0; i < BLOCK; ++i) {
            hashBuffer[(short) (64 + i)] = (byte) (hashBuffer[i] ^ hashBuffer[(short) (32 + i)]);
        }

        hasher.update(hashBuffer, (short) (2 * BLOCK), BLOCK);
        hasher.update(Consts.TWO, (short) 0, (short) Consts.TWO.length);
        hasher.update(Consts.CONTEXT_STRING, (short) 0, (short) Consts.CONTEXT_STRING.length);
        hasher.update(tag, (short) 0, (short) tag.length);
        hasher.doFinal(hashBuffer, (short) (3 * BLOCK), (short) 1, hashBuffer, (short) (2 * BLOCK));

        // take the first 48 B and compute mod r
        Util.arrayCopyNonAtomic(hashBuffer, BLOCK, largeScalar.as_byte_array(), (short) 0, BLOCK);
        Util.arrayCopyNonAtomic(hashBuffer, (short) (2 * BLOCK), largeScalar.as_byte_array(), BLOCK, (short) (L - BLOCK));
        largeScalar.mod(JCFROST.curve.rBN);
        Util.arrayCopyNonAtomic(largeScalar.as_byte_array(), (short) 16, outputScalar.as_byte_array(), (short) 0, (short) 32);
        outputScalar.set_size((short) 32);
    }
}
