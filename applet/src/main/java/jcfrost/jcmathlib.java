// Merged file class by JavaPresso (https://github.com/petrs/JavaPresso) 
// TODO: Fix 'your_package' to your real package name as necessary
// TODO: Add 'import your_package.opencrypto.*;' to access all classes as usual

package jcfrost;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.PINException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.*;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class jcmathlib {

    
    /**
     *
    * @author Vasilios Mavroudis and Petr Svenda
     */
    static class ReturnCodes {
        // Custom error response codes
        public static final short SW_BIGNAT_RESIZETOLONGER          = (short) 0x7000;
        public static final short SW_BIGNAT_REALLOCATIONNOTALLOWED  = (short) 0x7001;
        public static final short SW_BIGNAT_MODULOTOOLARGE          = (short) 0x7002;
        public static final short SW_BIGNAT_INVALIDCOPYOTHER        = (short) 0x7003;
        public static final short SW_BIGNAT_INVALIDRESIZE           = (short) 0x7004;
        public static final short SW_LOCK_ALREADYLOCKED             = (short) 0x7005;
        public static final short SW_LOCK_NOTLOCKED                 = (short) 0x7006;
        public static final short SW_LOCK_OBJECT_NOT_FOUND          = (short) 0x7007;
        public static final short SW_LOCK_NOFREESLOT                = (short) 0x7008;
        public static final short SW_LOCK_OBJECT_MISMATCH           = (short) 0x7009;
        public static final short SW_ECPOINT_INVALIDLENGTH          = (short) 0x700a;
        public static final short SW_ECPOINT_UNEXPECTED_KA_LEN      = (short) 0x700b;
        public static final short SW_ALLOCATOR_INVALIDOBJID         = (short) 0x700c;
        public static final short SW_OPERATION_NOT_SUPPORTED        = (short) 0x700d;
        public static final short SW_NOT_INITIALIZED                = (short) 0x700e;
    }
    
    
    /**
     * @author Vasilios Mavroudis and Petr Svenda and Antonin Dufka
     */
    static class ECPoint {
        private final ResourceManager rm;
    
        private ECPublicKey point;
        private KeyPair pointKeyPair;
        private final ECCurve curve;
    
        /**
         * Creates new ECPoint object for provided {@code curve}. Random initial point value is generated.
         * The point will use helper structures from provided ECPoint_Helper object.
         *
         * @param curve point's elliptic curve
         * @param rm resource manager with prealocated objects and memory arrays
         */
        public ECPoint(ECCurve curve, ResourceManager rm) {
            this.curve = curve;
            this.rm = rm;
            updatePointObjects();
        }
    
        /**
         * Returns length of this point in bytes.
         *
         * @return length of this point in bytes
         */
        public short length() {
            return (short) (point.getSize() / 8);
        }
    
        /**
         * Properly updates all point values in case of a change of an underlying curve.
         * New random point value is generated.
         */
        public final void updatePointObjects() {
            pointKeyPair = curve.newKeyPair(pointKeyPair);
            point = (ECPublicKey) pointKeyPair.getPublic();
        }
    
        /**
         * Generates new random point value.
         */
        public void randomize() {
            if (pointKeyPair == null) {
                pointKeyPair = curve.newKeyPair(null);
                point = (ECPublicKey) pointKeyPair.getPublic();
            } else {
                pointKeyPair.genKeyPair();
            }
        }
    
        /**
         * Copy value of provided point into this. This and other point must have
         * curve with same parameters, only length is checked.
         *
         * @param other point to be copied
         */
        public void copy(ECPoint other) {
            if (length() != other.length()) {
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
            }
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            rm.lock(pointBuffer);
            short len = other.getW(pointBuffer, (short) 0);
            setW(pointBuffer, (short) 0, len);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Set this point value (parameter W) from array with value encoded as per ANSI X9.62.
         * The uncompressed form is always supported. If underlying native JavaCard implementation
         * of {@code ECPublicKey} supports compressed points, then this method accepts also compressed points.
         *
         * @param buffer array with serialized point
         * @param offset start offset within input array
         * @param length length of point
         */
        public void setW(byte[] buffer, short offset, short length) {
            point.setW(buffer, offset, length);
        }
    
        /**
         * Returns current value of this point.
         *
         * @param buffer memory array where to store serailized point value
         * @param offset start offset for output serialized point
         * @return length of serialized point (number of bytes)
         */
        public short getW(byte[] buffer, short offset) {
            return point.getW(buffer, offset);
        }
    
        /**
         * Returns this point value as ECPublicKey object. No copy of point is made
         * before return, so change of returned object will also change this point value.
         *
         * @return point as ECPublicKey object
         */
        public ECPublicKey asPublicKey() {
            return point;
        }
    
        /**
         * Returns curve associated with this point. No copy of curve is made
         * before return, so change of returned object will also change curve for
         * this point.
         *
         * @return curve as ECCurve object
         */
        public ECCurve getCurve() {
            return curve;
        }
    
        /**
         * Returns the X coordinate of this point in uncompressed form.
         *
         * @param buffer output array for X coordinate
         * @param offset start offset within output array
         * @return length of X coordinate (in bytes)
         */
        public short getX(byte[] buffer, short offset) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            rm.lock(pointBuffer);
            point.getW(pointBuffer, (short) 0);
            Util.arrayCopyNonAtomic(pointBuffer, (short) 1, buffer, offset, curve.COORD_SIZE);
            rm.unlock(pointBuffer);
            return curve.COORD_SIZE;
        }
    
        /**
         * Returns the Y coordinate of this point in uncompressed form.
         *
         * @param buffer output array for Y coordinate
         * @param offset start offset within output array
         * @return length of Y coordinate (in bytes)
         */
        public short getY(byte[] buffer, short offset) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            rm.lock(pointBuffer);
            point.getW(pointBuffer, (short) 0);
            Util.arrayCopyNonAtomic(pointBuffer, (short) (1 + curve.COORD_SIZE), buffer, offset, curve.COORD_SIZE);
            rm.unlock(pointBuffer);
            return curve.COORD_SIZE;
        }
    
        /**
         * Returns the Y coordinate of this point in form of BigNat object.
         *
         * @param yCopy BigNat object which will be set with value of this point
         */
        public void getY(BigNat yCopy) {
            yCopy.set_size(getY(yCopy.as_byte_array(), (short) 0));
        }
    
        /**
         * Double this point. Pure implementation without KeyAgreement.
         */
        public void swDouble() {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            BigNat pX = rm.EC_BN_B;
            BigNat pY = rm.EC_BN_C;
            BigNat lambda = rm.EC_BN_D;
            BigNat tmp = rm.EC_BN_E;
    
            rm.lock(pointBuffer);
            getW(pointBuffer, (short) 0);
    
            pX.lock();
            pX.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);
    
            pY.lock();
            pY.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
    
            lambda.lock();
            lambda.mod_mult(pX, pX, curve.pBN);
            lambda.mod_mult(lambda, ResourceManager.THREE, curve.pBN);
            lambda.mod_add(curve.aBN, curve.pBN);
    
            tmp.lock();
            tmp.clone(pY);
            tmp.mod_add(tmp, curve.pBN);
            tmp.mod_inv(curve.pBN);
            lambda.mod_mult(lambda, tmp, curve.pBN);
            tmp.mod_mult(lambda, lambda, curve.pBN);
            tmp.mod_sub(pX, curve.pBN);
            tmp.mod_sub(pX, curve.pBN);
            tmp.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
    
            tmp.mod_sub(pX, curve.pBN);
            pX.unlock();
            tmp.mod_mult(tmp, lambda, curve.pBN);
            lambda.unlock();
            tmp.mod_add(pY, curve.pBN);
            tmp.mod_negate(curve.pBN);
            pY.unlock();
            tmp.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
            tmp.unlock();
    
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
        }
    
    
        /**
         * Doubles the current value of this point.
         */
        public void makeDouble() {
            // doubling via add sometimes causes exception inside KeyAgreement engine
            // this.add(this);
            // Use bit slower, but more robust version via multiplication by 2
            this.multiplication(ResourceManager.TWO);
        }
    
        /**
         * Adds this (P) and provided (Q) point. Stores a resulting value into this point.
         *
         * @param other point to be added to this.
         */
        public void add(ECPoint other) {
            if (OperationSupport.getInstance().EC_HW_ADD) {
                hwAdd(other);
            } else {
                swAdd(other);
            }
        }
    
        /**
         * Implements adding of two points without ALG_EC_PACE_GM.
         *
         * @param other point to be added to this.
         */
        private void swAdd(ECPoint other) {
            boolean samePoint = this == other || isEqual(other);
            if (samePoint && OperationSupport.getInstance().EC_HW_XY) {
                multiplication(ResourceManager.TWO);
                return;
            }
    
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            BigNat xR = rm.EC_BN_B;
            BigNat yR = rm.EC_BN_C;
            BigNat xP = rm.EC_BN_D;
            BigNat yP = rm.EC_BN_E;
            BigNat xQ = rm.EC_BN_F;
            BigNat nominator = rm.EC_BN_B;
            BigNat denominator = rm.EC_BN_C;
            BigNat lambda = rm.EC_BN_A;
    
            rm.lock(pointBuffer);
            point.getW(pointBuffer, (short) 0);
            xP.lock();
            xP.set_size(curve.COORD_SIZE);
            xP.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);
            yP.lock();
            yP.set_size(curve.COORD_SIZE);
            yP.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
            rm.unlock(pointBuffer);
    
    
            // l = (y_q-y_p)/(x_q-x_p))
            // x_r = l^2 - x_p -x_q
            // y_r = l(x_p-x_r)-y_p
    
            // P + Q = R
            nominator.lock();
            denominator.lock();
            if (samePoint) {
                // lambda = (3(x_p^2)+a)/(2y_p)
                // (3(x_p^2)+a)
                nominator.clone(xP);
                nominator.mod_exp(ResourceManager.TWO, curve.pBN);
                nominator.mod_mult(nominator, ResourceManager.THREE, curve.pBN);
                nominator.mod_add(curve.aBN, curve.pBN);
                // (2y_p)
                denominator.clone(yP);
                denominator.mod_mult(yP, ResourceManager.TWO, curve.pBN);
                denominator.mod_inv(curve.pBN);
    
            } else {
                // lambda = (y_q-y_p) / (x_q-x_p) mod p
                rm.lock(pointBuffer);
                other.point.getW(pointBuffer, (short) 0);
                xQ.lock();
                xQ.set_size(curve.COORD_SIZE);
                xQ.from_byte_array(other.curve.COORD_SIZE, (short) 0, pointBuffer, (short) 1);
                nominator.set_size(curve.COORD_SIZE);
                nominator.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
                rm.unlock(pointBuffer);
    
                nominator.mod(curve.pBN);
    
                nominator.mod_sub(yP, curve.pBN);
    
                // (x_q-x_p)
                denominator.clone(xQ);
                denominator.mod(curve.pBN);
                denominator.mod_sub(xP, curve.pBN);
                denominator.mod_inv(curve.pBN);
            }
    
            lambda.lock();
            lambda.resize_to_max(false);
            lambda.zero();
            lambda.mod_mult(nominator, denominator, curve.pBN);
            nominator.unlock();
            denominator.unlock();
    
            // (x_p, y_p) + (x_q, y_q) = (x_r, y_r)
            // lambda = (y_q - y_p) / (x_q - x_p)
    
            // x_r = lambda^2 - x_p - x_q
            xR.lock();
            if (samePoint) {
                short len = multXKA(ResourceManager.TWO, xR.as_byte_array(), (short) 0);
                xR.set_size(len);
            } else {
                xR.clone(lambda);
                xR.mod_exp2(curve.pBN);
                xR.mod_sub(xP, curve.pBN);
                xR.mod_sub(xQ, curve.pBN);
            }
            xQ.unlock();
    
            // y_r = lambda(x_p - x_r) - y_p
            yR.lock();
            yR.clone(xP);
            xP.unlock();
            yR.mod_sub(xR, curve.pBN);
            yR.mod_mult(yR, lambda, curve.pBN);
            lambda.unlock();
            yR.mod_sub(yP, curve.pBN);
            yP.unlock();
    
            rm.lock(pointBuffer);
            pointBuffer[0] = (byte) 0x04;
            // If x_r.length() and y_r.length() is smaller than curve.COORD_SIZE due to leading zeroes which were shrunk before, then we must add these back
            xR.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
            xR.unlock();
            yR.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
            yR.unlock();
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Implements adding of two points via ALG_EC_PACE_GM.
         *
         * @param other point to be added to this.
         */
        private void hwAdd(ECPoint other) {
            byte[] pointBuffer = rm.POINT_ARRAY_B;
    
            rm.lock(pointBuffer);
            setW(pointBuffer, (short) 0, multAndAddKA(ResourceManager.ONE_COORD, other, pointBuffer, (short) 0));
            rm.unlock(pointBuffer);
        }
    
        /**
         * Multiply value of this point by provided scalar. Stores the result into this point.
         *
         * @param scalarBytes value of scalar for multiplication
         */
        public void multiplication(byte[] scalarBytes, short scalarOffset, short scalarLen) {
            BigNat scalar = rm.EC_BN_F;
    
            scalar.lock();
            scalar.set_size(scalarLen);
            scalar.from_byte_array(scalarLen, (short) 0, scalarBytes, scalarOffset);
            multiplication(scalar);
            scalar.unlock();
        }
    
        /**
         * Multiply value of this point by provided scalar. Stores the result into this point.
         *
         * @param scalar value of scalar for multiplication
         */
        public void multiplication(BigNat scalar) {
            if (OperationSupport.getInstance().EC_SW_DOUBLE && scalar.same_value(ResourceManager.TWO)) {
                swDouble();
            // } else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY) {
            } else if (rm.ecMultKA.getAlgorithm() == (byte) 6) {
                multXY(scalar);
            //} else if (rm.ecMultKA.getAlgorithm() == KeyAgreement.ALG_EC_SVDP_DH_PLAIN) {
            } else if (rm.ecMultKA.getAlgorithm() == (byte) 3) {
                multX(scalar);
            } else {
                ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
            }
        }
    
        /**
         * Multiply this point by a given scalar and add another point to the result.
         *
         * @param scalar value of scalar for multiplication
         * @param point the other point
         */
        public void multAndAdd(BigNat scalar, ECPoint point) {
            if (!OperationSupport.getInstance().EC_HW_ADD) {
                ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
            }
            byte[] pointBuffer = rm.POINT_ARRAY_B;
    
            rm.lock(pointBuffer);
            setW(pointBuffer, (short) 0, multAndAddKA(scalar, point, pointBuffer, (short) 0));
            rm.unlock(pointBuffer);
        }
    
        /**
         * Multiply this point by a given scalar and add another point to the result and store the result into outBuffer.
         *
         * @param scalar value of scalar for multiplication
         * @param point the other point
         * @param outBuffer output buffer
         * @param outBufferOffset offset in the output buffer
         */
        private short multAndAddKA(BigNat scalar, ECPoint point, byte[] outBuffer, short outBufferOffset) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            rm.lock(pointBuffer);
            short len = this.getW(pointBuffer, (short) 0);
            curve.disposable_priv.setG(pointBuffer, (short) 0, len);
            curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
            rm.ecAddKA.init(curve.disposable_priv);
    
            len = point.getW(pointBuffer, (short) 0);
            len = rm.ecAddKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
            rm.unlock(pointBuffer);
            return len;
        }
    
        /**
         * Multiply value of this point by provided scalar using XY key agreement. Stores the result into this point.
         *
         * @param scalar value of scalar for multiplication
         */
        public void multXY(BigNat scalar) {
            byte[] pointBuffer = rm.POINT_ARRAY_B;
    
            rm.lock(pointBuffer);
            short len = multXYKA(scalar, pointBuffer, (short) 0);
            setW(pointBuffer, (short) 0, len);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Multiplies this point value with provided scalar and stores result into
         * provided array. No modification of this point is performed.
         * Native XY KeyAgreement engine is used.
         *
         * @param scalar          value of scalar for multiplication
         * @param outBuffer       output array for resulting value
         * @param outBufferOffset offset within output array
         * @return length of resulting value (in bytes)
         */
        public short multXYKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
            rm.ecMultKA.init(curve.disposable_priv);
    
            rm.lock(pointBuffer);
            short len = getW(pointBuffer, (short) 0);
            len = rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
            rm.unlock(pointBuffer);
            return len;
        }
    
        /**
         * Multiply value of this point by provided scalar using X-only key agreement. Stores the result into this point.
         *
         * @param scalar value of scalar for multiplication
         */
        private void multX(BigNat scalar) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            byte[] resultBuffer = rm.ARRAY_A;
            BigNat x = rm.EC_BN_B;
            BigNat ySq = rm.EC_BN_C;
            BigNat y1 = rm.EC_BN_D;
            BigNat y2 = rm.EC_BN_B;
    
            x.lock();
            short len = multXKA(scalar, x.as_byte_array(), (short) 0);
            x.set_size(len);
    
            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            ySq.lock();
            ySq.clone(x);
            ySq.mod_exp(ResourceManager.TWO, curve.pBN);
            ySq.mod_add(curve.aBN, curve.pBN);
            ySq.mod_mult(ySq, x, curve.pBN);
            ySq.mod_add(curve.bBN, curve.pBN);
            y1.lock();
            y1.clone(ySq);
            ySq.unlock();
            y1.sqrt_FP(curve.pBN);
    
            // Construct public key with <x, y_1>
            rm.lock(pointBuffer);
            pointBuffer[0] = 0x04;
            x.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
            x.unlock();
            y1.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
            setW(pointBuffer, (short) 0, curve.POINT_SIZE); //So that we can convert to pub key
    
            // Check if public point <x, y_1> corresponds to the "secret" (i.e., our scalar)
            rm.lock(resultBuffer);
            if (!SignVerifyECDSA(curve.bignatAsPrivateKey(scalar), asPublicKey(), rm.verifyEcdsa, resultBuffer)) { // If verification fails, then pick the <x, y_2>
                y2.lock();
                y2.clone(curve.pBN); // y_2 = p - y_1
                y2.mod_sub(y1, curve.pBN);
                y2.copy_to_buffer(pointBuffer, (short) (1 + curve.COORD_SIZE));
                y2.unlock();
            }
            rm.unlock(resultBuffer);
            y1.unlock();
    
    
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Multiplies this point value with provided scalar and stores result into
         * provided array. No modification of this point is performed.
         * Native X-only KeyAgreement engine is used.
         *
         * @param scalar          value of scalar for multiplication
         * @param outBuffer       output array for resulting value
         * @param outBufferOffset offset within output array
         * @return length of resulting value (in bytes)
         */
        private short multXKA(BigNat scalar, byte[] outBuffer, short outBufferOffset) {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            // NOTE: potential problem on real cards (j2e) - when small scalar is used (e.g., BigNat.TWO), operation sometimes freezes
            curve.disposable_priv.setS(scalar.as_byte_array(), (short) 0, scalar.length());
    
            rm.ecMultKA.init(curve.disposable_priv);
    
            rm.lock(pointBuffer);
            short len = getW(pointBuffer, (short) 0);
            len = rm.ecMultKA.generateSecret(pointBuffer, (short) 0, len, outBuffer, outBufferOffset);
            rm.unlock(pointBuffer);
            // Return always length of whole coordinate X instead of len - some real cards returns shorter value equal to SHA-1 output size although PLAIN results is filled into buffer (GD60) 
            return curve.COORD_SIZE;
        }
    
        /**
         * Computes negation of this point.
         * The operation will dump point into uncompressed_point_arr, negate Y and restore back
         */
        public void negate() {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            BigNat y = rm.EC_BN_C;
    
            y.lock();
            rm.lock(pointBuffer);
            point.getW(pointBuffer, (short) 0);
            y.set_size(curve.COORD_SIZE);
            y.from_byte_array(curve.COORD_SIZE, (short) 0, pointBuffer, (short) (1 + curve.COORD_SIZE));
            y.mod_negate(curve.pBN);
            y.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
            y.unlock();
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Restore point from X coordinate. Stores one of the two results into this point.
         *
         * @param xCoord  byte array containing the X coordinate
         * @param xOffset offset in the byte array
         * @param xLen    length of the X coordinate
         */
        public void fromX(byte[] xCoord, short xOffset, short xLen) {
            BigNat x = rm.EC_BN_F;
    
            x.lock();
            x.set_size(xLen);
            x.from_byte_array(xLen, (short) 0, xCoord, xOffset);
            fromX(x);
            x.unlock();
        }
    
        /**
         * Restore point from X coordinate. Stores one of the two results into this point.
         *
         * @param x the x coordinate
         */
        private void fromX(BigNat x) {
            BigNat y_sq = rm.EC_BN_C;
            BigNat y = rm.EC_BN_D;
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            //Y^2 = X^3 + XA + B = x(x^2+A)+B
            y_sq.lock();
            y_sq.clone(x);
            y_sq.mod_exp(ResourceManager.TWO, curve.pBN);
            y_sq.mod_add(curve.aBN, curve.pBN);
            y_sq.mod_mult(y_sq, x, curve.pBN);
            y_sq.mod_add(curve.bBN, curve.pBN);
            y.lock();
            y.clone(y_sq);
            y_sq.unlock();
            y.sqrt_FP(curve.pBN);
    
            // Construct public key with <x, y_1>
            rm.lock(pointBuffer);
            pointBuffer[0] = 0x04;
            x.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) 1);
            y.prepend_zeros(curve.COORD_SIZE, pointBuffer, (short) (1 + curve.COORD_SIZE));
            y.unlock();
            setW(pointBuffer, (short) 0, curve.POINT_SIZE);
            rm.unlock(pointBuffer);
        }
    
        /**
         * Returns true if Y coordinate is even; false otherwise.
         *
         * @return true if Y coordinate is even; false otherwise
         */
        public boolean isYEven() {
            byte[] pointBuffer = rm.POINT_ARRAY_A;
    
            rm.lock(pointBuffer);
            point.getW(pointBuffer, (short) 0);
            boolean result = pointBuffer[(short) (curve.POINT_SIZE - 1)] % 2 == 0;
            rm.unlock(pointBuffer);
            return result;
        }
    
        /**
         * Compares this and provided point for equality. The comparison is made using hash of both values to prevent leak of position of mismatching byte.
         *
         * @param other second point for comparison
         * @return true if both point are exactly equal (same length, same value), false otherwise
         */
        public boolean isEqual(ECPoint other) {
            if (length() != other.length()) {
                return false;
            }
            // The comparison is made with hash of point values instead of directly values.
            // This way, offset of first mismatching byte is not leaked via timing side-channel.
            // Additionally, only single array is required for storage of plain point values thus saving some RAM.
            byte[] pointBuffer = rm.POINT_ARRAY_A;
            byte[] hashBuffer = rm.HASH_ARRAY;
    
            rm.lock(pointBuffer);
            rm.lock(hashBuffer);
            short len = getW(pointBuffer, (short) 0);
            rm.hashEngine.doFinal(pointBuffer, (short) 0, len, hashBuffer, (short) 0);
            len = other.getW(pointBuffer, (short) 0);
            len = rm.hashEngine.doFinal(pointBuffer, (short) 0, len, pointBuffer, (short) 0);
            boolean bResult = Util.arrayCompare(hashBuffer, (short) 0, pointBuffer, (short) 0, len) == 0;
            rm.unlock(hashBuffer);
            rm.unlock(pointBuffer);
    
            return bResult;
        }
    
        static byte[] msg = {(byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x03};
    
        public static boolean SignVerifyECDSA(ECPrivateKey privateKey, ECPublicKey publicKey, Signature signEngine, byte[] tmpSignArray) {
            // TODO does not work properly in simulator
            signEngine.init(privateKey, Signature.MODE_SIGN);
            short signLen = signEngine.sign(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0);
            signEngine.init(publicKey, Signature.MODE_VERIFY);
            return signEngine.verify(msg, (short) 0, (short) msg.length, tmpSignArray, (short) 0, signLen);
        }
    
    
        //
        // ECKey methods
        //
        public void setFieldFP(byte[] bytes, short s, short s1) throws CryptoException {
            point.setFieldFP(bytes, s, s1);
        }
    
        public void setFieldF2M(short s) throws CryptoException {
            point.setFieldF2M(s);
        }
    
        public void setFieldF2M(short s, short s1, short s2) throws CryptoException {
            point.setFieldF2M(s, s1, s2);
        }
    
        public void setA(byte[] bytes, short s, short s1) throws CryptoException {
            point.setA(bytes, s, s1);
        }
    
        public void setB(byte[] bytes, short s, short s1) throws CryptoException {
            point.setB(bytes, s, s1);
        }
    
        public void setG(byte[] bytes, short s, short s1) throws CryptoException {
            point.setG(bytes, s, s1);
        }
    
        public void setR(byte[] bytes, short s, short s1) throws CryptoException {
            point.setR(bytes, s, s1);
        }
    
        public void setK(short s) {
            point.setK(s);
        }
    
        public short getField(byte[] bytes, short s) throws CryptoException {
            return point.getField(bytes, s);
        }
    
        public short getA(byte[] bytes, short s) throws CryptoException {
            return point.getA(bytes, s);
        }
    
        public short getB(byte[] bytes, short s) throws CryptoException {
            return point.getB(bytes, s);
        }
    
        public short getG(byte[] bytes, short s) throws CryptoException {
            return point.getG(bytes, s);
        }
    
        public short getR(byte[] bytes, short s) throws CryptoException {
            return point.getR(bytes, s);
        }
    
        public short getK() throws CryptoException {
            return point.getK();
        }
    }
    
    /**
     * OperationSupport class
     *
     * @author Antonin Dufka
     */
    static class OperationSupport {
        private static OperationSupport instance;
    
        public static final short SIMULATOR = 0x0000;
        public static final short J2E145G = 0x0001;
        public static final short J3H145 = 0x0002;
        public static final short J3R180 = 0x0003;
    
        public boolean RSA_MULT_TRICK = false;
        public boolean RSA_MOD_EXP = false;
        public boolean RSA_PREPEND_ZEROS = false;
        public boolean RSA_KEY_REFRESH = false;
        public boolean RSA_RESIZE_BASE = true;
        public boolean RSA_RESIZE_MODULUS = true;
        public boolean EC_HW_XY = false;
        public boolean EC_HW_X = true;
        public boolean EC_HW_ADD = false;
        public boolean EC_SW_DOUBLE = false;
        public boolean DEFERRED_INITIALIZATION = false;
    
        private OperationSupport() {
        }
    
        public static OperationSupport getInstance() {
            if (OperationSupport.instance == null)
                OperationSupport.instance = new OperationSupport();
            return OperationSupport.instance;
        }
    
        public void setCard(short card_identifier) {
            switch (card_identifier) {
                case SIMULATOR:
                    RSA_MULT_TRICK = false;
                    RSA_MOD_EXP = true;
                    RSA_PREPEND_ZEROS = true;
                    RSA_KEY_REFRESH = true;
                    RSA_RESIZE_BASE = true;
                    RSA_RESIZE_MODULUS = false;
                    EC_SW_DOUBLE = true;
                    EC_HW_XY = true;
                    EC_HW_ADD = true;
                    break;
                case J2E145G:
                    RSA_MULT_TRICK = true;
                    RSA_MOD_EXP = true;
                    break;
                case J3H145:
                    RSA_MULT_TRICK = true;
                    RSA_MOD_EXP = false;
                    EC_HW_XY = true;
                    break;
                case J3R180:
                    DEFERRED_INITIALIZATION = true;
                    RSA_MULT_TRICK = true;
                    RSA_MOD_EXP = true;
                    EC_HW_XY = true;
                    EC_HW_ADD = true;
                    break;
                default:
                    break;
            }
        }
    }
    
    
    /**
     * Configure itself to proper lengths and other parameters according to intended length of ECC
     * @author Petr Svenda
     */
    static class ECConfig {
        /**
         * The size of speedup engine used for fast modulo exponent computation
         * (must be larger than biggest Bignat used)
         */
        public short MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
        /**
         * The size of speedup engine used for fast multiplication of large numbers
         * Must be larger than 2x biggest Bignat used
         */
        public short MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
        /**
         * The size of largest integer used in computations
         */
        public short MAX_BIGNAT_SIZE = (short) 65; // ((short) (MODULO_ENGINE_MAX_LENGTH_BITS / 8) + 1);
        /**
         * The size of largest ECC point used
         */
        public short MAX_POINT_SIZE = (short) 64;
        /**
         * The size of single coordinate of the largest ECC point used 
         */
        public short MAX_COORD_SIZE = (short) 32; // MAX_POINT_SIZE / 2
        
        
        public ResourceManager rm;
    
        /**
         * Creates new control structure for requested bit length with all preallocated arrays and engines 
         * @param maxECLength maximum length of ECPoint objects supported. The provided value is used to 
         *      initialize properly underlying arrays and engines.  
         */
        public ECConfig(short maxECLength) {
            if (maxECLength <= (short) 256) {
                setECC256Config();
            }
            else if (maxECLength <= (short) 384) {
                setECC384Config();
            } 
            else if (maxECLength <= (short) 512) {
                setECC512Config();
            }
            else {
                ISOException.throwIt(ReturnCodes.SW_ECPOINT_INVALIDLENGTH);
            }
    
            rm = new ResourceManager(MAX_POINT_SIZE, MAX_COORD_SIZE, MAX_BIGNAT_SIZE, MULT_RSA_ENGINE_MAX_LENGTH_BITS, MODULO_RSA_ENGINE_MAX_LENGTH_BITS);
        }
        
        public void refreshAfterReset() {
            if (rm.locker != null) { 
                rm.locker.refreshAfterReset();
            }        
        }
    
        public void setECC256Config() {
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 512;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;        
            MAX_POINT_SIZE = (short) 64;
            computeDerivedLengths();
        }
        public void setECC384Config() {
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 768;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
            MAX_POINT_SIZE = (short) 96;
            computeDerivedLengths();
        }
        public void setECC512Config() {
            MODULO_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1024;
            MULT_RSA_ENGINE_MAX_LENGTH_BITS = (short) 1280;
            MAX_POINT_SIZE = (short) 128;
            computeDerivedLengths();
        }
    
        private void computeDerivedLengths() {
            MAX_BIGNAT_SIZE = (short) ((short) (MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8) + 1);
            MAX_COORD_SIZE = (short) (MAX_POINT_SIZE / 2);
        }
    
        /**
         * Unlocks all logically locked arrays and objects. Useful as recovery after premature end of some operation (e.g., due to exception)
         * when some objects remains locked.
         */
        void unlockAll() {
            rm.unlockAll();
        }
    }
    
    
    /**
     * 
     * @author Vasilios Mavroudis and Petr Svenda
     */
    static class ECCurve {
        public final short KEY_LENGTH; //Bits
        public final short POINT_SIZE; //Bytes
        public final short COORD_SIZE; //Bytes
    
        //Parameters
        public byte[] p;
        public byte[] a;
        public byte[] b;
        public byte[] G;
        public byte[] r;
        
        public BigNat pBN;
        public BigNat aBN;
        public BigNat bBN;
        public BigNat rBN;

        public KeyPair disposable_pair;
        public ECPrivateKey disposable_priv;
    
        
    
        /**
         * Creates new curve object from provided parameters. Either copy of provided
         * arrays is performed (bCopyArgs == true, input arrays can be reused later for other
         * purposes) or arguments are directly stored (bCopyArgs == false, usable for fixed static arrays) .
         * @param bCopyArgs if true, copy of arguments is created, otherwise reference is directly stored
         * @param p_arr array with p
         * @param a_arr array with a
         * @param b_arr array with b
         * @param G_arr array with base point G
         * @param r_arr array with r
         */
        public ECCurve(boolean bCopyArgs, byte[] p_arr, byte[] a_arr, byte[] b_arr, byte[] G_arr, byte[] r_arr) {
            //ECCurve_initialize(p_arr, a_arr, b_arr, G_arr, r_arr);
            this.KEY_LENGTH = (short) (p_arr.length * 8);
            this.POINT_SIZE = (short) G_arr.length;
            this.COORD_SIZE = (short) ((short) (G_arr.length - 1) / 2);
    
            if (bCopyArgs) {
                // Copy curve parameters into newly allocated arrays in EEPROM (will be only read, not written later => good performance even when in EEPROM)
                this.p = new byte[(short) p_arr.length];
                this.a = new byte[(short) a_arr.length];
                this.b = new byte[(short) b_arr.length];
                this.G = new byte[(short) G_arr.length];
                this.r = new byte[(short) r_arr.length];
    
                Util.arrayCopyNonAtomic(p_arr, (short) 0, p, (short) 0, (short) p.length);
                Util.arrayCopyNonAtomic(a_arr, (short) 0, a, (short) 0, (short) a.length);
                Util.arrayCopyNonAtomic(b_arr, (short) 0, b, (short) 0, (short) b.length);
                Util.arrayCopyNonAtomic(G_arr, (short) 0, G, (short) 0, (short) G.length);
                Util.arrayCopyNonAtomic(r_arr, (short) 0, r, (short) 0, (short) r.length);
            }
            else {
                // No allocation, store directly provided arrays 
                this.p = p_arr;
                this.a = a_arr;
                this.b = b_arr;
                this.G = G_arr;
                this.r = r_arr;
            }
    
            // We will not modify values of p/a/b/r during the lifetime of curve => allocate helper bignats directly from the array
            // Additionally, these Bignats will be only read from so Bignat_Helper can be null (saving need to pass as argument to ECCurve)
            this.pBN = new BigNat(this.p, null);
            this.aBN = new BigNat(this.a, null);
            this.bBN = new BigNat(this.b, null);
            this.rBN = new BigNat(this.r, null);

            this.disposable_pair = this.newKeyPair(null);
            this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
        }    
        
        /**
         * Refresh critical information stored in RAM for performance reasons after a card reset (RAM was cleared).
         */
        public void updateAfterReset() {
            this.pBN.from_byte_array(this.p);
            this.aBN.from_byte_array(this.a);
            this.bBN.from_byte_array(this.b);
        }
        
        /**
         * Creates a new keyPair based on this curve parameters. KeyPair object is reused if provided. Fresh keyPair value is generated.
         * @param existingKeyPair existing KeyPair object which is reused if required. If null, new KeyPair is allocated
         * @return new or existing object with fresh key pair value
         */
        KeyPair newKeyPair(KeyPair existingKeyPair) {
            ECPrivateKey privKey;
            ECPublicKey pubKey;
            if (existingKeyPair == null) { // Allocate if not supplied
                existingKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_LENGTH);
            }
            
            // Some implementation will not return valid pub key until ecKeyPair.genKeyPair() is called
            // Other implementation will fail with exception if same is called => try catch and drop any exception 
            try {
                pubKey = (ECPublicKey) existingKeyPair.getPublic();
                if (pubKey == null) {
                    existingKeyPair.genKeyPair();
                }
            } catch (Exception e) {
            } // intentionally do nothing
            
            privKey = (ECPrivateKey) existingKeyPair.getPrivate();
            pubKey = (ECPublicKey) existingKeyPair.getPublic();
    
            // Set required values
            privKey.setFieldFP(p, (short) 0, (short) p.length);
            privKey.setA(a, (short) 0, (short) a.length);
            privKey.setB(b, (short) 0, (short) b.length);
            privKey.setG(G, (short) 0, (short) G.length);
            privKey.setR(r, (short) 0, (short) r.length);
            privKey.setK((short) 1);
    
            pubKey.setFieldFP(p, (short) 0, (short) p.length);
            pubKey.setA(a, (short) 0, (short) a.length);
            pubKey.setB(b, (short) 0, (short) b.length);
            pubKey.setG(G, (short) 0, (short) G.length);
            pubKey.setR(r, (short) 0, (short) r.length);
            pubKey.setK((short) 1);
    
            existingKeyPair.genKeyPair();
    
            return existingKeyPair;
        }
        
        public KeyPair newKeyPair_legacy(KeyPair existingKeyPair) {
            ECPrivateKey privKey;
            ECPublicKey pubKey;
            if (existingKeyPair == null) {
                // We need to create required objects
                privKey = (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KEY_LENGTH, false);
                pubKey = (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KEY_LENGTH, false);
            }
            else {
                // Obtain from object
                privKey = (ECPrivateKey) existingKeyPair.getPrivate();
                pubKey = (ECPublicKey) existingKeyPair.getPublic();
            }
            // Set required values
            privKey.setFieldFP(p, (short) 0, (short) p.length);
            privKey.setA(a, (short) 0, (short) a.length);
            privKey.setB(b, (short) 0, (short) b.length);
            privKey.setG(G, (short) 0, (short) G.length);
            privKey.setR(r, (short) 0, (short) r.length);
    
            pubKey.setFieldFP(p, (short) 0, (short) p.length);
            pubKey.setA(a, (short) 0, (short) a.length);
            pubKey.setB(b, (short) 0, (short) b.length);
            pubKey.setG(G, (short) 0, (short) G.length);
            pubKey.setR(r, (short) 0, (short) r.length);
    
            if (existingKeyPair == null) { // Allocate if not supplied
                existingKeyPair = new KeyPair(pubKey, privKey);
            }
            existingKeyPair.genKeyPair();
    
            return existingKeyPair;
        }
        
        
        /**
         * Converts provided Bignat into temporary EC private key object. No new 
         * allocation is performed, returned ECPrivateKey is overwritten by next call.
         * @param bn Bignat with new value
         * @return ECPrivateKey initialized with provided Bignat
         */
        public ECPrivateKey bignatAsPrivateKey(BigNat bn) {
            disposable_priv.setS(bn.as_byte_array(), (short) 0, bn.length());
            return disposable_priv;
        }
        
        /**
         * Set new G for this curve. Also updates all dependent key values.
         * @param newG buffer with new G
         * @param newGOffset start offset within newG
         * @param newGLen length of new G
         */
        public void setG(byte[] newG, short newGOffset, short newGLen) {
            Util.arrayCopyNonAtomic(newG, newGOffset, G, (short) 0, newGLen);
            this.disposable_pair = this.newKeyPair(this.disposable_pair);
            this.disposable_priv = (ECPrivateKey) this.disposable_pair.getPrivate();
            this.disposable_priv.setG(newG, newGOffset, newGLen);  
        }
    }
    /**
     * Credits: Based on Bignat library from OV-chip project https://ovchip.cs.ru.nl/OV-chip_2.0 by Radboud University Nijmegen
     */
    
    
    /**
     * @author Vasilios Mavroudis and Petr Svenda
     */
    static class BigNat {
        // Threshold bit length of mult operand to invoke RSA trick
        public static final short FAST_MULT_VIA_RSA_THRESHOLD_LENGTH = (short) 16;
    
        private final ResourceManager rm;
        /**
         * Configuration flag controlling re-allocation of internal array. If true, internal BigNat buffer can be enlarged during clone
         * operation if required (keep false to prevent slow reallocations)
         */
        boolean ALLOW_RUNTIME_REALLOCATION = false;
    
        /**
         * Configuration flag controlling clearing of shared BigNats on lock as prevention of unwanted leak of sensitive information from previous operation.
         * If true, internal storage array is erased once BigNat is locked for use
         */
        boolean ERASE_ON_LOCK = false;
        /**
         * Configuration flag controlling clearing of shared Bignats on unlock as
         * prevention of unwanted leak of sensitive information to next operation.
         * If true, internal storage array is erased once Bignat is unlocked from use
         */
        boolean ERASE_ON_UNLOCK = false;
    
        /**
         * Factor for converting digit size into short length. 1 for the short/short
         * converting, 4 for the int/long configuration.
         */
        public static final short size_multiplier = 1;
    
        /**
         * Bitmask for extracting a digit out of a longer int/short value. short
         * 0xff for the short/short configuration, long 0xffffffffL the int/long
         * configuration.
         */
        public static final short digit_mask = 0xff;
    
        /**
         * Bitmask for the highest bit in a digit. short 0x80 for the short/short
         * configuration, long 0x80000000 for the int/long configuration.
         */
        public static final short digit_first_bit_mask = 0x80;
    
        /**
         * Bitmask for the second highest bit in a digit. short 0x40 for the
         * short/short configuration, long 0x40000000 for the int/long
         * configuration.
         */
        public static final short digit_second_bit_mask = 0x40;
    
        /**
         * Bitmask for the two highest bits in a digit. short 0xC0 for the
         * short/short configuration, long 0xC0000000 for the int/long
         * configuration.
         */
        public static final short digit_first_two_bit_mask = 0xC0;
    
        /**
         * Size in bits of one digit. 8 for the short/short configuration, 32 for
         * the int/long configuration.
         */
        public static final short digit_len = 8;
    
        /**
         * Size in bits of a double digit. 16 for the short/short configuration, 64
         * for the int/long configuration.
         */
        private static final short double_digit_len = 16;
    
        /**
         * Bitmask for erasing the sign bit in a double digit. short 0x7fff for the
         * short/short configuration, long 0x7fffffffffffffffL for the int/long
         * configuration.
         */
        private static final short positive_double_digit_mask = 0x7fff;
    
        /**
         * Bitmask for the highest bit in a double digit.
         */
        public static final short highest_digit_bit = (short) (1L << (digit_len - 1));
    
        /**
         * The base as a double digit. The base is first value that does not fit
         * into a single digit. 2^8 for the short/short configuration and 2^32 for
         * the int/long configuration.
         */
        public static final short bignat_base = (short) (1L << digit_len);
    
        /**
         * Bitmask with just the highest bit in a double digit.
         */
        public static final short highest_double_digit_bit = (short) (1L << (double_digit_len - 1));
    
        /**
         * Digit array. Elements have type byte.
         */
    
        /**
         * Internal storage array for this Bignat. The current version uses byte array with
         * intermediate values stored which can be quickly processed with
         */
        private byte[] value;
        private short size = -1;     // Current size of stored Bignat. Current number is encoded in first {@code size} of value array, starting from value[0]
        private short max_size = -1; // Maximum size of this Bignat. Corresponds to value.length
        private byte allocatorType = JCSystem.MEMORY_TYPE_PERSISTENT; // Memory storage type for value buffer
    
        private boolean locked = false;    // Logical flag to store info if this Bignat is currently used for some operation. Used as a prevention of unintentional parallel use of same temporary pre-allocated Bignats.
    
        /**
         * Construct a Bignat of size {@code size} in shorts. Allocated in EEPROM or RAM based on
         * {@code allocatorType}. JCSystem.MEMORY_TYPE_PERSISTENT, in RAM otherwise.
         *
         * @param size          the size of the new Bignat in bytes
         * @param allocatorType type of allocator storage
         *                      JCSystem.MEMORY_TYPE_PERSISTENT => EEPROM (slower writes, but RAM is saved)
         *                      JCSystem.MEMORY_TYPE_TRANSIENT_RESET => RAM
         *                      JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT => RAM
         * @param bignatHelper  {@code Bignat_Helper} class with helper objects
         */
        public BigNat(short size, byte allocatorType, ResourceManager rm) {
            this.rm = rm;
            allocate_storage_array(size, allocatorType);
        }
    
        /**
         * Construct a Bignat with provided array used as internal storage as well as initial value.
         * No copy of array is made. If this Bignat is used in operation which modifies the Bignat value,
         * content of provided array is changed.
         *
         * @param valueBuffer  internal storage
         * @param bignatHelper {@code Bignat_Helper} class with all relevant settings and helper objects
         */
        public BigNat(byte[] valueBuffer, ResourceManager rm) {
            this.rm = rm;
            this.size = (short) valueBuffer.length;
            this.max_size = (short) valueBuffer.length;
            this.allocatorType = -1; // no allocator
            this.value = valueBuffer;
        }
    
        /**
         * Lock/reserve this bignat for subsequent use.
         * Used to protect corruption of pre-allocated temporary Bignats used in different,
         * potentially nested operations. Must be unlocked by {@code unlock()} later on.
         *
         * @throws SW_LOCK_ALREADYLOCKED if already locked (is already in use by other operation)
         */
        public void lock() {
            if (!locked) {
                locked = true;
                if (ERASE_ON_LOCK) {
                    erase();
                }
            } else {
                // this Bignat is already locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
            }
        }
    
        /**
         * Unlock/release this bignat from use. Used to protect corruption
         * of pre-allocated temporary Bignats used in different nested operations.
         * Must be locked before.
         *
         * @throws SW_LOCK_NOTLOCKED if was not locked before (inconsistence in lock/unlock sequence)
         */
        public void unlock() {
            if (locked) {
                locked = false;
                if (ERASE_ON_UNLOCK) {
                    erase();
                }
            } else {
                // this Bignat is not locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
            }
        }
    
        /**
         * Return current state of logical lock of this object
         *
         * @return true if object is logically locked (reserved), false otherwise
         */
        public boolean isLocked() {
            return locked;
        }
    
        /**
         * Return this Bignat as byte array. For the short/short configuration
         * simply the digit array is returned. For other configurations a new short
         * array is allocated and returned. Modifying the returned short array
         * therefore might or might not change this bignat.
         * IMPORTANT: this function returns directly the underlying storage array.
         * Current value of this Bignat can be stored in smaller number of bytes.
         * Use {@code getLength()} method to obtain actual size.
         *
         * @return this BigNat as byte array
         */
        public byte[] as_byte_array() {
            return value;
        }
    
        /**
         * Serialize this BigNat value into a provided buffer
         *
         * @param buffer       target buffer
         * @param bufferOffset start offset in buffer
         * @return number of bytes copied
         */
        public short copy_to_buffer(byte[] buffer, short bufferOffset) {
            Util.arrayCopyNonAtomic(value, (short) 0, buffer, bufferOffset, size);
            return size;
        }
    
    
        /**
         * Return the size in digits. Provides access to the internal {@link #size}
         * field.
         * <p>
         * The return value is adjusted by {@link #set_size}.
         *
         * @return size in digits.
         */
        public short length() {
            return size;
        }
    
        /**
         * Sets internal size of BigNat. Previous value are kept so value is either non-destructively trimmed or enlarged.
         *
         * @param newSize new size of BigNat. Must be in range of [0, max_size] where max_size was provided during object creation
         */
        public void set_size(short newSize) {
            if (newSize < 0 || newSize > max_size) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_RESIZETOLONGER);
            } else {
                this.size = newSize;
            }
        }
    
        /**
         * Resize internal length of this Bignat to maximum size given during object
         * creation. If required, object is also zeroized
         *
         * @param bZeroize if true, all bytes of internal array are also set to
         *                 zero. If false, previous value is kept.
         */
        public void resize_to_max(boolean bZeroize) {
            set_size(max_size);
            if (bZeroize) {
                zero();
            }
        }
    
        /**
         * Create BigNat with different number of bytes used. Will cause longer number
         * to shrink (loss of the more significant bytes) and shorter to be prepended with zeroes
         *
         * @param new_size new size in bytes
         */
        void deep_resize(short new_size) {
            if (new_size > this.max_size) {
                if (ALLOW_RUNTIME_REALLOCATION) {
                    allocate_storage_array(new_size, this.allocatorType);
                } else {
                    ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED); // Reallocation to longer size not permitted
                }
            }
    
            if (new_size == this.size) {
                return;
            }
    
            byte[] tmpBuffer = rm.ARRAY_A;
            short this_start, other_start, len;
    
            rm.lock(tmpBuffer);
            if (this.size >= new_size) {
                this_start = (short) (this.size - new_size);
                other_start = 0;
                len = new_size;
    
                // Shrinking/cropping
                Util.arrayCopyNonAtomic(value, this_start, tmpBuffer, (short) 0, len);
                Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, (short) 0, len); // Move bytes in item array towards beginning
                // Erase rest of allocated array with zeroes (just as sanitization)
                short toErase = (short) (this.max_size - new_size);
                if (toErase > 0) {
                    Util.arrayFillNonAtomic(value, new_size, toErase, (byte) 0);
                }
            } else {
                this_start = 0;
                other_start = (short) (new_size - this.size);
                len = this.size;
                // Enlarging => Insert zeroes at begging, move bytes in item array towards the end
                Util.arrayCopyNonAtomic(value, this_start, tmpBuffer, (short) 0, len);
                // Move bytes in item array towards end
                Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, value, other_start, len);
                // Fill begin of array with zeroes (just as sanitization)
                if (other_start > 0) {
                    Util.arrayFillNonAtomic(value, (short) 0, other_start, (byte) 0);
                }
            }
            rm.unlock(tmpBuffer);
    
            set_size(new_size);
        }
    
    
        /**
         * Appends zeros in the suffix to reach the defined byte length
         * Essentially multiplies the number with 16 (HEX)
         *
         * @param targetLength required length including appended zeroes
         * @param outBuffer    output buffer for value with appended zeroes
         * @param outOffset    start offset inside outBuffer for write
         */
        public void append_zeros(short targetLength, byte[] outBuffer, short outOffset) {
            Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, outOffset, this.size); //copy the value
            Util.arrayFillNonAtomic(outBuffer, (short) (outOffset + this.size), (short) (targetLength - this.size), (byte) 0); //append zeros
        }
    
        /**
         * Prepends zeros before the value of this Bignat up to target length.
         *
         * @param targetLength required length including prepended zeroes
         * @param outBuffer    output buffer for value with prepended zeroes
         * @param outOffset    start offset inside outBuffer for write
         */
        public void prepend_zeros(short targetLength, byte[] outBuffer, short outOffset) {
            short other_start = (short) (targetLength - this.size);
            if (other_start > 0) {
                Util.arrayFillNonAtomic(outBuffer, outOffset, other_start, (byte) 0); //fill prefix with zeros
            }
            Util.arrayCopyNonAtomic(value, (short) 0, outBuffer, (short) (outOffset + other_start), this.size); //copy the value
        }
    
        /**
         * Remove leading zeroes (if any) from Bignat value and decrease size accordingly
         */
        public void shrink() {
            short i = 0;
            for (i = 0; i < this.length(); i++) { // Find first non-zero byte
                if (this.value[i] != 0) {
                    break;
                }
            }
    
            short new_size = (short) (this.size - i);
            if (new_size < 0) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDRESIZE);
            }
            this.deep_resize(new_size);
        }
    
    
        /**
         * Stores zero in this object for currently used subpart given by internal size.
         */
        public void zero() {
            Util.arrayFillNonAtomic(value, (short) 0, this.size, (byte) 0);
        }
    
        /**
         * Stores zero in this object for whole internal buffer regardless of current size.
         */
        public void zero_complete() {
            Util.arrayFillNonAtomic(value, (short) 0, (short) value.length, (byte) 0);
        }
    
        /**
         * Erase value stored inside this Bignat
         */
        public void erase() {
            zero_complete();
        }
    
    
        /**
         * Stores one in this object. Keeps previous size of this Bignat
         * (1 is prepended with required number of zeroes).
         */
        public void one() {
            this.zero();
            value[(short) (size - 1)] = 1;
        }
    
        /**
         * Stores two in this object. Keeps previous size of this Bignat (2 is
         * prepended with required number of zeroes).
         */
        public void two() {
            this.zero();
            value[(short) (size - 1)] = 0x02;
        }
    
        public void three() {
            this.zero();
            value[(short) (size - 1)] = 0x03;
        }
    
        public void four() {
            this.zero();
            value[(short) (size - 1)] = 0x04;
        }
    
        public void five() {
            this.zero();
            value[(short) (size - 1)] = 0x05;
        }
    
        public void eight() {
            this.zero();
            value[(short) (size - 1)] = 0x08;
        }
    
        public void ten() {
            this.zero();
            value[(short) (size - 1)] = 0x0A;
        }
    
        public void twentyfive() {
            this.zero();
            value[(short) (size - 1)] = 0x19;
        }
    
        public void twentyseven() {
            this.zero();
            value[(short) (size - 1)] = 0x1B;
        }
    
        public void athousand() {
            this.zero();
            value[(short) (size - 2)] = (byte) 0x03;
            value[(short) (size - 1)] = (byte) 0xE8;
        }
    
    
        /**
         * Copies {@code other} into this. No size requirements. If {@code other}
         * has more digits then the superfluous leading digits of {@code other} are
         * asserted to be zero. If this bignat has more digits than its leading
         * digits are correctly initilized to zero. This function will not change size
         * attribute of this object.
         *
         * @param other Bignat to copy into this object.
         */
        public void copy(BigNat other) {
            short this_start, other_start, len;
            if (this.size >= other.size) {
                this_start = (short) (this.size - other.size);
                other_start = 0;
                len = other.size;
            } else {
                this_start = 0;
                other_start = (short) (other.size - this.size);
                len = this.size;
                // Verify here that other have leading zeroes up to other_start
                for (short i = 0; i < other_start; i++) {
                    if (other.value[i] != 0) {
                        ISOException.throwIt(ReturnCodes.SW_BIGNAT_INVALIDCOPYOTHER);
                    }
                }
            }
    
            if (this_start > 0) {
                // if this bignat has more digits than its leading digits are initilized to zero
                Util.arrayFillNonAtomic(this.value, (short) 0, this_start, (byte) 0);
            }
            Util.arrayCopyNonAtomic(other.value, other_start, this.value, this_start, len);
        }
    
        /**
         * Copies content of {@code other} into this and set size of this to {@code other}.
         * The size attribute (returned by length()) is updated. If {@code other}
         * is longer than maximum capacity of this, internal buffer is reallocated if enabled
         * (ALLOW_RUNTIME_REALLOCATION), otherwise exception is thrown.
         *
         * @param other Bignat to clone into this object.
         */
        public void clone(BigNat other) {
            // Reallocate array only if current array cannot store the other value and reallocation is enabled by ALLOW_RUNTIME_REALLOCATION
            if (this.max_size < other.length()) {
                // Reallocation necessary
                if (ALLOW_RUNTIME_REALLOCATION) {
                    allocate_storage_array(other.length(), this.allocatorType);
                } else {
                    ISOException.throwIt(ReturnCodes.SW_BIGNAT_REALLOCATIONNOTALLOWED);
                }
            }
    
            // copy value from other into proper place in this (this can be longer than other so rest of bytes wil be filled with 0)
            other.copy_to_buffer(this.value, (short) 0);
            if (this.max_size > other.length()) {
                Util.arrayFillNonAtomic(this.value, other.length(), (short) (this.max_size - other.length()), (byte) 0);
            }
            this.size = other.length();
        }
    
        /**
         * Equality check. Requires that this object and other have the same size or are padded with zeroes.
         * Returns true if all digits (except for leading zeroes) are equal.
         *
         * @param other BigNat to compare
         * @return true if this and other have the same value, false otherwise.
         */
        public boolean same_value(BigNat other) {
            short hashLen;
            byte[] tmpBuffer = rm.ARRAY_A;
            byte[] hashBuffer = rm.ARRAY_B;
    
            // Compare using hash engine
            // The comparison is made with hash of point values instead of directly values.
            // This way, offset of first mismatching byte is not leaked via timing side-channel.
            rm.lock(tmpBuffer);
            rm.lock(hashBuffer);
            if (this.length() == other.length()) {
                // Same length, we can hash directly from BN values
                rm.hashEngine.doFinal(this.value, (short) 0, this.length(), hashBuffer, (short) 0);
                hashLen = rm.hashEngine.doFinal(other.value, (short) 0, other.length(), tmpBuffer, (short) 0);
            } else {
                // Different length of bignats - can be still same if prepended with zeroes 
                // Find the length of longer one and padd other one with starting zeroes
                if (this.length() < other.length()) {
                    this.prepend_zeros(other.length(), tmpBuffer, (short) 0);
                    rm.hashEngine.doFinal(tmpBuffer, (short) 0, other.length(), hashBuffer, (short) 0);
                    hashLen = rm.hashEngine.doFinal(other.value, (short) 0, other.length(), tmpBuffer, (short) 0);
                } else {
                    other.prepend_zeros(this.length(), tmpBuffer, (short) 0);
                    rm.hashEngine.doFinal(tmpBuffer, (short) 0, this.length(), hashBuffer, (short) 0);
                    hashLen = rm.hashEngine.doFinal(this.value, (short) 0, this.length(), tmpBuffer, (short) 0);
                }
            }
    
            boolean result = Util.arrayCompare(hashBuffer, (short) 0, tmpBuffer, (short) 0, hashLen) == 0;
    
            rm.unlock(tmpBuffer);
            rm.unlock(hashBuffer);
    
            return result;
        }
    
    
        /**
        * Addition of big integers x and y stored in byte arrays with specified offset and length.
        * The result is stored into x array argument. 
        * @param x          array with first bignat
        * @param xOffset    start offset in array of {@code x}
        * @param xLength    length of {@code x}
        * @param y          array with second bignat
        * @param yOffset    start offset in array of {@code y}
        * @param yLength    length of {@code y}
        * @return 0x01 if carry of most significant byte occurs, 0x00 otherwise
        */
        public static byte add(byte[] x, short xOffset, short xLength, byte[] y,
                        short yOffset, short yLength) {
            short result = 0;
            short i = (short) (xLength + xOffset - 1);
            short j = (short) (yLength + yOffset - 1);
    
            for (; i >= xOffset && j >= 0; i--, j--) {
                result = (short) (result + (short) (x[i] & digit_mask) + (short) (y[j] & digit_mask));
    
                x[i] = (byte) (result & digit_mask);
                result = (short) ((result >> digit_len) & digit_mask);
            }
            while (result > 0 && i >= xOffset) {
                result = (short) (result + (short) (x[i] & digit_mask));
                x[i] = (byte) (result & digit_mask);
                result = (short) ((result >> digit_len) & digit_mask);
                i--;
            }
    
            // 1. result != 0 => result | -result will have the sign bit set
            // 2. casting magic to overcome the absence of int
            // 3. move the sign bit to the rightmost position
            // 4. discard the sign bit which is present due to the unavoidable casts
            //    and return the value of the rightmost bit
            return (byte) ((byte) (((short)(result | -result) & (short)0xFFFF) >>> 15) & 0x01);
        }
    
        /**
         * Subtracts big integer y from x specified by offset and length.
         * The result is stored into x array argument.
         *
         * @param x       array with first bignat
         * @param xOffset start offset in array of {@code x}
         * @param xLength length of {@code x}
         * @param y       array with second bignat
         * @param yOffset start offset in array of {@code y}
         * @param yLength length of {@code y}
         * @return true if carry of most significant byte occurs, false otherwise
         */
        public static boolean subtract(byte[] x, short xOffset, short xLength, byte[] y,
                                       short yOffset, short yLength) {
            short i = (short) (xLength + xOffset - 1);
            short j = (short) (yLength + yOffset - 1);
            short carry = 0;
            short subtraction_result = 0;
    
            for (; i >= xOffset && j >= yOffset; i--, j--) {
                subtraction_result = (short) ((x[i] & digit_mask) - (y[j] & digit_mask) - carry);
                x[i] = (byte) (subtraction_result & digit_mask);
                carry = (short) (subtraction_result < 0 ? 1 : 0);
            }
            for (; i >= xOffset && carry > 0; i--) {
                if (x[i] != 0) {
                    carry = 0;
                }
                x[i] -= 1;
            }
    
            return carry > 0;
        }
    
        /**
         * Substract provided other bignat from this bignat.
         *
         * @param other bignat to be substracted from this
         */
        public void subtract(BigNat other) {
            this.times_minus(other, (short) 0, (short) 1);
        }
    
        /**
         * Scaled subtraction. Subtracts {@code mult * 2^(}{@link #digit_len}
         * {@code  * shift) * other} from this.
         * <p>
         * That is, shifts {@code mult * other} precisely {@code shift} digits to
         * the left and subtracts that value from this. {@code mult} must be less
         * than {@link #bignat_base}, that is, it must fit into one digit. It is
         * only declared as short here to avoid negative values.
         * <p>
         * {@code mult} has type short.
         * <p>
         * No size constraint. However, an assertion is thrown, if the result would
         * be negative. {@code other} can have more digits than this object, but
         * then sufficiently many leading digits must be zero to avoid the
         * underflow.
         * <p>
         * Used in division.
         *
         * @param other Bignat to subtract from this object
         * @param shift number of digits to shift {@code other} to the left
         * @param mult  of type short, multiple of {@code other} to subtract from this
         *              object. Must be below {@link #bignat_base}.
         */
        public void times_minus(BigNat other, short shift, short mult) {
            short akku = 0;
            short subtraction_result;
            short i = (short) (this.size - 1 - shift);
            short j = (short) (other.size - 1);
            for (; i >= 0 && j >= 0; i--, j--) {
                akku = (short) (akku + (short) (mult * (other.value[j] & digit_mask)));
                subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
    
                value[i] = (byte) (subtraction_result & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
                if (subtraction_result < 0) {
                    akku++;
                }
            }
    
            // deal with carry as long as there are digits left in this
            while (i >= 0 && akku != 0) {
                subtraction_result = (short) ((value[i] & digit_mask) - (akku & digit_mask));
                value[i] = (byte) (subtraction_result & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
                if (subtraction_result < 0) {
                    akku++;
                }
                i--;
            }
        }
    
        /**
         * Quick function for decrement of this BigNat value by 1. Faster than {@code substract(BigNat.one())}
         */
        public void decrement_one() {
            short tmp = 0;
            for (short i = (short) (this.size - 1); i >= 0; i--) {
                tmp = (short) (this.value[i] & 0xff);
                this.value[i] = (byte) (tmp - 1);
                if (tmp != 0) {
                    break; // CTO
                } else {
                    // need to modify also one byte up, continue with cycle
                }
            }
        }
    
        /**
         * Quick function for increment of this bignat value by 1. Faster than
         * {@code add(Bignat.one())}
         */
        public void increment_one() {
            short tmp = 0;
            for (short i = (short) (this.size - 1); i >= 0; i--) {
                tmp = (short) (this.value[i] & 0xff);
                this.value[i] = (byte) (tmp + 1);
                if (tmp < 255) {
                    break; // CTO
                } else {
                    // need to modify also one byte up (carry) , continue with cycle
                }
            }
        }
    
        /**
         * Index of the most significant 1 bit.
         * <p>
         * {@code x} has type short.
         * <p>
         * Utility method, used in division.
         *
         * @param x of type short
         * @return index of the most significant 1 bit in {@code x}, returns
         * {@link #double_digit_len} for {@code x == 0}.
         */
        private static short highest_bit(short x) {
            for (short i = 0; i < double_digit_len; i++) {
                if (x < 0) {
                    return i;
                }
                x <<= 1;
            }
            return double_digit_len;
        }
    
        /**
         * Shift to the left and fill. Takes {@code high} {@code middle} {@code low}
         * as 4 digits, shifts them {@code shift} bits to the left and returns the
         * most significant {@link #double_digit_len} bits.
         * <p>
         * Utility method, used in division.
         *
         * @param high   of type short, most significant {@link #double_digit_len} bits
         * @param middle of type byte, middle {@link #digit_len} bits
         * @param low    of type byte, least significant {@link #digit_len} bits
         * @param shift  amount of left shift
         * @return most significant {@link #double_digit_len} as short
         */
        private static short shift_bits(short high, byte middle, byte low,
                                        short shift) {
            // shift high
            high <<= shift;
    
            // merge middle bits
            byte mask = (byte) (digit_mask << (shift >= digit_len ? 0 : digit_len
                    - shift));
            short bits = (short) ((short) (middle & mask) & digit_mask);
            if (shift > digit_len) {
                bits <<= shift - digit_len;
            } else {
                bits >>>= digit_len - shift;
            }
            high |= bits;
    
            if (shift <= digit_len) {
                return high;
            }
    
            // merge low bits
            mask = (byte) (digit_mask << double_digit_len - shift);
            bits = (short) ((((short) (low & mask) & digit_mask) >> double_digit_len - shift));
            high |= bits;
    
            return high;
        }
    
        /**
         * Scaled comparison. Compares this number with {@code other * 2^(}
         * {@link #digit_len} {@code * shift)}. That is, shifts {@code other}
         * {@code shift} digits to the left and compares then. This bignat and
         * {@code other} will not be modified inside this method.
         * <p>
         * <p>
         * As optimization {@code start} can be greater than zero to skip the first
         * {@code start} digits in the comparison. These first digits must be zero
         * then, otherwise an assertion is thrown. (So the optimization takes only
         * effect when <a
         * href="../../../overview-summary.html#NO_CARD_ASSERT">NO_CARD_ASSERT</a>
         * is defined.)
         *
         * @param other Bignat to compare to
         * @param shift left shift of other before the comparison
         * @param start digits to skip at the beginning
         * @return true if this number is strictly less than the shifted
         * {@code other}, false otherwise.
         */
        public boolean shift_lesser(BigNat other, short shift, short start) {
            short j;
    
            j = (short) (other.size + shift - this.size + start);
            short this_short, other_short;
            for (short i = start; i < this.size; i++, j++) {
                this_short = (short) (this.value[i] & digit_mask);
                if (j >= 0 && j < other.size) {
                    other_short = (short) (other.value[j] & digit_mask);
                } else {
                    other_short = 0;
                }
                if (this_short < other_short) {
                    return true; // CTO
                }
                if (this_short > other_short) {
                    return false;
                }
            }
            return false;
        }
    
        /**
         * Compares this and other BigNat.
         *
         * @param other other value to compare with
         * @return true if this BigNat is smaller, false if bigger or equal
         */
        public boolean smaller(BigNat other) {
            short index_this = 0;
            for (short i = 0; i < this.length(); i++) {
                if (this.value[i] != 0x00) {
                    index_this = i;
                }
            }
    
            short index_other = 0;
            for (short i = 0; i < other.length(); i++) {
                if (other.value[i] != 0x00) {
                    index_other = i;
                }
            }
    
            if ((short) (this.length() - index_this) < (short) (other.length() - index_other)) {
                return true; // CTO
            }
            short i = 0;
            while (i < this.length() && i < other.length()) {
                if (((short) (this.value[i] & digit_mask)) < ((short) (other.value[i] & digit_mask))) {
                    return true; // CTO
                }
                i = (short) (1 + i);
            }
    
            return false;
        }
    
    
        /**
         * Comparison of this and other.
         *
         * @param other Bignat to compare with
         * @return true if this number is strictly lesser than {@code other}, false
         * otherwise.
         */
        public boolean lesser(BigNat other) {
            return this.shift_lesser(other, (short) 0, (short) 0);
        }
    
        /**
         * Test equality with zero.
         *
         * @return true if this bignat equals zero.
         */
        public boolean is_zero() {
            for (short i = 0; i < size; i++) {
                if (value[i] != 0) {
                    return false; // CTO
                }
            }
            return true;
        }
    
        /**
         * Check if stored bignat is odd.
         *
         * @return true if odd, false if even
         */
        public boolean is_odd() {
            if ((value[(short) (this.size - 1)] & 1) == 0) {
                return false; // CTO
            }
            return true;
        }
    
        /**
         * Remainder and Quotient. Divide this number by {@code divisor} and store
         * the remainder in this. If {@code quotient} is non-null store the quotient
         * there.
         * <p>
         * There are no direct size constraints, but if {@code quotient} is
         * non-null, it must be big enough for the quotient, otherwise an assertion
         * is thrown.
         * <p>
         * Uses schoolbook division inside and has O^2 complexity in the difference
         * of significant digits of the divident (in this number) and the divisor.
         * For numbers of equal size complexity is linear.
         *
         * @param divisor  must be non-zero
         * @param quotient gets the quotient if non-null
         */
        public void remainder_divide(BigNat divisor, BigNat quotient) {
            // There are some size requirements, namely that quotient must
            // be big enough. However, this depends on the value of the
            // divisor and is therefore not stated here.
    
            // zero-initialize the quotient, because we are only adding to it below
            if (quotient != null) {
                quotient.zero();
            }
    
            // divisor_index is the first nonzero digit (short) in the divisor
            short divisor_index = 0;
            while (divisor.value[divisor_index] == 0) {
                divisor_index++;
            }
    
            // The size of this might be different from divisor. Therefore,
            // for the first subtraction round we have to shift the divisor
            // divisor_shift = this.size - divisor.size + divisor_index
            // digits to the left. If this amount is negative, then
            // this is already smaller then divisor and we are done.
            // Below we do divisor_shift + 1 subtraction rounds. As an
            // additional loop index we also count the rounds (from
            // zero upwards) in division_round. This gives access to the
            // first remaining divident digits.
            short divisor_shift = (short) (this.size - divisor.size + divisor_index);
            short division_round = 0;
    
            // We could express now a size constraint, namely that
            // divisor_shift + 1 <= quotient.size
            // However, in the proof protocol we divide x / v, where
            // x has 2*n digits when v has n digits. There the above size
            // constraint is violated, the division is however valid, because
            // it will always hold that x < v * (v - 1) and therefore the
            // quotient will always fit into n digits.
            // System.out.format("XX this size %d div ind %d div shift %d " +
            // "quo size %d\n" +
            // "%s / %s\n",
            // this.size,
            // divisor_index,
            // divisor_shift,
            // quotient != null ? quotient.size : -1,
            // this.to_hex_string(),
            // divisor.to_hex_string());
            // The first digits of the divisor are needed in every
            // subtraction round.
            short first_divisor_digit = (short) (divisor.value[divisor_index] & digit_mask);
            short divisor_bit_shift = (short) (highest_bit((short) (first_divisor_digit + 1)) - 1);
            byte second_divisor_digit = divisor_index < (short) (divisor.size - 1) ? divisor.value[(short) (divisor_index + 1)]
                    : 0;
            byte third_divisor_digit = divisor_index < (short) (divisor.size - 2) ? divisor.value[(short) (divisor_index + 2)]
                    : 0;
    
            // The following variables are used inside the loop only.
            // Declared here as optimization.
            // divident_digits and divisor_digit hold the first one or two
            // digits. Needed to compute the multiple of the divisor to
            // subtract from this.
            short divident_digits, divisor_digit;
    
            // To increase precisision the first digits are shifted to the
            // left or right a bit. The following variables compute the shift.
            short divident_bit_shift, bit_shift;
    
            // Declaration of the multiple, with which the divident is
            // multiplied in each round and the quotient_digit. Both are
            // a single digit, but declared as a double digit to avoid the
            // trouble with negative numbers. If quotient != null multiple is
            // added to the quotient. This addition is done with quotient_digit.
            short multiple, quotient_digit;
            short numLoops = 0;
            short numLoops2 = 0;
            while (divisor_shift >= 0) {
                numLoops++; // CTO number of outer loops is constant (for given length of divisor)
                // Keep subtracting from this until
                // divisor * 2^(8 * divisor_shift) is bigger than this.
                while (!shift_lesser(divisor, divisor_shift,
                        (short) (division_round > 0 ? division_round - 1 : 0))) {
                    numLoops2++; // BUGBUG: CTO - number of these loops fluctuates heavily => strong impact on operation time 
                    // this is bigger or equal than the shifted divisor.
                    // Need to subtract some multiple of divisor from this.
                    // Make a conservative estimation of the multiple to subtract.
                    // We estimate a lower bound to avoid underflow, and continue
                    // to subtract until the remainder in this gets smaller than
                    // the shifted divisor.
                    // For the estimation get first the two relevant digits
                    // from this and the first relevant digit from divisor.
                    divident_digits = division_round == 0 ? 0
                            : (short) ((short) (value[(short) (division_round - 1)]) << digit_len);
                    divident_digits |= (short) (value[division_round] & digit_mask);
    
                    // The multiple to subtract from this is
                    // divident_digits / divisor_digit, but there are two
                    // complications:
                    // 1. divident_digits might be negative,
                    // 2. both might be very small, in which case the estimated
                    // multiple is very inaccurate.
                    if (divident_digits < 0) {
                        // case 1: shift both one bit to the right
                        // In standard java (ie. in the test frame) the operation
                        // for >>= and >>>= seems to be done in integers,
                        // even if the left hand side is a short. Therefore,
                        // for a short left hand side there is no difference
                        // between >>= and >>>= !!!
                        // Do it the complicated way then.
                        divident_digits = (short) ((divident_digits >>> 1) & positive_double_digit_mask);
                        divisor_digit = (short) ((first_divisor_digit >>> 1) & positive_double_digit_mask);
                    } else {
                        // To avoid case 2 shift both to the left
                        // and add relevant bits.
                        divident_bit_shift = (short) (highest_bit(divident_digits) - 1);
                        // Below we add one to divisor_digit to avoid underflow.
                        // Take therefore the highest bit of divisor_digit + 1
                        // to avoid running into the negatives.
                        bit_shift = divident_bit_shift <= divisor_bit_shift ? divident_bit_shift
                                : divisor_bit_shift;
    
                        divident_digits = shift_bits(
                                divident_digits,
                                division_round < (short) (this.size - 1) ? value[(short) (division_round + 1)]
                                        : 0,
                                division_round < (short) (this.size - 2) ? value[(short) (division_round + 2)]
                                        : 0, bit_shift);
                        divisor_digit = shift_bits(first_divisor_digit,
                                second_divisor_digit, third_divisor_digit,
                                bit_shift);
    
                    }
    
                    // add one to divisor to avoid underflow
                    multiple = (short) (divident_digits / (short) (divisor_digit + 1));
    
                    // Our strategy to avoid underflow might yield multiple == 0.
                    // We know however, that divident >= divisor, therefore make
                    // sure multiple is at least 1.
                    if (multiple < 1) {
                        multiple = 1;
                    }
    
                    times_minus(divisor, divisor_shift, multiple);
    
                    // build quotient if desired
                    if (quotient != null) {
                        // Express the size constraint only here. The check is
                        // essential only in the first round, because
                        // divisor_shift decreases. divisor_shift must be
                        // strictly lesser than quotient.size, otherwise
                        // quotient is not big enough. Note that the initially
                        // computed divisor_shift might be bigger, this
                        // is OK, as long as we don't reach this point.
    
                        quotient_digit = (short) ((quotient.value[(short) (quotient.size - 1 - divisor_shift)] & digit_mask) + multiple);
                        quotient.value[(short) (quotient.size - 1 - divisor_shift)] = (byte) (quotient_digit);
                    }
                }
    
                // treat loop indices
                division_round++;
                divisor_shift--;
            }
        }
    
    
        /**
         * Add short value to this bignat
         *
         * @param other short value to add
         */
        public void add(short other) {
            Util.setShort(rm.RAM_WORD, (short) 0, other); // serialize other into array
            this.add_carry(rm.RAM_WORD, (short) 0, (short) 2); // add as array
        }
    
        /**
         * Addition with carry report. Adds other to this number. If this is too
         * small for the result (i.e., an overflow occurs) the method returns true.
         * Further, the result in {@code this} will then be the correct result of an
         * addition modulo the first number that does not fit into {@code this} (
         * {@code 2^(}{@link #digit_len}{@code * }{@link #size this.size}{@code )}),
         * i.e., only one leading 1 bit is missing. If there is no overflow the
         * method will return false.
         * <p>
         * <p>
         * It would be more natural to report the overflow with an
         * {@link javacard.framework.UserException}, however its
         * {@link javacard.framework.UserException#throwIt throwIt} method dies with
         * a null pointer exception when it runs in a host test frame...
         * <p>
         * <p>
         * Asserts that the size of other is not greater than the size of this.
         *
         * @param other       Bignat to add
         * @param otherOffset start offset within other buffer
         * @param otherLen    length of other
         * @return true if carry occurs, false otherwise
         */
        public boolean add_carry(byte[] other, short otherOffset, short otherLen) {
            short akku = 0;
            short j = (short) (this.size - 1);
            for (short i = (short) (otherLen - 1); i >= 0 && j >= 0; i--, j--) {
                akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (other[(short) (i + otherOffset)] & digit_mask));
    
                this.value[j] = (byte) (akku & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
            }
            // add carry at position j
            while (akku > 0 && j >= 0) {
                akku = (short) (akku + (short) (this.value[j] & digit_mask));
                this.value[j] = (byte) (akku & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
                j--;
            }
    
            return akku != 0;
        }
    
        /**
         * Add with carry. See {@code add_cary()} for full description
         *
         * @param other value to be added
         * @return true if carry happens, false otherwise
         */
        public boolean add_carry(BigNat other) {
            return add_carry(other.value, (short) 0, other.size);
        }
    
    
        /**
         * Addition. Adds other to this number.
         * <p>
         * Same as {@link #times_add times_add}{@code (other, 1)} but without the
         * multiplication overhead.
         * <p>
         * Asserts that the size of other is not greater than the size of this.
         *
         * @param other Bignat to add
         */
        public void add(BigNat other) {
            add_carry(other);
        }
    
        /**
         * Add other bignat to this bignat modulo {@code modulo} value.
         *
         * @param other  value to add
         * @param modulo value of modulo to compute
         */
        public void mod_add(BigNat other, BigNat modulo) {
            BigNat tmp = rm.BN_A;
    
            short tmp_size = this.size;
            if (tmp_size < other.size) {
                tmp_size = other.size;
            }
            tmp_size++;
            tmp.lock();
            tmp.set_size(tmp_size);
            tmp.zero();
            tmp.copy(this);
            tmp.add(other);
            tmp.mod(modulo);
            tmp.shrink();
            this.clone(tmp);
            tmp.unlock();
        }
    
        /**
         * Subtract other BigNat from this BigNat modulo {@code modulo} value.
         *
         * @param other  value to substract
         * @param modulo value of modulo to apply
         */
        public void mod_sub(BigNat other, BigNat modulo) {
            BigNat tmp = rm.BN_B;
            BigNat tmpOther = rm.BN_C;
            BigNat tmpThis = rm.BN_A;
    
            if (other.lesser(this)) { // CTO
                this.subtract(other);
                this.mod(modulo);
            } else { //other>this (mod-other+this)
                tmpOther.lock();
                tmpOther.clone(other);
                tmpOther.mod(modulo);
    
                //fnc_mod_sub_tmpThis = new Bignat(this.length());
                tmpThis.lock();
                tmpThis.clone(this);
                tmpThis.mod(modulo);
    
                tmp.lock();
                tmp.clone(modulo);
                tmp.subtract(tmpOther);
                tmpOther.unlock();
                tmp.add(tmpThis); //this will never overflow as "other" is larger than "this"
                tmpThis.unlock();
                tmp.mod(modulo);
                tmp.shrink();
                this.clone(tmp);
                tmp.unlock();
            }
        }
    
    
        /**
         * Scaled addition. Add {@code mult * other} to this number. {@code mult}
         * must be below {@link #bignat_base}, that is, it must fit into one digit.
         * It is only declared as a short here to avoid negative numbers.
         * <p>
         * Asserts (overly restrictive) that this and other have the same size.
         * <p>
         * Same as {@link #times_add_shift times_add_shift}{@code (other, 0, mult)}
         * but without the shift overhead.
         * <p>
         * Used in multiplication.
         *
         * @param other Bignat to add
         * @param mult  of short, factor to multiply {@code other} with before
         *              addition. Must be less than {@link #bignat_base}.
         */
        public void times_add(BigNat other, short mult) {
            short akku = 0;
            for (short i = (short) (size - 1); i >= 0; i--) {
                akku = (short) (akku + (short) (this.value[i] & digit_mask) + (short) (mult * (other.value[i] & digit_mask)));
                this.value[i] = (byte) (akku & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
            }
        }
    
        /**
         * Scaled addition. Adds {@code mult * other * 2^(}{@link #digit_len}
         * {@code * shift)} to this. That is, shifts other {@code shift} digits to
         * the left, multiplies it with {@code mult} and adds then.
         * <p>
         * {@code mult} must be less than {@link #bignat_base}, that is, it must fit
         * into one digit. It is only declared as a short here to avoid negative
         * numbers.
         * <p>
         * Asserts that the size of this is greater than or equal to
         * {@code other.size + shift + 1}.
         *
         * @param x     Bignat to add
         * @param mult  of short, factor to multiply {@code other} with before
         *              addition. Must be less than {@link #bignat_base}.
         * @param shift number of digits to shift {@code other} to the left, before
         *              addition.
         */
        public void times_add_shift(BigNat x, short shift, short mult) {
            short akku = 0;
            short j = (short) (this.size - 1 - shift);
            for (short i = (short) (x.size - 1); i >= 0; i--, j--) {
                akku = (short) (akku + (short) (this.value[j] & digit_mask) + (short) (mult * (x.value[i] & digit_mask)));
    
                this.value[j] = (byte) (akku & digit_mask);
                akku = (short) ((akku >> digit_len) & digit_mask);
            }
            // add carry at position j
            akku = (short) (akku + (short) (this.value[j] & digit_mask));
            this.value[j] = (byte) (akku & digit_mask);
            // BUGUG: assert no overflow
        }
    
        /**
         * Division of this bignat by provided other bignat.
         *
         * @param other value of divisor
         */
        public void divide(BigNat other) {
            BigNat tmp = rm.BN_E;
    
            tmp.lock();
            tmp.clone(this);
            tmp.remainder_divide(other, this);
            this.clone(tmp);
            tmp.unlock();
        }
    
        /**
         * Greatest common divisor of this BigNat with other BigNat. Result is
         * stored into this.
         *
         * @param other value of other BigNat
         */
        public void gcd(BigNat other) {
            BigNat tmp = rm.BN_A;
            BigNat tmpOther = rm.BN_B;
    
            tmp.lock();
            tmpOther.lock();
    
            tmpOther.clone(other);
    
            // TODO: optimise?
            while (!other.is_zero()) {
                tmp.clone(tmpOther);
                this.mod(tmpOther);
                tmpOther.clone(this);
                this.clone(tmp);
            }
    
            tmp.unlock();
            tmpOther.unlock();
        }
    
        /**
         * Decides whether the arguments are coprime or not.
         *
         * @param a BigNat value
         * @param b BigNat value
         * @return true if coprime, false otherwise
         */
        public boolean is_coprime(BigNat a, BigNat b) {
            BigNat tmp = rm.BN_C; // is_coprime calls gcd internally
    
            tmp.lock();
            tmp.clone(a);
    
            tmp.gcd(b);
            return tmp.same_value(ResourceManager.ONE);
        }
    
        /**
         * Computes base^exp and stores result into this bignat
         *
         * @param base value of base
         * @param exp  value of exponent
         */
        public void exponentiation(BigNat base, BigNat exp) {
            BigNat tmp = rm.BN_A;
            BigNat i = rm.BN_B;
    
            this.one();
            i.lock();
            i.set_size(exp.length());
            i.zero();
            tmp.lock();
            tmp.set_size((short) (2 * this.length()));
            for (; i.lesser(exp); i.increment_one()) {
                tmp.mult(this, base);
                this.copy(tmp);
            }
            i.unlock();
            tmp.unlock();
        }
    
        /**
         * Multiplication. Automatically selects fastest available algorithm.
         * Stores {@code x * y} in this. To ensure this is big
         * enough for the result it is asserted that the size of this is greater
         * than or equal to the sum of the sizes of {@code x} and {@code y}.
         *
         * @param x first factor
         * @param y second factor
         */
        public void mult(BigNat x, BigNat y) {
            if (!OperationSupport.getInstance().RSA_MULT_TRICK || x.length() < FAST_MULT_VIA_RSA_THRESHOLD_LENGTH) {
                // If simulator or not supported, use slow multiplication
                // Use slow multiplication also when numbers are small => faster to do in software
                mult_schoolbook(x, y);
            } else {
                mult_rsa_trick(x, y, null, null);
            }
        }
    
        /**
         * Slow schoolbook algorithm for multiplication
         *
         * @param x first number to multiply
         * @param y second number to multiply
         */
        public void mult_schoolbook(BigNat x, BigNat y) {
            this.zero(); // important to keep, used in exponentiation()
            for (short i = (short) (y.size - 1); i >= 0; i--) {
                this.times_add_shift(x, (short) (y.size - 1 - i), (short) (y.value[i] & digit_mask));
            }
        }
    
        /**
         * Performs multiplication of two bignats x and y and stores result into this.
         * RSA engine is used to speedup operation for large values.
         * Idea of speedup:
         * We need to mutiply x.y where both x and y are 32B
         * (x + y)^2 == x^2 + y^2 + 2xy
         * Fast RSA engine is available (a^b mod n)
         * n can be set bigger than 64B => a^b mod n == a^b
         * [(x + y)^2 mod n] - [x^2 mod n] - [y^2 mod n] => 2xy where [] means single RSA operation
         * 2xy / 2 => result of mult(x,y)
         * Note: if multiplication is used with either x or y argument same repeatedly,
         * [x^2 mod n] or [y^2 mod n] can be precomputed and passed as arguments x_pow_2 or y_pow_2
         *
         * @param x       first value to multiply
         * @param y       second value to multiply
         * @param x_pow_2 if not null, array with precomputed value x^2 is expected
         * @param y_pow_2 if not null, array with precomputed value y^2 is expected
         */
        public void mult_rsa_trick(BigNat x, BigNat y, byte[] x_pow_2, byte[] y_pow_2) {
            short xOffset;
            short yOffset;
    
            byte[] resultBuffer1 = rm.ARRAY_A;
            byte[] resultBuffer2 = rm.ARRAY_B;
    
            rm.lock(resultBuffer1);
    
            // x+y
            Util.arrayFillNonAtomic(resultBuffer1, (short) 0, (short) resultBuffer1.length, (byte) 0);
            // We must copy bigger number first
            if (x.size > y.size) {
                // Copy x to the end of mult_resultArray
                xOffset = (short) (resultBuffer1.length - x.length());
                Util.arrayCopyNonAtomic(x.value, (short) 0, resultBuffer1, xOffset, x.length());
    
                // modified for CT
                byte carry = add(resultBuffer1, xOffset, x.size, y.value, (short) 0, y.size);
                xOffset--;
                resultBuffer1[xOffset] = carry; // add carry if occured
            } else {
                // Copy x to the end of mult_resultArray
                yOffset = (short) (resultBuffer1.length - y.length());
                Util.arrayCopyNonAtomic(y.value, (short) 0, resultBuffer1, yOffset, y.length());
    
                // modified for CT
                byte carry = add(resultBuffer1, yOffset, y.size, x.value, (short) 0, x.size);
                yOffset--;
                resultBuffer1[yOffset] = carry; // add carry if occured
            }
    
            // ((x+y)^2)
            rm.multCiph.doFinal(resultBuffer1, (byte) 0, (short) resultBuffer1.length, resultBuffer1, (short) 0);
    
            // x^2
            rm.lock(resultBuffer2);
            if (x_pow_2 == null) {
                // x^2 is not precomputed
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                xOffset = (short) (resultBuffer2.length - x.length());
                Util.arrayCopyNonAtomic(x.value, (short) 0, resultBuffer2, xOffset, x.length());
                rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
            } else {
                // x^2 is precomputed
                if ((short) x_pow_2.length != (short) resultBuffer2.length) {
                    Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                    xOffset = (short) ((short) resultBuffer2.length - (short) x_pow_2.length);
                } else {
                    xOffset = 0;
                }
                Util.arrayCopyNonAtomic(x_pow_2, (short) 0, resultBuffer2, xOffset, (short) x_pow_2.length);
            }
            // ((x+y)^2) - x^2
            subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);
    
            // y^2
            if (y_pow_2 == null) {
                // y^2 is not precomputed
                Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                yOffset = (short) (resultBuffer2.length - y.length());
                Util.arrayCopyNonAtomic(y.value, (short) 0, resultBuffer2, yOffset, y.length());
                rm.multCiph.doFinal(resultBuffer2, (byte) 0, (short) resultBuffer2.length, resultBuffer2, (short) 0);
            } else {
                // y^2 is precomputed
                if ((short) y_pow_2.length != (short) resultBuffer2.length) {
                    Util.arrayFillNonAtomic(resultBuffer2, (short) 0, (short) resultBuffer2.length, (byte) 0);
                    yOffset = (short) ((short) resultBuffer2.length - (short) y_pow_2.length);
                } else {
                    yOffset = 0;
                }
                Util.arrayCopyNonAtomic(y_pow_2, (short) 0, resultBuffer2, yOffset, (short) y_pow_2.length);
            }
    
    
            // {(x+y)^2) - x^2} - y^2
            subtract(resultBuffer1, (short) 0, (short) resultBuffer1.length, resultBuffer2, (short) 0, (short) resultBuffer2.length);
    
            // we now have 2xy in mult_resultArray, divide it by 2 => shift by one bit and fill back into this
            short multOffset = (short) ((short) resultBuffer1.length - 1);
            short res = 0;
            short res2 = 0;
            // this.length() must be different from multOffset, set proper ending condition
            short stopOffset = 0;
            if (this.length() > multOffset) {
                stopOffset = (short) (this.length() - multOffset); // only part of this.value will be filled
            } else {
                stopOffset = 0; // whole this.value will be filled
            }
            if (stopOffset > 0) {
                Util.arrayFillNonAtomic(this.value, (short) 0, stopOffset, (byte) 0);
            }
            for (short i = (short) (this.length() - 1); i >= stopOffset; i--) {
                res = (short) (resultBuffer1[multOffset] & 0xff);
                res = (short) (res >> 1);
                res2 = (short) (resultBuffer1[(short) (multOffset - 1)] & 0xff);
                res2 = (short) (res2 << 7);
                this.value[i] = (byte) (short) (res | res2);
                multOffset--;
            }
            rm.unlock(resultBuffer1);
            rm.unlock(resultBuffer2);
        }
    
        /**
         * Multiplication of bignats x and y computed by modulo {@code modulo}.
         * The result is stored to this.
         *
         * @param x      first value to multiply
         * @param y      second value to multiply
         * @param modulo value of modulo
         */
        public void mod_mult(BigNat x, BigNat y, BigNat modulo) {
            BigNat tmp = rm.BN_E; // mod_mult is called from sqrt_FP => requires helper_BN_E not being locked when mod_mult is called
    
            tmp.lock();
            tmp.resize_to_max(false);
            // Perform fast multiplication using RSA trick
            tmp.mult(x, y);
            // Compute modulo 
            tmp.mod(modulo);
            tmp.shrink();
            this.clone(tmp);
            tmp.unlock();
        }
        // Potential speedup for  modular multiplication
        // Binomial theorem: (op1 + op2)^2 - (op1 - op2)^2 = 4 * op1 * op2 mod (mod)
    
    
        /**
         * One digit left shift.
         * <p>
         * Asserts that the first digit is zero.
         */
        public void shift_left() {
            // NOTE: assumes that overlapping src and dest arrays are properly handled by Util.arrayCopyNonAtomic
            Util.arrayCopyNonAtomic(this.value, (short) 1, this.value, (short) 0, (short) (size - 1));
            value[(short) (size - 1)] = 0;
        }
    
        /**
         * Optimized division by value two
         */
        private void divide_by_2() {
            short tmp = 0;
            short tmp2 = 0;
            short carry = 0;
            for (short i = 0; i < this.size; i++) {
                tmp = (short) (this.value[i] & 0xff);
                tmp2 = tmp;
                tmp >>= 1; // shift by 1 => divide by 2
                this.value[i] = (byte) (tmp | carry);
                carry = (short) (tmp2 & 0x01); // save lowest bit
                carry <<= 7; // shifted to highest position
            }
        }
    
        /**
         * Inefficient modular multiplication.
         * <p>
         * This bignat is assigned to {@code x * y} modulo {@code mod}. Inefficient,
         * because it computes the modules with {@link #remainder_divide
         * remainder_divide} in each multiplication round. To avoid overflow the
         * first two digits of {@code x} and {@code mod} must be zero (which plays
         * nicely with the requirements for montgomery multiplication, see
         * {@link #montgomery_mult montgomery_mult}).
         * <p>
         * Asserts that {@code x} and {@code mod} have the same size. Argument
         * {@code y} can be arbitrary in size.
         * <p>
         * Included here to make it possible to compute the squared <a
         * href="package-summary.html#montgomery_factor">montgomery factor</a>,
         * which is needed to montgomerize numbers before montgomery multiplication.
         * Until now this has never been used, because the montgomery factors are
         * computed on the host and then installed on the card. Or numbers are
         * montgomerized on the host already.
         *
         * @param x   first factor, first two digits must be zero
         * @param y   second factor
         * @param mod modulus, first two digits must be zero
         */
        public void mod_mult_inefficient(BigNat x, BigNat y, BigNat mod) {
            BigNat tmp = rm.BN_A;
            BigNat tmpMod = rm.BN_B;
            BigNat tmpX = rm.BN_C;
    
            short len = 0;
            if (x.length() >= mod.length()) {
                len = x.length();
            } else {
                len = mod.length();
            }
    
            short magicAdd = 2;
            tmpX.lock();
            tmpX.set_size((short) (len + magicAdd));
            tmpX.copy(x);
    
            tmpMod.lock();
            tmpMod.set_size((short) (len + magicAdd));
            tmpMod.copy(mod);
    
            tmp.lock();
            tmp.set_size((short) (this.length() + magicAdd));
            tmp.zero();
            for (short i = 0; i < y.size; i++) {
                tmp.shift_left();
                tmp.times_add(tmpX, (short) (y.value[i] & digit_mask));
                tmp.remainder_divide(tmpMod, null);
            }
            tmpX.unlock();
            tmpMod.unlock();
    
            tmp.shrink();
            this.clone(tmp);
            tmp.unlock();
        }
    
    
        //
    
        /**
         * Computes square root of provided bignat which MUST be prime using Tonelli
         * Shanks Algorithm. The result (one of the two roots) is stored to this.
         *
         * @param p value to compute square root from
         */
        public void sqrt_FP(BigNat p) {
            BigNat s = rm.BN_A;
            BigNat exp = rm.BN_A;
            BigNat p1 = rm.BN_B;
            BigNat q = rm.BN_C;
            BigNat tmp = rm.BN_D;
            BigNat z = rm.BN_E;
    
            // 1. By factoring out powers of 2, find Q and S such that p-1=Q2^S p-1=Q*2^S and Q is odd
            p1.lock();
            p1.clone(p);
            p1.decrement_one();
    
            // Compute Q
            q.lock();
            q.clone(p1);
            q.divide_by_2(); // Q /= 2
    
            //Compute S
            s.lock();
            s.set_size(p.length());
            s.zero();
            tmp.lock();
            tmp.set_size(p.length());
            tmp.zero();
    
            while (!tmp.same_value(q)) {
                s.increment_one();
                tmp.mod_mult(s, q, p);
            }
            tmp.unlock();
            s.unlock();
    
            // 2. Find the first quadratic non-residue z by brute-force search
            exp.lock();
            exp.clone(p1);
            exp.divide_by_2();
    
    
            z.lock();
            z.set_size(p.length());
            z.one();
            tmp.lock();
            tmp.zero();
            tmp.copy(ResourceManager.ONE);
    
            while (!tmp.same_value(p1)) {
                z.increment_one();
                tmp.copy(z);
                tmp.mod_exp(exp, p);
            }
            p1.unlock();
            tmp.unlock();
            z.unlock();
            exp.copy(q);
            q.unlock();
            exp.increment_one();
            exp.divide_by_2();
    
            this.mod(p);
            this.mod_exp(exp, p);
            exp.unlock();
        }
    
    
        /**
         * Computes and stores modulo of this bignat.
         *
         * @param modulo value of modulo
         */
        public void mod(BigNat modulo) {
            this.remainder_divide(modulo, null);
            // NOTE: attempt made to utilize crypto co-processor in pow2Mod_RSATrick_worksOnlyAbout30pp, but doesn't work for all inputs 
        }
    
    
        /**
         * Computes inversion of this bignat taken modulo {@code modulo}.
         * The result is stored into this.
         *
         * @param modulo value of modulo
         */
        public void mod_inv(BigNat modulo) {
            BigNat tmp = rm.BN_B;
            tmp.lock();
            tmp.clone(modulo);
            tmp.decrement_one();
            tmp.decrement_one();
    
            mod_exp(tmp, modulo);
            tmp.unlock();
        }
    
        /**
         * Computes {@code res := this ** exponent mod modulo} and store results into this.
         * Uses RSA engine to quickly compute this^exponent % modulo
         *
         * @param exponent value of exponent
         * @param modulo   value of modulo
         */
        public void mod_exp(BigNat exponent, BigNat modulo) {
            if (!OperationSupport.getInstance().RSA_MOD_EXP)
                ISOException.throwIt(ReturnCodes.SW_OPERATION_NOT_SUPPORTED);
    
            BigNat tmpMod = rm.BN_F;  // mod_exp is called from sqrt_FP => requires helper_BN_F not being locked when mod_exp is called
            byte[] tmpBuffer = rm.ARRAY_A;
            short tmpSize = (short) (rm.MODULO_RSA_ENGINE_MAX_LENGTH_BITS / 8);
            short modLength;
    
            tmpMod.lock();
            tmpMod.set_size(tmpSize);
    
            // Verify if pre-allocated engine match the required values
            if (rm.expPK.getSize() < (short) (modulo.length() * 8) || rm.expPK.getSize() < (short) (this.length() * 8)) {
                ISOException.throwIt(ReturnCodes.SW_BIGNAT_MODULOTOOLARGE);
            }
            if (OperationSupport.getInstance().RSA_KEY_REFRESH) {
                // Simulator fails when reusing the original object
                rm.expPK = (RSAPrivateKey) KeyBuilder.buildKey(javacard.security.KeyBuilder.TYPE_RSA_PRIVATE, rm.MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
            }
            rm.expPK.setExponent(exponent.as_byte_array(), (short) 0, exponent.length());
            rm.lock(tmpBuffer);
            if (OperationSupport.getInstance().RSA_RESIZE_MODULUS) {
                modulo.prepend_zeros(tmpSize, tmpBuffer, (short) 0);
                rm.expPK.setModulus(tmpBuffer, (short) 0, tmpSize);
                modLength = tmpSize;
            } else {
                rm.expPK.setModulus(modulo.as_byte_array(), (short) 0, modulo.length());
                modLength = modulo.length();
            }
            rm.expCiph.init(rm.expPK, Cipher.MODE_DECRYPT);
            short len;
            if (OperationSupport.getInstance().RSA_RESIZE_BASE) {
                this.prepend_zeros(modLength, tmpBuffer, (short) 0);
                len = rm.expCiph.doFinal(tmpBuffer, (short) 0, modLength, tmpMod.value, (short) 0);
            } else {
                len = rm.expCiph.doFinal(this.as_byte_array(), (short) 0, this.length(), tmpMod.value, (short) 0);
            }
            rm.unlock(tmpBuffer);
    
            if (OperationSupport.getInstance().RSA_PREPEND_ZEROS) {
                // Decrypted length can be either tmp_size or less because of leading zeroes consumed by simulator engine implementation
                // Move obtained value into proper position with zeroes prepended
                if (len != tmpSize) {
                    rm.lock(tmpBuffer);
                    Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) tmpBuffer.length, (byte) 0);
                    Util.arrayCopyNonAtomic(tmpMod.value, (short) 0, tmpBuffer, (short) (tmpSize - len), len);
                    Util.arrayCopyNonAtomic(tmpBuffer, (short) 0, tmpMod.value, (short) 0, tmpSize);
                    rm.unlock(tmpBuffer);
                }
            } else {
                // real cards should keep whole length of block, just check
                if (len != tmpSize) {
                    ISOException.throwIt(ReturnCodes.SW_ECPOINT_UNEXPECTED_KA_LEN);
                }
            }
            tmpMod.mod(modulo);
            tmpMod.shrink();
            this.clone(tmpMod);
            tmpMod.unlock();
        }
    
    
        public void mod_exp2(BigNat modulo) {
            mod_exp(ResourceManager.TWO, modulo);
            //this.pow2Mod_RSATrick(modulo);
    /*        
            short tmp_size = (short) (occ.bnHelper.MOD_RSA_LENGTH / 8);
            
            // Idea: a = this with prepended zeroes, b = this with appended zeroes, modulo with appended zeroes
            // Compute mult_RSATrick
            this.prependzeros(tmp_size, occ.bnHelper.helper_BN_A.as_byte_array(), (short) 0);
            occ.bnHelper.helper_BN_A.setSize(tmp_size);
            this.appendzeros(tmp_size, occ.bnHelper.helper_BN_B.as_byte_array(), (short) 0);
            occ.bnHelper.helper_BN_B.setSize(tmp_size);
    
            mult_RSATrick(occ.bnHelper.helper_BN_A, occ.bnHelper.helper_BN_B);
            
            // We will use prepared engine with exponent=2 and very large modulus (instead of provided modulus)
            // The reason is to avoid need for setting custom modulus and re-init RSA engine
            // Mod operation is computed later 
            occ.bnHelper.modPublicKey.setExponent(occ.bnHelper.CONST_TWO, (short) 0, (short) 1);
            occ.locker.lock(occ.bnHelper.fastResizeArray);
            modulo.appendzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            // NOTE: ideally, we would just set RSA engine modulus to our modulo. But smallest RSA key is 512 bit while 
            // our values are commonly smaller (e.g., 32B for 256b ECC). Prepending leading zeroes will cause 0xf105 (CryptoException.InvalidUse)
            //modulo.prependzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.bnHelper.modPublicKey.setModulus(occ.bnHelper.fastResizeArray, (short) 0, tmp_size);
            occ.bnHelper.modCipher.init(occ.bnHelper.modPublicKey, Cipher.MODE_DECRYPT);
            this.prependzeros(tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.bnHelper.modCipher.doFinal(occ.bnHelper.fastResizeArray, (byte) 0, tmp_size, occ.bnHelper.fastResizeArray, (short) 0);
            occ.locker.unlock(occ.bnHelper.fastResizeArray);
    
            // We used RSA engine with large modulo => some leading values will be zero (|this^2| <= 2*|this|)
            short startOffset = 0; // Find first nonzero value in resulting buffer
            while (occ.bnHelper.fastResizeArray[startOffset] == 0) {
                startOffset++;
            }
            short len = (short) (tmp_size - startOffset);
            this.setSize(len);
            this.from_byte_array(len, (short) 0, occ.bnHelper.fastResizeArray, startOffset);
            occ.locker.unlock(occ.bnHelper.fastResizeArray);
    */
        }
    
        /**
         * Negate current Bignat modulo provided modulus
         *
         * @param mod value of modulus
         */
        public void mod_negate(BigNat mod) {
            BigNat tmp = rm.BN_B;
    
            tmp.lock();
            tmp.set_size(mod.length());
            tmp.copy(mod); //-y=mod-y
    
            if (!this.lesser(mod)) { // y<mod
                this.mod(mod);//-y=y-mod
            }
            tmp.subtract(this);
            this.copy(tmp);
            tmp.unlock();
        }
    
        /**
         * Shifts stored value to right by specified number of bytes. This operation equals to multiplication by value numBytes * 256.
         *
         * @param numBytes number of bytes to shift
         */
        public void shift_bytes_right(short numBytes) {
            byte[] tmp = rm.ARRAY_A;
    
            // Move whole content by numBytes offset
            rm.lock(tmp);
            Util.arrayCopyNonAtomic(this.value, (short) 0, tmp, (short) 0, (short) (this.value.length));
            Util.arrayCopyNonAtomic(tmp, (short) 0, this.value, numBytes, (short) ((short) (this.value.length) - numBytes));
            Util.arrayFillNonAtomic(this.value, (short) 0, numBytes, (byte) 0);
            rm.unlock(tmp);
        }
    
        /**
         * Allocates required underlying storage array with given maximum size and
         * allocator type (RAM or EEROM). Maximum size can be increased only by
         * future reallocation if allowed by ALLOW_RUNTIME_REALLOCATION flag
         *
         * @param maxSize       maximum size of this Bignat
         * @param allocatorType memory allocator type. If
         *                      JCSystem.MEMORY_TYPE_PERSISTENT then memory is allocated in EEPROM. Use
         *                      JCSystem.CLEAR_ON_RESET or JCSystem.CLEAR_ON_DESELECT for allocation in
         *                      RAM with corresponding clearing behaviour.
         */
        private void allocate_storage_array(short maxSize, byte allocatorType) {
            this.size = maxSize;
            this.max_size = maxSize;
            this.allocatorType = allocatorType;
            this.value = rm.memAlloc.allocateByteArray(this.max_size, allocatorType);
        }
    
        /**
         * Set content of Bignat internal array
         *
         * @param from_array_length available data in {@code from_array}
         * @param this_offset       offset where data should be stored
         * @param from_array        data array to deserialize from
         * @param from_array_offset offset in {@code from_array}
         * @return the number of shorts actually read, except for the case where
         * deserialization finished by reading precisely {@code len} shorts, in this
         * case {@code len + 1} is returned.
         */
        public short from_byte_array(short from_array_length, short this_offset, byte[] from_array, short from_array_offset) {
            short max
                    = (short) (this_offset + from_array_length) <= this.size
                    ? from_array_length : (short) (this.size - this_offset);
            Util.arrayCopyNonAtomic(from_array, from_array_offset, value, this_offset, max);
            if ((short) (this_offset + from_array_length) == this.size) {
                return (short) (from_array_length + 1);
            } else {
                return max;
            }
        }
    
        /**
         * Set content of Bignat internal array
         *
         * @param this_offset       offset where data should be stored
         * @param from_array        data array to deserialize from
         * @param from_array_length available data in {@code from_array}
         * @param from_array_offset offset in {@code from_array}
         * @return the number of shorts actually read, except for the case where
         * deserialization finished by reading precisely {@code len} shorts, in this
         * case {@code len + 1} is returned.
         */
        public short set_from_byte_array(short this_offset, byte[] from_array, short from_array_offset, short from_array_length) {
            return from_byte_array(from_array_length, this_offset, from_array, from_array_offset);
        }
    
        /**
         * Set content of BigNat internal array
         *
         * @param from_array data array to deserialize from
         * @return the number of shorts actually read
         */
        public short from_byte_array(byte[] from_array) {
            return this.from_byte_array((short) from_array.length, (short) (this.value.length - from_array.length), from_array, (short) 0);
        }
    }
    
    
    /**
     * @author Vasilios Mavroudis and Petr Svenda
     */
    static class Integer {
        private ResourceManager rm;
        private BigNat magnitude;
        private byte sign;
    
        /**
         * Allocates integer with provided length and sets to zero.
         *
         * @param size
         * @param bnh  Bignat_Helper with all supporting objects
         */
        public Integer(short size, ResourceManager rm) {
            allocate(size, (byte) 0, null, (byte) -1, rm);
        }
    
        /**
         * Allocates integer from provided buffer and initialize by provided value.
         * Sign is expected as first byte of value.
         *
         * @param value       array with initial value
         * @param valueOffset start offset within   value
         * @param length      length of array
         * @param bnh         BignatHelper with all supporting objects
         */
        public Integer(byte[] value, short valueOffset, short length, ResourceManager rm) {
            allocate(length, (value[valueOffset] == (byte) 0x00) ? (byte) 0 : (byte) 1, value, (short) (valueOffset + 1), rm);
        }
    
        /**
         * Allocates integer from provided array with explicit sign. No sign is expected in provided array.
         *
         * @param sign  sign of integer
         * @param value array with initial value
         * @param bnh   Bignat_Helper with all supporting objects
         */
        public Integer(byte sign, byte[] value, ResourceManager rm) {
            allocate((short) value.length, sign, value, (short) 0, rm);
        }
    
        /**
         * Copy constructor of integer from other already existing value
         *
         * @param other integer to copy from
         */
        public Integer(Integer other) {
            allocate(other.getSize(), other.getSign(), other.getMagnitude_b(), (short) 0, other.rm);
        }
    
        /**
         * Creates integer from existing Bignat and provided sign. If required,
         * copy is performed, otherwise BigNat is used as magnitude.
         *
         * @param sign      sign of integer
         * @param magnitude initial magnitude
         * @param copy      if true, magnitude is directly used (no copy). If false, new storage array is allocated.
         */
        public Integer(byte sign, BigNat magnitude, boolean copy, ResourceManager rm) {
            if (copy) {
                // Copy from provided BigNat
                allocate(magnitude.length(), sign, magnitude.as_byte_array(), (short) 0, rm);
            } else {
                // Use directly provided BigNat as storage - no allocation
                initialize(sign, magnitude, rm);
            }
        }
    
        /**
         * Initialize integer object with provided sign and already allocated Bignat
         * as magnitude
         *
         * @param sign      sign of integer
         * @param bnStorage magnitude (object is directly used, no copy is performed)
         */
        private void initialize(byte sign, BigNat bnStorage, ResourceManager rm) {
            this.sign = sign;
            this.magnitude = bnStorage;
            this.rm = rm;
        }
    
        /**
         * Allocates and initializes Integer.
         *
         * @param size            length of integer
         * @param sign            sign of integer
         * @param fromArray       input array with initial value (copy of value is
         *                        performed)
         * @param fromArrayOffset start offset within fromArray
         */
        private void allocate(short size, byte sign, byte[] fromArray, short fromArrayOffset, ResourceManager rm) {
            this.rm = rm;
            BigNat mag = new BigNat(size, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, this.rm);
            if (fromArray != null) {
                mag.from_byte_array(size, (short) 0, fromArray, fromArrayOffset);
            }
            initialize(sign, mag, this.rm);
        }
    
        /**
         * Clone value into this Integer from other Integer. Updates size of integer.
         *
         * @param other other integer to copy from
         */
        public void clone(Integer other) {
            this.sign = other.getSign();
            this.magnitude.copy(other.getMagnitude());
        }
    
        /**
         * set this integer to zero
         */
        public void zero() {
            this.sign = (short) 0;
            this.magnitude.zero();
        }
    
        /**
         * Return sign of this integer
         *
         * @return current sign
         */
        public byte getSign() {
            return this.sign;
        }
    
        /**
         * Set sign of this integer
         *
         * @param s new sign
         */
        public void setSign(byte s) {
            this.sign = s;
        }
    
        /**
         * Return length (in bytes) of this integer
         *
         * @return length of this integer
         */
        public short getSize() {
            return this.magnitude.length();
        }
    
        /**
         * Set length of this integer
         *
         * @param newSize new length
         */
        public void setSize(short newSize) {
            this.magnitude.set_size(newSize);
        }
    
        /**
         * Compute negation of this integer
         */
        public void negate() {
            if (this.isPositive()) {
                this.setSign((byte) 1);
            } else if (this.isNegative()) {
                this.setSign((byte) 0);
            }
        }
    
        /**
         * Returns internal array as byte array. No copy is performed so change of
         * values in array also changes this integer
         *
         * @return byte array with magnitude
         */
        public byte[] getMagnitude_b() {
            return this.magnitude.as_byte_array();
        }
    
        /**
         * Returns magnitude as Bignat. No copy is performed so change of Bignat also changes this integer
         *
         * @return Bignat representing magnitude
         */
        public BigNat getMagnitude() {
            return this.magnitude;
        }
    
        /**
         * Set magnitude of this integer from other one. Will not change this integer length.
         * No sign is copied from other.
         *
         * @param other other integer to copy from
         */
        public void setMagnitude(Integer other) {
            this.magnitude.copy(other.getMagnitude());
        }
    
        /**
         * Serializes this integer value into array. Sign is serialized as first byte
         *
         * @param outBuffer       output array
         * @param outBufferOffset start offset within output array
         * @return length of resulting serialized number including sign (number of bytes)
         */
        public short toByteArray(byte[] outBuffer, short outBufferOffset) {
            //Store sign
            outBuffer[outBufferOffset] = sign;
            //Store magnitude
            Util.arrayCopyNonAtomic(this.getMagnitude_b(), (short) 0, outBuffer, (short) (outBufferOffset + 1), this.getSize());
            return (short) (this.getSize() + 1);
        }
    
        /**
         * Deserialize value of this integer from provided array including sign.
         * Sign is expected to be as first byte
         *
         * @param value       array with value
         * @param valueOffset start offset within value
         * @param valueLength length of value
         */
        public void fromByteArray(byte[] value, short valueOffset, short valueLength) {
            //Store sign
            this.sign = value[valueOffset];
            //Store magnitude
            this.magnitude.from_byte_array((short) (valueLength - 1), (short) 0, value, (short) (valueOffset + 1));
        }
    
        /**
         * Return true if integer is negative.
         *
         * @return true if integer is negative, false otherwise
         */
        public boolean isNegative() {
            return this.sign == 1;
        }
    
        /**
         * Return true if integer is positive.
         *
         * @return true if integer is positive, false otherwise
         */
        public boolean isPositive() {
            return this.sign == 0;
        }
    
        /**
         * Compares two integers. Return true, if this is smaller than other.
         *
         * @param other other integer to compare
         * @return true, if this is strictly smaller than other. False otherwise.
         */
        public boolean lesser(Integer other) {
            if (this.sign == 1 && other.sign == 0) {
                return true;
            } else if (this.sign == 0 && other.sign == 1) {
                return false;
            } else if ((this.sign == 0 && other.sign == 0)) {
                return this.magnitude.lesser(other.magnitude);
            } else { //if ((this.sign == 1 && other.sign==1))
                return (!this.magnitude.lesser(other.magnitude));
            }
        }
    
        /**
         * Add other integer to this and store result into this.
         *
         * @param other other integer to add
         */
        public void add(Integer other) {
            BigNat tmp = rm.BN_A;
    
            if (this.isPositive() && other.isPositive()) { //this and other are (+)
                this.sign = 0;
                this.magnitude.add(other.magnitude);
            } else if (this.isNegative() && other.isNegative()) { //this and other are (-)
                this.sign = 1;
                this.magnitude.add(other.magnitude);
            } else {
                if (this.isPositive() && other.getMagnitude().lesser(this.getMagnitude())) { //this(+) is larger than other(-)
                    this.sign = 0;
                    this.magnitude.subtract(other.magnitude);
                } else if (this.isNegative() && other.getMagnitude().lesser(this.getMagnitude())) {    //this(-) has larger magnitude than other(+)
                    this.sign = 1;
                    this.magnitude.subtract(other.magnitude);
                } else if (this.isPositive() && this.getMagnitude().lesser(other.getMagnitude())) { //this(+) has smaller magnitude than other(-)
                    this.sign = 1;
                    tmp.lock();
                    tmp.clone(other.getMagnitude());
                    tmp.subtract(this.magnitude);
                    this.magnitude.copy(tmp);
                    tmp.unlock();
                } else if (this.isNegative() && this.getMagnitude().lesser(other.getMagnitude())) {  //this(-) has larger magnitude than other(+)
                    this.sign = 0;
                    tmp.lock();
                    tmp.clone(other.getMagnitude());
                    tmp.subtract(this.magnitude);
                    this.magnitude.copy(tmp);
                    tmp.unlock();
                } else if (this.getMagnitude().same_value(other.getMagnitude())) {  //this has opposite sign than other, and the same magnitude
                    this.sign = 0;
                    this.zero();
                }
            }
        }
    
        /**
         * Substract other integer from this and store result into this.
         *
         * @param other other integer to substract
         */
        public void subtract(Integer other) {
            other.negate(); // Potentially problematic - failure and exception in subsequent function will cause other to stay negated
            this.add(other);
            // Restore original sign for other
            other.negate();
        }
    
        /**
         * Multiply this and other integer and store result into this.
         *
         * @param other other integer to multiply
         */
        public void multiply(Integer other) {
            BigNat mod = rm.BN_A;
            BigNat tmp = rm.BN_B;
    
            if (this.isPositive() && other.isNegative()) {
                this.setSign((byte) 1);
            } else if (this.isNegative() && other.isPositive()) {
                this.setSign((byte) 1);
            } else {
                this.setSign((byte) 0);
            }
    
            // Make mod BN as maximum value (positive, leading 0x80)
            mod.lock();
            mod.set_size(this.magnitude.length());
            mod.zero();
            mod.as_byte_array()[0] = (byte) 0x80;  // Max INT+1 Value
    
            tmp.lock();
            tmp.set_size(this.magnitude.length());
            tmp.mod_mult(this.getMagnitude(), other.getMagnitude(), mod);
            this.magnitude.copy(tmp);
            mod.unlock();
            tmp.unlock();
        }
    
        /**
         * Divide this by other integer and store result into this.
         *
         * @param other divisor
         */
        public void divide(Integer other) {
            BigNat tmp = rm.BN_A;
    
            if (this.isPositive() && other.isNegative()) {
                this.setSign((byte) 1);
            } else if (this.isNegative() && other.isPositive()) {
                this.setSign((byte) 1);
            } else {
                this.setSign((byte) 0);
            }
    
            tmp.lock();
            tmp.clone(this.magnitude);
            tmp.remainder_divide(other.getMagnitude(), this.magnitude);
            tmp.unlock();
        }
    
        /**
         * Computes modulo of this by other integer and store result into this.
         *
         * @param other modulus
         */
        public void modulo(Integer other) {
            this.magnitude.mod(other.getMagnitude());
        }
    }
    
    /**
     * @author Petr Svenda
     */
    static class ResourceManager {
        public ObjectLocker locker;
        public ObjectAllocator memAlloc;
    
        MessageDigest hashEngine;
        KeyAgreement ecMultKA;
        KeyAgreement ecAddKA;
        Signature verifyEcdsa;
        Cipher multCiph;
        RSAPrivateKey expPK;
        Cipher expCiph;
    
        byte[] ARRAY_A, ARRAY_B, POINT_ARRAY_A, POINT_ARRAY_B, HASH_ARRAY;
        public static final byte LOCKER_ARRAYS = 5;
        byte[] RAM_WORD; // Without lock
    
        static byte[] CONST_TWO = {0x02};
        public static final byte LOCKER_OBJECTS = 1;
    
        BigNat BN_A, BN_B, BN_C, BN_D, BN_E, BN_F;
        BigNat EC_BN_A, EC_BN_B, EC_BN_C, EC_BN_D, EC_BN_E, EC_BN_F;
        public static BigNat ONE, TWO, THREE, ONE_COORD;
    
        // TODO remove if possible
        public final short MODULO_RSA_ENGINE_MAX_LENGTH_BITS;
    
        public ResourceManager(short MAX_POINT_SIZE, short MAX_COORD_SIZE, short MAX_BIGNAT_SIZE, short MULT_RSA_ENGINE_MAX_LENGTH_BITS, short MODULO_RSA_ENGINE_MAX_LENGTH_BITS) {
            this.MODULO_RSA_ENGINE_MAX_LENGTH_BITS = MODULO_RSA_ENGINE_MAX_LENGTH_BITS;
            // Allocate long-term helper values
            locker = new ObjectLocker((short) (LOCKER_ARRAYS + LOCKER_OBJECTS));
            // locker.setLockingActive(false); // if required, locking can be disabled
            memAlloc = new ObjectAllocator();
            memAlloc.setAllAllocatorsRAM();
            // if required, memory for helper objects and arrays can be in persistent memory to save RAM (or some tradeoff)
            // ObjectAllocator.setAllAllocatorsEEPROM();
            // ObjectAllocator.setAllocatorsTradeoff();
    
    
            ARRAY_A = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.ARRAY_A));
            locker.registerLock(ARRAY_A);
            ARRAY_B = memAlloc.allocateByteArray((short) (MULT_RSA_ENGINE_MAX_LENGTH_BITS / 8), memAlloc.getAllocatorType(ObjectAllocator.ARRAY_B));
            locker.registerLock(ARRAY_B);
            POINT_ARRAY_A = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_A));
            locker.registerLock(POINT_ARRAY_A);
            POINT_ARRAY_B = memAlloc.allocateByteArray((short) (MAX_POINT_SIZE + 1), memAlloc.getAllocatorType(ObjectAllocator.POINT_ARRAY_B));
            locker.registerLock(POINT_ARRAY_B);
            hashEngine = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            HASH_ARRAY = memAlloc.allocateByteArray(hashEngine.getLength(), memAlloc.getAllocatorType(ObjectAllocator.HASH_ARRAY));
            locker.registerLock(HASH_ARRAY);
            RAM_WORD = memAlloc.allocateByteArray((short) 2, JCSystem.MEMORY_TYPE_TRANSIENT_RESET); // only 2b RAM for faster add(short)
    
            BN_A = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_A), this);
            BN_B = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_B), this);
            BN_C = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_C), this);
            BN_D = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_D), this);
            BN_E = new BigNat(MAX_BIGNAT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.BN_E), this);
            BN_F = new BigNat((short) (MAX_BIGNAT_SIZE + 2), memAlloc.getAllocatorType(ObjectAllocator.BN_F), this); // +2 is to correct for infrequent RSA result with two or more leading zeroes
    
            EC_BN_A = new BigNat(MAX_POINT_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_A), this);
            EC_BN_B = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_B), this);
            EC_BN_C = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_C), this);
            EC_BN_D = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_D), this);
            EC_BN_E = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_E), this);
            EC_BN_F = new BigNat(MAX_COORD_SIZE, memAlloc.getAllocatorType(ObjectAllocator.EC_BN_F), this);
    
            // Allocate BN constants always in EEPROM (only reading)
            ONE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            ONE.one();
            TWO = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            TWO.two();
            THREE = new BigNat((short) 1, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            THREE.three();
            ONE_COORD = new BigNat(MAX_COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, this);
            ONE_COORD.one();
    
            // ECC Helpers
            if (OperationSupport.getInstance().EC_HW_XY) {
                // ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
                ecMultKA = KeyAgreement.getInstance((byte) 6, false);
            } else if (OperationSupport.getInstance().EC_HW_X) {
                // ecMultKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
                ecMultKA = KeyAgreement.getInstance((byte) 3, false);
            }
            // verifyEcdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            verifyEcdsa = Signature.getInstance((byte) 33, false);
            if (OperationSupport.getInstance().EC_HW_ADD) {
                // ecAddKA = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
                ecAddKA = KeyAgreement.getInstance((byte) 5, false);
            }
    
            // RSA Mult Helpers
            KeyPair multKP = new KeyPair(KeyPair.ALG_RSA_CRT, MULT_RSA_ENGINE_MAX_LENGTH_BITS);
            multKP.genKeyPair();
            RSAPublicKey multPK = (RSAPublicKey) multKP.getPublic();
            multPK.setExponent(CONST_TWO, (short) 0, (short) CONST_TWO.length);
            multCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            multCiph.init(multPK, Cipher.MODE_ENCRYPT);
    
            // RSA Exp Helpers
            expPK = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, MODULO_RSA_ENGINE_MAX_LENGTH_BITS, false);
            expCiph = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        }
    
        /**
         * Erase all values stored in helper objects
         */
        void erase() {
            BN_A.erase();
            BN_B.erase();
            BN_C.erase();
            BN_D.erase();
            BN_E.erase();
            BN_F.erase();
    
            EC_BN_A.erase();
            EC_BN_B.erase();
            EC_BN_C.erase();
            EC_BN_D.erase();
            EC_BN_E.erase();
            EC_BN_F.erase();
    
            Util.arrayFillNonAtomic(ARRAY_A, (short) 0, (short) ARRAY_A.length, (byte) 0);
            Util.arrayFillNonAtomic(ARRAY_B, (short) 0, (short) ARRAY_B.length, (byte) 0);
            Util.arrayFillNonAtomic(POINT_ARRAY_A, (short) 0, (short) POINT_ARRAY_A.length, (byte) 0);
            Util.arrayFillNonAtomic(RAM_WORD, (short) 0, (short) RAM_WORD.length, (byte) 0);
        }
    
        /**
         * Lock a byte array
         *
         * @param objToLock the byte array
         */
        public void lock(byte[] objToLock) {
            locker.lock(objToLock);
        }
    
        /**
         * Unlock a byte array
         *
         * @param objToUnlock the byte array
         */
        public void unlock(byte[] objToUnlock) {
            locker.unlock(objToUnlock);
        }
    
        /**
         * Unlocks all locked objects
         */
        public void unlockAll() {
            if (BN_A.isLocked()) {
                BN_A.unlock();
            }
            if (BN_B.isLocked()) {
                BN_B.unlock();
            }
            if (BN_C.isLocked()) {
                BN_C.unlock();
            }
            if (BN_D.isLocked()) {
                BN_D.unlock();
            }
            if (BN_E.isLocked()) {
                BN_E.unlock();
            }
            if (BN_F.isLocked()) {
                BN_F.unlock();
            }
    
            if (EC_BN_A.isLocked()) {
                EC_BN_A.unlock();
            }
            if (EC_BN_B.isLocked()) {
                EC_BN_B.unlock();
            }
            if (EC_BN_C.isLocked()) {
                EC_BN_C.unlock();
            }
            if (EC_BN_D.isLocked()) {
                EC_BN_D.unlock();
            }
            if (EC_BN_E.isLocked()) {
                EC_BN_E.unlock();
            }
            if (EC_BN_F.isLocked()) {
                EC_BN_F.unlock();
            }
    
            locker.unlockAll();
        }
    }
    
    static class SecP256r1 {
    
        public final static short KEY_LENGTH = 256;//Bits
        public final static short POINT_SIZE = 65; //Bytes
        public final static short COORD_SIZE = 32; //Bytes
    
        public final static byte[] p = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };
    
    
        public final static byte[] a = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc};
    
        public final static byte[] b = { 0x5a, (byte) 0xc6, 0x35, (byte) 0xd8, (byte) 0xaa, 0x3a,
                (byte) 0x93, (byte) 0xe7, (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, 0x55, 0x76, (byte) 0x98,
                (byte) 0x86, (byte) 0xbc, 0x65, 0x1d, 0x06, (byte) 0xb0, (byte) 0xcc, 0x53, (byte) 0xb0,
                (byte) 0xf6, 0x3b, (byte) 0xce, 0x3c, 0x3e, 0x27, (byte) 0xd2, 0x60, 0x4b };
    
        public final static byte[] G = { 0x04, 0x6b, 0x17, (byte) 0xd1, (byte) 0xf2, (byte) 0xe1, 0x2c,
                0x42, 0x47, (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5, 0x63, (byte) 0xa4, 0x40,
                (byte) 0xf2, 0x77, 0x03, 0x7d, (byte) 0x81, 0x2d, (byte) 0xeb, 0x33, (byte) 0xa0, (byte) 0xf4,
                (byte) 0xa1, 0x39, 0x45, (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96, 0x4f, (byte) 0xe3,
                0x42, (byte) 0xe2, (byte) 0xfe, 0x1a, 0x7f, (byte) 0x9b, (byte) 0x8e, (byte) 0xe7, (byte) 0xeb,
                0x4a, 0x7c, 0x0f, (byte) 0x9e, 0x16, 0x2b, (byte) 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                (byte) 0xce, (byte) 0xcb, (byte) 0xb6, 0x40, 0x68, 0x37, (byte) 0xbf, 0x51, (byte) 0xf5 };
    
        public final static byte[] r = { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x00, 0x00, 0x00,
                0x00, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad, (byte) 0xa7, 0x17, (byte) 0x9e,
                (byte) 0x84, (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2, (byte) 0xfc, 0x63, 0x25, 0x51 };
    }
    
    static class SecP256k1 {
    
        public final static short KEY_LENGTH = 256; // Bits
        public final static short POINT_SIZE = 65; // Bytes
        public final static short COORD_SIZE = 32; // Bytes
    
        public final static byte[] p = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
                (byte) 0xff, (byte) 0xff, (byte) 0xfc, (byte) 0x2f
        };
    
        public final static byte[] a = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
        };
    
        public final static byte[] b = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x07
        };
    
        public final static byte[] G = {
                (byte) 0x04,
                (byte) 0x79, (byte) 0xbe, (byte) 0x66, (byte) 0x7e,
                (byte) 0xf9, (byte) 0xdc, (byte) 0xbb, (byte) 0xac,
                (byte) 0x55, (byte) 0xa0, (byte) 0x62, (byte) 0x95,
                (byte) 0xce, (byte) 0x87, (byte) 0x0b, (byte) 0x07,
                (byte) 0x02, (byte) 0x9b, (byte) 0xfc, (byte) 0xdb,
                (byte) 0x2d, (byte) 0xce, (byte) 0x28, (byte) 0xd9,
                (byte) 0x59, (byte) 0xf2, (byte) 0x81, (byte) 0x5b,
                (byte) 0x16, (byte) 0xf8, (byte) 0x17, (byte) 0x98,
                (byte) 0x48, (byte) 0x3a, (byte) 0xda, (byte) 0x77,
                (byte) 0x26, (byte) 0xa3, (byte) 0xc4, (byte) 0x65,
                (byte) 0x5d, (byte) 0xa4, (byte) 0xfb, (byte) 0xfc,
                (byte) 0x0e, (byte) 0x11, (byte) 0x08, (byte) 0xa8,
                (byte) 0xfd, (byte) 0x17, (byte) 0xb4, (byte) 0x48,
                (byte) 0xa6, (byte) 0x85, (byte) 0x54, (byte) 0x19,
                (byte) 0x9c, (byte) 0x47, (byte) 0xd0, (byte) 0x8f,
                (byte) 0xfb, (byte) 0x10, (byte) 0xd4, (byte) 0xb8
        };
    
        public final static byte[] r = {
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
                (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfe,
                (byte) 0xba, (byte) 0xae, (byte) 0xdc, (byte) 0xe6,
                (byte) 0xaf, (byte) 0x48, (byte) 0xa0, (byte) 0x3b,
                (byte) 0xbf, (byte) 0xd2, (byte) 0x5e, (byte) 0x8c,
                (byte) 0xd0, (byte) 0x36, (byte) 0x41, (byte) 0x41,
        };
    }
    

    /**
     *
    * @author Vasilios Mavroudis and Petr Svenda
     */
    static class ObjectLocker {
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information from previous
         * operation. If true, object is erased once locked for use
         */
        private boolean ERASE_ON_LOCK = false;
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information to next 
         * operation. If true, object is erased once unlocked from use
         */
        private boolean ERASE_ON_UNLOCK = false;    
        
        /**
         * Configuration flag controlling clearing of shared objects on lock as
         * prevention of unwanted leak of sensitive information to next operation.
         * If true, object is erased once unlocked from use
         */
        private boolean PROFILE_LOCKED_OBJECTS = false;
        /**
         * Array of pointers to objects which will be guarded by locks. 
         * Every even value contains pointer to registered object. Subsequent index 
         * contains null if not locked, !null if locked, 
         * Stored in RAM for fast access.
         */
        private Object[] lockedObjects;
        /**
         * Copy of pointers to objects from lockedObjects in persistent memory to refresh after card reset.
         * Refreshed by call {@code refreshAfterReset()}
         */
        private Object[] lockedObjectsPersistent;
        
        /**
         * Array to hold state of lock for all other objects implemented as N x N array [0...N-1][N...2N-1]...[] 
         * where [0...N-1] contains the states of lock for all other objects than first object (lockedObjects[0]). 
         * If no other object is locked after series of operations, [0...N-1] will contain 0 on all indexes. 
         * All objects (lockedObjects[i]) which happened to be locked together with have 1 at [0...i...N-1]. 
         */
        public byte[] profileLockedObjects;
        /**
         * If true, locking is performed, otherwise relevant method just return without any operation performed
         */
        private boolean bLockingActive = true;
        
        public ObjectLocker(short numArrays) {
            initialize(numArrays, ERASE_ON_LOCK, ERASE_ON_UNLOCK);
        }
        public ObjectLocker(short numArrays, boolean bEraseOnLock, boolean bEraseOnUnlock) {
            initialize(numArrays, bEraseOnLock, bEraseOnUnlock);
        }
        private final void initialize(short numObjects, boolean bEraseOnLock, boolean bEraseOnUnlock) {
            lockedObjects = JCSystem.makeTransientObjectArray((short) (2 * numObjects), JCSystem.CLEAR_ON_RESET);
            lockedObjectsPersistent = new Object[(short) (2 * numObjects)];
            ERASE_ON_LOCK = bEraseOnLock;
            ERASE_ON_UNLOCK = bEraseOnUnlock;
            profileLockedObjects = new byte[(short) (numObjects * numObjects)]; 
            resetProfileLocks();
        }
        
        /**
         * Reset profile array with profile locks statistics.
         */
        public void resetProfileLocks() {
            Util.arrayFillNonAtomic(profileLockedObjects, (short) 0, (short) profileLockedObjects.length, (byte) 0);
        }
    
        /**
         * Register new object for lock guarding. 
         * @param objToLock object to be guarded
         * @return index to internal array where registered object is stored (if known, lock/unlock is faster)
         */
        public short registerLock(Object objToLock) {
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] == null) {
                    // Free slot found
                    lockedObjects[i] = objToLock;
                    lockedObjects[(short) (i + 1)] = null; // null means array is unlocked
                    lockedObjectsPersistent[i] = objToLock; // Store same into persistent array as well
                    lockedObjectsPersistent[(short) (i + 1)] = null; 
                    return i; // Return index for potential speedup of locking
                }
            }
            ISOException.throwIt(ReturnCodes.SW_LOCK_NOFREESLOT);
            return -1;
        }
        /**
         * Locking array (placed in RAM) must be refreshed after card reset. Call this method during select()
         */
        public void refreshAfterReset() {
            for (short i = 0; i < (short) lockedObjects.length; i++) {
                lockedObjects[i] = lockedObjectsPersistent[i];
            }
        }
        
        /**
         * Controls if locking and unlocking is actually performed. The lock operations 
         * add some overhead, so it may be turned on/off as required. E.g., when developing 
         * new code or like to enjoy protection of automatic clearing of shared objects before/after lock
         * enable this feature. 
         * @param bLockActive if true, locking and unlocking is performed. If false, lock/unlock methods will return without any effect
         */
        public void setLockingActive(boolean bLockActive) {
            bLockingActive = bLockActive;
        }
        /**
         * Lock/reserve provided object for subsequent use. Used to protect corruption
         * of pre-allocated shared objects in different, potentially nested,
         * operations. Must be unlocked later on.
         *
         * @param objToLock array to be locked
         * @throws SW_ALREADYLOCKED if already locked (is already in use by
         * other operation)
         */
        public void lock(Object objToLock) {
            if (!bLockingActive) {
                return;
            }
            // Find object to lock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToLock)) {
                    lock(objToLock, i);
                    break;
                }
            }
            // If reached here, required array was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
        }
        public void lock(byte[] objToLock) {
            if (!bLockingActive) {
                return;
            }
            lock((Object) objToLock);
            if (ERASE_ON_LOCK) {
                Util.arrayFillNonAtomic(objToLock, (short) 0, (short) objToLock.length, (byte) 0);
            }
        }
        /**
         * Unlock/release object from use. Used to protect corruption of
         * pre-allocated objects used in different nested operations. Must
         * be locked before.
         *
         * @param objToUnlock object to unlock
         * @throws SW_NOTLOCKED_BIGNAT if was not locked before (inconsistence in
         * lock/unlock sequence)
         */
        
        public void unlock(Object objToUnlock) {
            if (!bLockingActive) {
                return;
            }
            // Find object to unlock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                    unlock(objToUnlock, i);
                    break;
                }
            }
            // If reached here, required array was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
        }    
    
        public void unlock(byte[] objToUnlock) {
            if (!bLockingActive) {
                return;
            }
            unlock((Object) objToUnlock);
            if (ERASE_ON_UNLOCK) {
                Util.arrayFillNonAtomic(objToUnlock, (short) 0, (short) objToUnlock.length, (byte) 0);
            }
        }    
        
        /**
         * Unlocks all locked objects
         */
        public void unlockAll() {
            if (!bLockingActive) {
                return;
            }
            for (short i = 0; i < (short) lockedObjects.length; i += 2) {
                lockedObjects[(short) (i + 1)] = null;
            }
        }
        
        /**
         * Check if provided object is logically locked
         * @param objToUnlock object to be checked
         * @return true of array is logically locked, false otherwise 
         */
        
        public boolean isLocked(Object objToUnlock) {
            if (!bLockingActive) {
                return false;
            }
            // Find object to unlock
            short i;
            for (i = 0; i < (short) lockedObjects.length; i += 2) {
                if (lockedObjects[i] != null && lockedObjects[i].equals(objToUnlock)) {
                    return lockedObjects[(short) (i + 1)] != null;
                }
            }
            // If reached here, required object was not found
            if (i == (short) lockedObjects.length) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_NOT_FOUND);
            }
            return false;
        }
        
        
        private void lock(Object objToLock, short lockIndex) {
            if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToLock)) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
            }
            // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
            if (lockedObjects[(short) (lockIndex + 1)] == null) {
                lockedObjects[(short) (lockIndex + 1)] = objToLock; // lock logically by assigning object reference to [i + 1]
            } else {
                // this array is already locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_ALREADYLOCKED);
            }
            if (PROFILE_LOCKED_OBJECTS) {
                // If enabled, check status of all other objects and mark these that are currently locked
                short profileLockOffset = (short) ((short) (lockIndex / 2) * (short) ((short) lockedObjects.length / 2)); // Obtain section of profileLockedObjects array relevant for current object
                
                for (short i = 0; i < (short) lockedObjects.length; i += 2) {
                    if (lockedObjects[(short) (i + 1)] != null) {
                        // Object at index i is locked, mark it to corresponding position in profileLockedObjects by setting value to 1
                        profileLockedObjects[(short) (profileLockOffset + (short) (i / 2))] = 1;
                    }
                }
            }
        }
        
        private void unlock(Object objToUnlock, short lockIndex) {
            if (lockedObjects[lockIndex] != null && !lockedObjects[lockIndex].equals(objToUnlock)) {
                ISOException.throwIt(ReturnCodes.SW_LOCK_OBJECT_MISMATCH);
            }
            // Next position in array signalizes logical lock (null == unlocked, !null == locked) 
            if (lockedObjects[(short) (lockIndex + 1)].equals(objToUnlock)) {
                lockedObjects[(short) (lockIndex + 1)] = null; // lock logically by assigning object reference to [i + 1]
            } else {
                // this array is not locked, raise exception (incorrect sequence of locking and unlocking)
                ISOException.throwIt(ReturnCodes.SW_LOCK_NOTLOCKED);
            }
        }
    }
    
    
    /**
     * The control point for unified allocation of arrays and objects with customable
     * specification of allocator type (RAM/EEPROM) for particular array. Allows for 
     * quick personalization and optimization of memory use when compiling for cards 
     * with more/less available memory. 
     * 
    * @author Petr Svenda
     */
    static class ObjectAllocator {
        short allocatedInRAM = 0;
        short allocatedInEEPROM = 0;
        byte[] ALLOCATOR_TYPE_ARRAY;
        
        public static final byte ARRAY_A = 0;
        public static final byte ARRAY_B = 1;
        public static final byte BN_A = 2;
        public static final byte BN_B = 3;
        public static final byte BN_C = 4;
        public static final byte BN_D = 5;
        public static final byte BN_E = 6;
        public static final byte BN_F = 7;
        
        public static final byte EC_BN_A = 8;
        public static final byte EC_BN_B = 9;
        public static final byte EC_BN_C = 10;
        public static final byte EC_BN_D = 11;
        public static final byte EC_BN_E = 12;
        public static final byte EC_BN_F = 13;
        public static final byte POINT_ARRAY_A = 14;
        public static final byte POINT_ARRAY_B = 15;
        public static final byte HASH_ARRAY = 16;
        
        public static final short ALLOCATOR_TYPE_ARRAY_LENGTH = (short) (HASH_ARRAY + 1);
        
        /**
         * Creates new allocator control object, resets performance counters
         */
        public ObjectAllocator() {
            ALLOCATOR_TYPE_ARRAY = new byte[ALLOCATOR_TYPE_ARRAY_LENGTH];
            setAllAllocatorsRAM();
            resetAllocatorCounters();
        }
        /**
         * All type of allocator for all object as EEPROM
         */
        public final void setAllAllocatorsEEPROM() {
            Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_PERSISTENT);
        }
        /**
         * All type of allocator for all object as RAM
         */
        public void setAllAllocatorsRAM() {
            Util.arrayFillNonAtomic(ALLOCATOR_TYPE_ARRAY, (short) 0, (short) ALLOCATOR_TYPE_ARRAY.length, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        }
        /**
         * All type of allocator for selected object as RAM (faster), rest EEPROM (saving RAM)
         * The current settings is heuristically obtained from measurements of performance of Bignat and ECPoint operations 
         */    
        public void setAllocatorsTradeoff() {
            // Set initial allocators into EEPROM
            setAllAllocatorsEEPROM();
            
            // Put only the most perfromance relevant ones into RAM
            ALLOCATOR_TYPE_ARRAY[ARRAY_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[ARRAY_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_D] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_E] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[BN_F] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[EC_BN_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[EC_BN_C] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[POINT_ARRAY_A] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
            ALLOCATOR_TYPE_ARRAY[POINT_ARRAY_B] = JCSystem.MEMORY_TYPE_TRANSIENT_RESET;
        }   
    
        /**
         * Allocates new byte[] array with provided length either in RAM or EEPROM based on an allocator type.
         * Method updates internal counters of bytes allocated with specific allocator. Use {@code getAllocatedInRAM()} 
         * or {@code getAllocatedInEEPROM} for counters readout.
         * @param length    length of array
         * @param allocatorType type of allocator
         * @return allocated array 
         */
        public byte[] allocateByteArray(short length, byte allocatorType) {
            switch (allocatorType) {
                case JCSystem.MEMORY_TYPE_PERSISTENT:
                    allocatedInEEPROM += length;
                    return new byte[length];
                case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
                    allocatedInRAM += length;
                    return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_RESET);
                case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
                    allocatedInRAM += length;
                    return JCSystem.makeTransientByteArray(length, JCSystem.CLEAR_ON_DESELECT);
            }
            return null;
        }
    
        /**
         * Returns pre-set allocator type for provided object identified by unique objectAllocatorID
         * @param objectAllocatorID unique id of target object
         * @return allocator type
         */
        public byte getAllocatorType(short objectAllocatorID) {
            if (objectAllocatorID >= 0 && objectAllocatorID <= (short) ALLOCATOR_TYPE_ARRAY.length) {
                return ALLOCATOR_TYPE_ARRAY[objectAllocatorID];
            } else {
                ISOException.throwIt(ReturnCodes.SW_ALLOCATOR_INVALIDOBJID);
                return -1;
            }
        }    
        
        /**
         * Returns number of bytes allocated in RAM via {@code allocateByteArray()} since last reset of counters.
         * @return number of bytes allocated in RAM via this control object
         */
        public short getAllocatedInRAM() {
            return allocatedInRAM;
        }
        /**
         * Returns number of bytes allocated in EEPROM via {@code allocateByteArray()}
         * since last reset of counters.
         *
         * @return number of bytes allocated in EEPROM via this control object
         */
        public short getAllocatedInEEPROM() {
            return allocatedInEEPROM;
        }
        /**
         * Resets counters of allocated bytes in RAM and EEPROM
         */
        public final void resetAllocatorCounters() {
            allocatedInRAM = 0;
            allocatedInEEPROM = 0;
        }
    }
}
