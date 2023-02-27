package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import jcfrost.JCFROST;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest extends BaseTest {
    TestVectors tv = new TestVectors("src/test/resources/frost-secp256k1-sha256.json");
    int CARD = 1;

    public AppletTest() throws Exception {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
        connect().transmit(new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0));
    }

    public ResponseAPDU setup(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(
                Consts.CLA_JCFROST,
                Consts.INS_SETUP,
                tv.minParticipants(),
                tv.maxParticipants(),
                Util.concat(new byte[]{(byte) CARD}, tv.secret(CARD), tv.groupKey())
        );
        return cm.transmit(cmd);
    }

    public ResponseAPDU commit(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_COMMIT, 0, 0);
        return cm.transmit(cmd);
    }

    public ResponseAPDU commitment(CardManager cm, int identifier, byte[] data) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_COMMITMENT, identifier, 0, data);
        return cm.transmit(cmd);
    }

    public ResponseAPDU sign(CardManager cm, byte[] msg) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_SIGN, msg.length, 0, msg);
        return cm.transmit(cmd);
    }

    public ResponseAPDU reset(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_RESET, 0, 0);
        return cm.transmit(cmd);
    }

    @Test
    public void testSetup() throws Exception {
        CardManager cm = connect();
        ResponseAPDU responseAPDU = setup(cm);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        if (JCFROST.DEBUG) {
            byte[] expected = Util.concat(
                    new byte[]{(byte) tv.minParticipants(), (byte) tv.maxParticipants(), (byte) CARD},
                    tv.secret(CARD),
                    tv.groupKey()
            );
            Assert.assertArrayEquals(responseAPDU.getData(), expected);
        }
        reset(cm);
    }

    @Test
    public void testCommit() throws Exception {
        CardManager cm = connect();
        setup(cm);
        ResponseAPDU responseAPDU = commit(cm);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        // TODO check if proper points were output
        Assert.assertEquals(responseAPDU.getData().length, 66);
        reset(cm);
    }

    @Test
    public void testCommitments() throws Exception {
        CardManager cm = connect();
        setup(cm);
        byte[] data = commit(cm).getData();
        ResponseAPDU responseAPDU = commitment(cm, 1, data);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        responseAPDU = commitment(cm, 3, Util.concat(tv.hidingCommitment(3), tv.bindingCommitment(3)));
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        reset(cm);
    }

    @Test
    public void testSign() throws Exception {
        CardManager cm = connect();
        setup(cm);
        byte[] data = commit(cm).getData();
        commitment(cm, 1, data);
        commitment(cm, 3, Util.concat(tv.hidingCommitment(3), tv.hidingCommitment(3)));
        ResponseAPDU responseAPDU = sign(cm, tv.message());
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertEquals(responseAPDU.getData().length, 32);
        reset(cm);
    }
}
