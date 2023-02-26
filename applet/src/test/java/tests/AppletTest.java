package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import jcfrost.JCFROST;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest extends BaseTest {
    public AppletTest() throws Exception {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
        connect().transmit(new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0));
    }

    public ResponseAPDU setup(CardManager cm) throws CardException {
        byte[] secret = Hex.decode("08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c");
        byte[] groupKey = Hex.decode("02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f");
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_SETUP, 2, 3, Util.concat(new byte[]{1}, Util.concat(secret, groupKey)));
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

    @Test
    public void testSetup() throws Exception {
        CardManager cm = connect();
        ResponseAPDU responseAPDU = setup(cm);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        if(JCFROST.DEBUG) {
            Assert.assertArrayEquals(responseAPDU.getData(), Hex.decode("02030108f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f"));
        }
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
    }

    @Test
    public void testCommitments() throws Exception {
        CardManager cm = connect();
        setup(cm);
        byte[] data = commit(cm).getData();
        ResponseAPDU responseAPDU = commitment(cm, 1, data);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        responseAPDU = commitment(cm, 3, Util.concat(Hex.decode("030278e6e6055fb963b40e0c3c37099f803f3f38930fc89092517f8ce1b47e8d6b"), Hex.decode("028eb6d238c6c0fc6216906706ad0ff9943c6c1d6079cdf74f674481ebb2485db3")));
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
    }

    @Test
    public void testH1() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_TEST_HASH, 1, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertArrayEquals(responseAPDU.getData(), Hex.decode("55b8dbdcbf72668e017f79f83bb7e1b6a30dd60c9dd0654f6c1458c37f50f2b8"));
    }

    @Test
    public void testH3() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_TEST_HASH, 3, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertArrayEquals(responseAPDU.getData(), Hex.decode("dd0a0204c7a7e3ed4a32d5edee5ba274a7ca655ad55e46ed2767dee7c95b2d19"));
    }

    @Test
    public void testH4() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_TEST_HASH, 4, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertArrayEquals(responseAPDU.getData(), Hex.decode("6b930d6492cad96927a6df946246df8cf9c9f9e4537436526b40a08d85dc27aa"));
    }
}
