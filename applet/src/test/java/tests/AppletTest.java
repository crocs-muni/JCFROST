package tests;

import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest extends BaseTest {
    public AppletTest() throws Exception {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
        connect().transmit(new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0));
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
