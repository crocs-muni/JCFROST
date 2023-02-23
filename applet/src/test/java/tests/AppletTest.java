package tests;

import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class AppletTest extends BaseTest {
    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
    }

    @Test
    public void initialize() throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0);
        final ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertTrue(responseAPDU.getSW() == 0x9000 || (short) responseAPDU.getSW() == Consts.E_ALREADY_INITIALIZED);
        Assert.assertNotNull(responseAPDU.getBytes());
    }

}
