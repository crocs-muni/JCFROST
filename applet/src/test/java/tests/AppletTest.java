package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.Util;
import jcfrost.Consts;
import cz.muni.fi.crocs.rcard.client.CardType;
import jcfrost.JCFROST;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.jupiter.api.*;
import org.json.*;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.File;
import java.nio.file.Files;

public class AppletTest extends BaseTest {
    private JSONObject testVectors = new JSONObject(new String(Files.readAllBytes(new File("src/test/resources/frost-secp256k1-sha256.json").toPath())));
    private byte[] secret = Hex.decode(testVectors.getJSONObject("inputs").getJSONObject("participants").getJSONObject("1").getString("participant_share"));
    private byte[] groupKey = Hex.decode(testVectors.getJSONObject("inputs").getString("group_public_key"));
    private int maxParticipants = testVectors.getJSONObject("config").getInt("MAX_PARTICIPANTS");
    private int minParticipants = testVectors.getJSONObject("config").getInt("MIN_PARTICIPANTS");
    private int identifier = 1;
    private byte[] message = Hex.decode(testVectors.getJSONObject("inputs").getString("message"));
    private byte[] hidingNonceCommitment3 = Hex.decode(testVectors.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject("3").getString("hiding_nonce_commitment"));
    private byte[] bindingNonceCommitment3 = Hex.decode(testVectors.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject("3").getString("binding_nonce_commitment"));

    public AppletTest() throws Exception {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
        connect().transmit(new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_INITIALIZE, 0, 0));
    }

    public ResponseAPDU setup(CardManager cm) throws CardException {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_JCFROST, Consts.INS_SETUP, minParticipants, maxParticipants, Util.concat(new byte[]{(byte) identifier}, Util.concat(secret, groupKey)));
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
            byte[] expected = Util.concat(new byte[]{(byte) minParticipants, (byte) maxParticipants, (byte) identifier}, secret, groupKey);
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
        responseAPDU = commitment(cm, 3, Util.concat(hidingNonceCommitment3, bindingNonceCommitment3));
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
        commitment(cm, 3, Util.concat(hidingNonceCommitment3, bindingNonceCommitment3));
        ResponseAPDU responseAPDU = sign(cm, message);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(responseAPDU.getSW(), 0x9000);
        Assert.assertEquals(responseAPDU.getData().length, 32);
        reset(cm);
    }
}
