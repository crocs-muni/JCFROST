package tests;

import org.bouncycastle.util.encoders.Hex;
import org.json.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class TestVectors {
    private final JSONObject data;

    public TestVectors(String path) throws IOException {
        data = new JSONObject(new String(Files.readAllBytes(new File(path).toPath())));
    }

    public int minParticipants() {
        return data.getJSONObject("config").getInt("MIN_PARTICIPANTS");
    }

    public int maxParticipants() {
        return data.getJSONObject("config").getInt("MAX_PARTICIPANTS");
    }

    public int[] participants() {
        String[] ids = data.getJSONObject("round_one_outputs").getString("participant_list").split(",");
        int[] result = new int[ids.length];
        for(int i = 0; i < ids.length; ++i) {
            result[i] = Integer.parseInt(ids[i]);
        }
        return result;
    }

    public byte[] secret(int identifier) {
        return Hex.decode(data.getJSONObject("inputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("participant_share"));
    }

    public byte[] groupKey() {
        return Hex.decode(data.getJSONObject("inputs").getString("group_public_key"));
    }

    public byte[] hidingCommitment(int identifier) {
        return Hex.decode(data.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("hiding_nonce_commitment"));
    }

    public byte[] bindingCommitment(int identifier) {
        return Hex.decode(data.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("binding_nonce_commitment"));
    }

    public byte[] hidingRandomness(int identifier) {
        return Hex.decode(data.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("hiding_nonce_randomness"));
    }

    public byte[] bindingRandomness(int identifier) {
        return Hex.decode(data.getJSONObject("round_one_outputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("binding_nonce_randomness"));
    }

    public byte[] message() {
        return Hex.decode(data.getJSONObject("inputs").getString("message"));
    }

    public byte[] signature(int identifier) {
        return Hex.decode(data.getJSONObject("round_two_outputs").getJSONObject("participants").getJSONObject(String.valueOf(identifier)).getString("sig_share"));
    }
}
