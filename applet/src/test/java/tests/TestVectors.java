package tests;

import org.bouncycastle.util.encoders.Hex;
import org.json.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class TestVectors {
    private JSONObject data;

    public TestVectors(String path) throws IOException {
        data = new JSONObject(new String(Files.readAllBytes(new File(path).toPath())));
    }

    public int minParticipants() {
        return data.getJSONObject("config").getInt("MIN_PARTICIPANTS");
    }

    public int maxParticipants() {
        return data.getJSONObject("config").getInt("MAX_PARTICIPANTS");
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

    public byte[] message() {
        return Hex.decode(data.getJSONObject("inputs").getString("message"));
    }
}
