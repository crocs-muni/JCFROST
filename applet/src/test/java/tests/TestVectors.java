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

    public int numParticipants() {
        return data.getJSONObject("config").getInt("NUM_PARTICIPANTS");
    }


    public int[] participants() {
        int[] result = new int[numParticipants()];
        int i = 0;
        for (Object participant_idx : data.getJSONObject("inputs").getJSONArray("participant_list")) {
            result[i] = (int) participant_idx;
            ++i;
        }
        return result;
    }

    public byte[] secret(int identifier) {
        for (Object participant_share : data.getJSONObject("inputs").getJSONArray("participant_shares")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("participant_share"));
            }
        }
        throw new IndexOutOfBoundsException();
    }

    public byte[] groupKey() {
        return Hex.decode(data.getJSONObject("inputs").getString("group_public_key"));
    }

    public byte[] hidingCommitment(int identifier) {
        for (Object participant_share : data.getJSONObject("round_one_outputs").getJSONArray("outputs")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("hiding_nonce_commitment"));
            }
        }
        throw new IndexOutOfBoundsException();
    }

    public byte[] bindingCommitment(int identifier) {
        for (Object participant_share : data.getJSONObject("round_one_outputs").getJSONArray("outputs")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("binding_nonce_commitment"));
            }
        }
        throw new IndexOutOfBoundsException();
    }

    public byte[] hidingRandomness(int identifier) {
        for (Object participant_share : data.getJSONObject("round_one_outputs").getJSONArray("outputs")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("hiding_nonce_randomness"));
            }
        }
        throw new IndexOutOfBoundsException();
    }

    public byte[] bindingRandomness(int identifier) {
        for (Object participant_share : data.getJSONObject("round_one_outputs").getJSONArray("outputs")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("binding_nonce_randomness"));
            }
        }
        throw new IndexOutOfBoundsException();
    }

    public byte[] message() {
        return Hex.decode(data.getJSONObject("inputs").getString("message"));
    }

    public byte[] signature(int identifier) {
        for (Object participant_share : data.getJSONObject("round_two_outputs").getJSONArray("outputs")) {
            JSONObject share = (JSONObject) participant_share;
            if (share.getInt("identifier") == identifier) {
                return Hex.decode(share.getString("sig_share"));
            }
        }
        throw new IndexOutOfBoundsException();
    }
}
