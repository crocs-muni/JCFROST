package jcfrost;

import static jcfrost.JCFROST.POINT_SIZE;

public class FrostCommitment {
    public byte identifier;
    public byte[] hiding = new byte[POINT_SIZE];
    public byte[] binding = new byte[POINT_SIZE];
}
