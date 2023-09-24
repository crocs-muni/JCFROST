# JCFROST

JCFROST is a JavaCard implementation of FROST threshold signature scheme using public JavaCard API complying with the [IRTF standardization draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-frost/).

## Getting Started

This implementation is intended mainly for demonstration and is not intended for production use as a standalone applet. It includes only the code to execute the protocol and produce a signature share.

The implementation can be integrated with other applets, but be aware that the underlying [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib) is not constant time, and thus can be compromised by an attacker who can measure the timing of operations with sufficient precision. It may be used only as an additional security factor in cases where it can only improve security.

### Building the Applet

To build the applet, clone this repository with submodules, set your card type in [the main applet](applet/src/main/java/jcfrost/JCFROST.java#L8) file on [line 8](applet/src/main/java/jcfrost/JCFROST.java#L8), and run:

```
./gradlew buildJavaCard
```

The resulting cap file can be found in `applet/build/javacard/jcfrost.cap`.

### Testing

Tests can be run using the following command. If you followed the instructions in the [Building the Applet](#building-the-applet) section, installed the applet on a card, and have it connected, the tests will run on the smartcard; otherwise, it will run in a simulator.

```
./gradlew test
```

If you have multiple readers, you may have to select a different index in the [BaseText.java](applet/src/test/java/tests/BaseTest.java#L70) file.

## Further Information

### Performance Measurement

For the version and configuration of the applet that was used for measurement and the results see `measurement/*` branches. The measurement was performed with modified [JCProfilerNext](https://github.com/lzaoral/JCProfilerNext) that before each measurement samples inputs to the protocol randomly and sets them using the applet instructions, and only after that starts profiling of the signature round.

### APDU Interface

The applet responds to the following APDUs.

| Name         | CLA   | INS   | P1           | P2         | Data                                                           |
| :---         | :---: | :---: | :---:        | :---:      | :---                                                           |
| `INITIALIZE` | 0x00  | 0x00  | 0x00         | 0x00       | ---                                                            |
| `SETUP`      | 0x00  | 0x01  | t            | n          | card index + secret key share + group public key               |
| `COMMIT`     | 0x00  | 0x02  | data length  | 0x00       | --- or randomness used to fix nonce generation (in debug mode) |
| `COMMITMENT` | 0x00  | 0x03  | `idx`        | 0x00       | hiding commitment + binding commitment of party `idx`          |
| `SIGN`       | 0x00  | 0x04  | msg length   | 0x00       | message                                                        |
| `RESET`      | 0x00  | 0x05  | 0x00         | 0x00       | ---                                                            |
| `GROUP_KEY`  | 0x00  | 0x06  | 0x00         | 0x00       | ---                                                            |

The applet expects that commitments supplied by the `COMMITMENT` instruction are ordered by party `idx`, including the card's commitments.
