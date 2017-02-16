package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.junit.Test;

import net.i2p.crypto.eddsa.Utils;

import org.interledger.cryptoconditions.encoding.FulfillmentInputStream;
import org.interledger.cryptoconditions.encoding.OerDecodingException;
import org.interledger.cryptoconditions.types.*;

// TODO:(0) Complete tests
public class TestEd25519Fulfillment {

    static {
        Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();
    }

    final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");
    static final byte[] TEST_PK = Utils.hexToBytes("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
    static final byte[] TEST_MSG = "Hello World! Conditions are here!".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_INPUT_STREAM_FF_OK = Utils.hexToBytes(
            "000460ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bfb62291fad9432f8f298b9c4a4895dbe293f6ffda1a68dadf0ccdef5f47a0c7212a5fea3cda97a3f4c03ea9f2e8ac1cec86a51d452127abdba09d1b6f331c070a");
    static final byte[] TEST_INPUT_STREAM_FF_WRONG = Utils.hexToBytes(
            "000460ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf3a727b27c60beb9ab68b8fe29860fca856c38580ca2f5a9c35d01aa64c3aa5dc336ef4606834f547b3f9c0ed4ed95ca15cc78a641e90ded99d737b38be68030e");

    static final byte[] TEST_KO_MSG = "This is a wrong secret message".getBytes(Charset.forName("UTF-8"));
    static final byte[] TEST_MSG_SIG = Utils.hexToBytes(
            "94825896c7075c31bcb81f06dba2bdcd9dcf16e79288d4b9f87c248215c8468d475f429f3de3b4a2cf67fe17077ae19686020364d6d4fa7a0174bab4a123ba0f");
    static final byte[] TEST_KO_MSG_SIG = Utils.hexToBytes(
            "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");

    static final String FF_OK_URI = "cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK";

    private Fulfillment getPayload(byte[] ffOEREncoded) throws IOException, UnsupportedConditionException, OerDecodingException {
        ByteArrayInputStream auxi = new ByteArrayInputStream(ffOEREncoded);
        FulfillmentInputStream ffOut = new FulfillmentInputStream(auxi);
        Fulfillment result = ffOut.readFulfillment();

        ffOut.close();
        return result;
    }

    @Test
    public void testEd25519Fulfillment() throws IOException, UnsupportedConditionException, OerDecodingException {
        // Build from stream
        System.out.println("testEd25519Fulfillment start:");
        Fulfillment ff_ok = getPayload(TEST_INPUT_STREAM_FF_OK);
        assertTrue(FF_OK_URI.equals(ff_ok.toURI()));
        ff_ok.getCondition();
        assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));
        assertFalse("Fulfillment validates TEST_KO_MSG", ff_ok.validate(new MessagePayload(TEST_KO_MSG)));

        Fulfillment ff_wrong = getPayload(TEST_INPUT_STREAM_FF_WRONG);
        ff_wrong.getCondition();
        assertFalse("Fulfillment does not validates TEST_MSG", ff_wrong.validate(new MessagePayload(TEST_MSG)));
        assertFalse("Fulfillment does not validates TEST_KO_MSG", ff_wrong.validate(new MessagePayload(TEST_KO_MSG)));

        // Build from URI
        ff_ok = FulfillmentFactory.getFulfillmentFromURI(FF_OK_URI);
        assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

        // Build from secret
        ff_ok = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_MSG));
        ff_ok.getCondition();
        assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

        ff_ok = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_KO_MSG));
        ff_ok.getCondition();
        assertFalse("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

    }

}
