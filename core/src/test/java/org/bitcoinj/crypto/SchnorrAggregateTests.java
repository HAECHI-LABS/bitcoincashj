package org.bitcoinj.crypto;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Utils;
import org.bitcoinj.params.MainNetParams;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Scanner;

import static org.junit.Assert.assertEquals;

public class SchnorrAggregateTests {
    @Test
    public void aggregateAddress() {
        //Taken from Mark, Chris Pacia, and checksum0 3-of-3 multisig
        //https://gist.github.com/checksum0/47d5ee7ee513a9d2e9fcb0b2761c7c73
        String checksumPrivKeyString = "a145c109b44521329421227a7d29b4bcbb4e75a37743435d2978c02cbb45842f";
        String paciaPrivKeyString = "3c33570f986612912464cc61259ceeeba18c2c494e9de505a78c4222277d1b56";
        String markPrivKeyString = "8426999585720f236608b8a7112759f93269acf1124b0f82edbfa862cc8a6d0d";
        ECKey checksumEcKey = ECKey.fromPrivate(Hex.decode(checksumPrivKeyString));
        ECKey paciaEcKey = ECKey.fromPrivate(Hex.decode(paciaPrivKeyString));
        ECKey markEcKey = ECKey.fromPrivate(Hex.decode(markPrivKeyString));
        ArrayList<byte[]> otherPubKeys = new ArrayList<byte[]>();
        otherPubKeys.add(paciaEcKey.getPubKey());
        otherPubKeys.add(markEcKey.getPubKey());

        //In this example, "we" are checksum
        BigInteger[] aggregatePoint = SchnorrSignature.point_from_bytes(checksumEcKey.getPubKey());
        for(byte[] pubKey : otherPubKeys) {
            BigInteger[] otherPoint = SchnorrSignature.point_from_bytes(pubKey);
            aggregatePoint = SchnorrSignature.point_add(aggregatePoint, otherPoint);
        }

        byte[] aggregatePublicKey = SchnorrSignature.bytes_from_point(aggregatePoint);
        byte[] aggregatePubKeyHash = Utils.sha256hash160(aggregatePublicKey);
        Address aggregateAddress = Address.fromP2PKHHash(MainNetParams.get(), aggregatePubKeyHash);
        String aggregateCashAddress = aggregateAddress.toCash().toString();
        assertEquals("bitcoincash:qr2n5jt6sfnd06ts25l9dqg2sycc8q6qvv6eyk65lq", aggregateCashAddress);
    }
}
