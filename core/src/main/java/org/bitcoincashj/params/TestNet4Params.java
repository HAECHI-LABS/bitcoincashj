/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoincashj.params;

import org.bitcoincashj.core.Block;
import org.bitcoincashj.core.Sha256Hash;
import org.bitcoincashj.core.Utils;

import java.math.BigInteger;
import java.util.Date;

import static com.google.common.base.Preconditions.checkState;

/**
 * Parameters for the testnet, a separate public instance of Bitcoin that has relaxed rules suitable for development
 * and testing of applications and new Bitcoin versions.
 */
public class TestNet4Params extends AbstractBitcoinNetParams {
    public static final int TESTNET_MAJORITY_WINDOW = 100;
    public static final int TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED = 75;
    public static final int TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 51;

    public TestNet4Params() {
        super();
        id = ID_TESTNET4;
        packetMagic = 0xe2b7daafL;
        targetTimespan = TARGET_TIMESPAN;
        interval = targetTimespan / TARGET_SPACING;
        maxTarget = Utils.decodeCompactBits(0x1d00ffffL);
        port = 28333;
        addressHeader = 111;
        p2shHeader = 196;
        acceptableAddressCodes = new int[]{addressHeader, p2shHeader};
        dumpedPrivateKeyHeader = 239;
        genesisBlock.setTime(1597811185L);
        genesisBlock.setDifficultyTarget(0x1d00ffffL);
        genesisBlock.setNonce(114152193);
        spendableCoinbaseDepth = 100;
        defaultPeerCount = 4;
        String genesisHash = genesisBlock.getHashAsString();
        checkState(genesisHash.equals("000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b"));

        checkpoints.put(0, Sha256Hash.wrap(genesisHash));
        checkpoints.put(5000, Sha256Hash.wrap("000000009f092d074574a216faec682040a853c4f079c33dfd2c3ef1fd8108c4"));
        checkpoints.put(16845, Sha256Hash.wrap("00000000fb325b8f34fe80c96a5f708a08699a68bbab82dba4474d86bd743077"));

        dnsSeeds = new String[]{
                "testnet4-seed-bch.bitcoinforks.org",
                "testnet4-seed-bch.toom.im",
                "seed.tbch4.loping.net",
                "testnet4-seed.flowee.cash"
        };
        httpSeeds = null;
        addrSeeds = new String[] {
                "66.172.112.151",
                "66.172.112.154",
                "66.172.112.251",
                "66.172.112.252",
                "45.33.41.87",
                "172.104.34.214",
                "193.135.10.219"
        };
        bip32HeaderP2PKHpub = 0x043587cf; // The 4 byte header that serializes in base58 to "tpub".
        bip32HeaderP2PKHpriv = 0x04358394; // The 4 byte header that serializes in base58 to "tprv"

        majorityEnforceBlockUpgrade = TESTNET_MAJORITY_ENFORCE_BLOCK_UPGRADE;
        majorityRejectBlockOutdated = TESTNET_MAJORITY_REJECT_BLOCK_OUTDATED;
        majorityWindow = TESTNET_MAJORITY_WINDOW;
        asertReferenceBlockBits = 0x1d00ffff;
        asertReferenceBlockHeight = BigInteger.valueOf(16844L);
        asertReferenceBlockAncestorTime = BigInteger.valueOf(1605451779L);
        asertUpdateTime = 1605441600L;
        // Aug, 1 hard fork
        uahfHeight = 7;
        // Nov, 13 hard fork
        daaUpdateHeight = 3000;
        cashAddrPrefix = "bchtest";
        simpleledgerPrefix = "slptest";

        asertHalfLife = 60L * 60L;
        allowMinDifficultyBlocks = true;
        //1.2 MB
        maxBlockSize = 2000 * 1000;
        maxBlockSigops = maxBlockSize / 50;

    }

    private static TestNet4Params instance;

    public static synchronized TestNet4Params get() {
        if (instance == null) {
            instance = new TestNet4Params();
        }
        return instance;
    }

    @Override
    public String getPaymentProtocolId() {
        return PAYMENT_PROTOCOL_ID_TESTNET4;
    }

    // February 16th 2012
    private static final Date testnetDiffDate = new Date(1329264000000L);

    public static boolean isValidTestnetDateBlock(Block block) {
        return block.getTime().after(testnetDiffDate);
    }
}
