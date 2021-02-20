/*
 * Copyright by the original author or authors.
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

package org.bitcoinj.store;

import org.bitcoinj.core.*;
import org.fusesource.leveldbjni.JniDBFactory;
import org.iq80.leveldb.*;

import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * An SPV block store that writes every header it sees to a <a href="https://github.com/fusesource/leveldbjni">LevelDB</a>.
 * This allows for fast lookup of block headers by block hash at the expense of more costly inserts and higher disk
 * usage than the {@link SPVBlockStore}. If all you want is a regular wallet you don't need this class: it exists for
 * specialised applications where you need to quickly verify a standalone SPV proof.
 */
public class LevelDBBlockStore implements BlockStore {
    private static final byte[] CHAIN_HEAD_KEY = "chainhead".getBytes();

    private final Context context;
    private final ByteBuffer buffer = ByteBuffer.allocate(StoredBlock.COMPACT_SERIALIZED_SIZE);
    private final File path;
    private DB db;

    /**
     * Creates a LevelDB SPV block store using the JNI/C++ version of LevelDB.
     */
    public LevelDBBlockStore(Context context, File directory) throws BlockStoreException {
        this(context, directory, JniDBFactory.factory);
    }

    /**
     * Creates a LevelDB SPV block store using the given factory, which is useful if you want a pure Java version.
     */
    public LevelDBBlockStore(Context context, File directory, DBFactory dbFactory) throws BlockStoreException {
        this.context = context;
        this.path = directory;
        Options options = new Options();
        options.createIfMissing();

        try {
            tryOpen(directory, dbFactory, options);
        } catch (IOException e) {
            try {
                dbFactory.repair(directory, options);
                tryOpen(directory, dbFactory, options);
            } catch (IOException e1) {
                throw new BlockStoreException(e1);
            }
        }
    }

    private synchronized void tryOpen(File directory, DBFactory dbFactory, Options options) throws IOException, BlockStoreException {
        db = dbFactory.open(directory, options);
        initStoreIfNeeded();
    }

    private synchronized void initStoreIfNeeded() throws BlockStoreException {
        if (db.get(CHAIN_HEAD_KEY) != null)
            return;   // Already initialised.
        Block genesis = context.getParams().getGenesisBlock().cloneAsHeader();
        StoredBlock storedGenesis = new StoredBlock(genesis, genesis.getWork(), 0);
        put(storedGenesis);
        setChainHead(storedGenesis);
    }

    @Override
    public synchronized void put(StoredBlock block) throws BlockStoreException {
        buffer.clear();
        block.serializeCompact(buffer);
        db.put(block.getHeader().getHash().getBytes(), buffer.array());
    }

    @Override
    @Nullable
    public synchronized StoredBlock get(Sha256Hash hash) throws BlockStoreException {
        byte[] bits = db.get(hash.getBytes());
        if (bits == null)
            return null;
        return StoredBlock.deserializeCompact(context.getParams(), ByteBuffer.wrap(bits));
    }

    @Override
    public synchronized StoredBlock getChainHead() throws BlockStoreException {
        return get(Sha256Hash.wrap(db.get(CHAIN_HEAD_KEY)));
    }

    @Override
    public synchronized void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        db.put(CHAIN_HEAD_KEY, chainHead.getHeader().getHash().getBytes());
    }

    @Override
    public synchronized void close() throws BlockStoreException {
        try {
            db.close();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    /**
     * Erases the contents of the database (but NOT the underlying files themselves) and then reinitialises with the genesis block.
     */
    public synchronized void reset() throws BlockStoreException {
        try {
            try (WriteBatch batch = db.createWriteBatch(); DBIterator it = db.iterator()) {
                it.seekToFirst();
                while (it.hasNext())
                    batch.delete(it.next().getKey());
                db.write(batch);
            }
            initStoreIfNeeded();
        } catch (IOException e) {
            throw new BlockStoreException(e);
        }
    }

    public synchronized void destroy() throws IOException {
        JniDBFactory.factory.destroy(path, new Options());
    }

    @Override
    public NetworkParameters getParams() {
        return context.getParams();
    }
}
