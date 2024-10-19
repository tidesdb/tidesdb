package tidesdb;

public class TidesDB {
    static {
        System.loadLibrary("tidesdb_jni");
    }

    public static class LSMT {
        private long ptr;

        public LSMT(String directory, int memtableFlushSize, int compactionInterval, int maxCompactionThreads) {
            this.ptr = newLSMT(directory, memtableFlushSize, compactionInterval, maxCompactionThreads);
        }

        public native long newLSMT(String directory, int memtableFlushSize, int compactionInterval, int maxCompactionThreads);
        public native void delete(long ptr);
        public native int put(long ptr, byte[] key, byte[] value);
        public native byte[] get(long ptr, byte[] key);
        public native int deleteKey(long ptr, byte[] key);
        public native void close(long ptr);
        public native long beginTransaction(long ptr);
        public native int commitTransaction(long ptr, long txPtr);
        public native void rollbackTransaction(long ptr, long txPtr);
        public native void addDelete(long txPtr, byte[] key, byte[] value);
        public native void addPut(long txPtr, byte[] key, byte[] value);

        public void delete() {
            delete(this.ptr);
        }

        public int put(byte[] key, byte[] value) {
            return put(this.ptr, key, value);
        }

        public byte[] get(byte[] key) {
            return get(this.ptr, key);
        }

        public int deleteKey(byte[] key) {
            return deleteKey(this.ptr, key);
        }

        public void close() {
            close(this.ptr);
        }

        public Transaction beginTransaction() {
            return new Transaction(beginTransaction(this.ptr));
        }

        public int commitTransaction(Transaction tx) {
            return commitTransaction(this.ptr, tx.ptr);
        }

        public void rollbackTransaction(Transaction tx) {
            rollbackTransaction(this.ptr, tx.ptr);
        }
    }

    public static class Transaction {
        private long ptr;

        public Transaction(long ptr) {
            this.ptr = ptr;
        }

        public void addDelete(byte[] key, byte[] value) {
            addDelete(this.ptr, key, value);
        }

        public void addPut(byte[] key, byte[] value) {
            addPut(this.ptr, key, value);
        }
    }

    public static class Wal {
        private long ptr;

        public Wal(String path) {
            this.ptr = newWalWithPath(path);
        }

        public native long newWalWithPath(String path);
        public native int recover(long walPtr, long lsmtPtr);
        public native void close(long walPtr);

        public int recover(LSMT lsmt) {
            return recover(this.ptr, lsmt.ptr);
        }

        public void close() {
            close(this.ptr);
        }
    }
}