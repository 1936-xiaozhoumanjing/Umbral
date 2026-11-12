package io.umbral.flash;

/** cpio 条目 */
class Entry {
    String name;
    int mode;
    int uid;
    int gid;
    int nlink;
    int mtime;

    int devMajor;
    int devMinor;
    int rdevMajor;
    int rdevMinor;

    byte[] data;

    Entry() {
        uid = 0;
        gid = 0;
        nlink = 1;
        mtime = 0;
        devMajor = 0;
        devMinor = 0;
        rdevMajor = 0;
        rdevMinor = 0;
    }
}
