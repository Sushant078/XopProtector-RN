package com.xop.rn;

import android.content.Context;
import android.system.Os;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Arrays;

/** Binary-preserving Hermes/JS loader. Private plaintext file remains a documented limitation. */
public final class XopBundleLoader {
    private static volatile String bundleFile;
    private XopBundleLoader() {}
    public static synchronized void prepare(Context context) {
        if (bundleFile != null) return;
        if (!XopRuntime.isProtected(context)) return; // Unprotected baseline / Metro.
        try (InputStream marker = context.getAssets().open("protector/aenc/index.android.bundle")) {
            // Existence only; decryption errors below must not fall back to stale/plain content.
        } catch (java.io.IOException notEncrypted) { return; }
        byte[] bytes = null;
        File temporary = null;
        try {
            Method read = Class.forName("com.yqsh.protector.shell.ProtectorAssets")
                .getMethod("readBytes", Context.class, String.class);
            bytes = (byte[]) read.invoke(null, context, "index.android.bundle");
            File directory = new File(context.getNoBackupFilesDir(), "xop-rn");
            if (!directory.isDirectory() && !directory.mkdirs()) throw new java.io.IOException("bundle directory");
            Os.chmod(directory.getAbsolutePath(), 0700);
            File target = new File(directory, "index.android.bundle");
            temporary = File.createTempFile("bundle-", ".tmp", directory);
            Os.chmod(temporary.getAbsolutePath(), 0600);
            try (FileOutputStream out = new FileOutputStream(temporary)) {
                out.write(bytes);
                out.getFD().sync();
            }
            // Re-decrypt and replace every process start: no stale cache after upgrades.
            Os.rename(temporary.getAbsolutePath(), target.getAbsolutePath());
            bundleFile = target.getAbsolutePath();
        } catch (Exception error) {
            throw new IllegalStateException("Protected RN bundle could not be loaded", error);
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
            if (temporary != null) temporary.delete();
        }
    }
    public static String getBundleFile() { return bundleFile; }
}
