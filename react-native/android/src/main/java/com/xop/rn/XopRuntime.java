package com.xop.rn;

import android.content.Context;
import java.io.InputStream;

/** API binding to the post-build shell; no duplicate shell DEX/AAR in the app. */
public final class XopRuntime {
    private XopRuntime() {}
    public static Object invoke(String name) throws Exception {
        return Class.forName("com.yqsh.protector.shell.JniBridge").getMethod(name).invoke(null);
    }
    public static boolean isProtected(Context context) {
        try (InputStream in = context.getAssets().open("protector/config.json")) {
            return true;
        } catch (java.io.IOException absent) {
            return false;
        }
    }
    public static boolean canStart() {
        try { return Boolean.TRUE.equals(invoke("canStartSensitiveOperation")); }
        catch (Exception | LinkageError unavailable) { return false; }
    }
}
