package com.xop.rn;

import com.facebook.react.bridge.*;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;

public final class XopRaspModule extends ReactContextBaseJavaModule {
    public XopRaspModule(ReactApplicationContext context) { super(context); }
    @Override public String getName() { return "XopRasp"; }
    @ReactMethod public void getStatus(Promise promise) {
        WritableMap result = Arguments.createMap();
        result.putBoolean("protected", XopRuntime.isProtected(getReactApplicationContext()));
        result.putBoolean("canStartSensitiveOperation", XopRuntime.canStart());
        promise.resolve(result);
    }
    @ReactMethod public void getThreatReports(Promise promise) {
        try { promise.resolve(XopRuntime.invoke("drainThreatReports")); }
        catch (Exception | LinkageError e) { promise.reject("E_RASP_UNAVAILABLE", "Protection runtime unavailable"); }
    }
    @ReactMethod public void addListener(String name) {}
    @ReactMethod public void removeListeners(double count) {}

    /** Call on native-module queue before starting an operation, never from a USB transfer callback. */
    public static boolean allowOperation(ReactApplicationContext context, boolean required) {
        if (!required && !XopRuntime.isProtected(context)) return true;
        if (XopRuntime.canStart()) return true;
        String message = "Security check prevented a new vehicle operation. Existing transfers are not stopped.";
        new Handler(Looper.getMainLooper()).post(() ->
            Toast.makeText(context, message, Toast.LENGTH_LONG).show());
        if (context.hasActiveCatalystInstance()) {
            WritableMap event = Arguments.createMap();
            event.putString("code", "E_RASP_RESTRICTED");
            event.putString("message", message);
            context.getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
                .emit("XopOperationBlocked", event);
        }
        return false;
    }
}
