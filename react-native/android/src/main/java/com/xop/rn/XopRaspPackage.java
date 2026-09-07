package com.xop.rn;
import com.facebook.react.ReactPackage;
import com.facebook.react.bridge.*;
import com.facebook.react.uimanager.ViewManager;
import java.util.*;
public final class XopRaspPackage implements ReactPackage {
    @Override public List<NativeModule> createNativeModules(ReactApplicationContext context) {
        return Collections.<NativeModule>singletonList(new XopRaspModule(context));
    }
    @Override public List<ViewManager> createViewManagers(ReactApplicationContext context) {
        return Collections.emptyList();
    }
}
