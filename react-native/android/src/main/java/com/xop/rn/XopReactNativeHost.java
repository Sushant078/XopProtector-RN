/*
 * Host builder adapted from React Native 0.68 ReactNativeHost.java.
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the MIT license; see react-native/REACT_NATIVE_LICENSE.
 */
package com.xop.rn;

import android.app.Application;
import com.facebook.react.*;
import com.facebook.react.bridge.JSBundleLoader;
import com.facebook.react.bridge.ReactMarker;
import com.facebook.react.bridge.ReactMarkerConstants;
import com.facebook.react.common.LifecycleState;

/** RN 0.68 host adapter. Retains the asset source URL for Android drawable resolution. */
public abstract class XopReactNativeHost extends ReactNativeHost {
    public XopReactNativeHost(Application application) { super(application); }
    @Override protected ReactInstanceManager createReactInstanceManager() {
        if (XopBundleLoader.getBundleFile() == null) return super.createReactInstanceManager();
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_START);
        ReactInstanceManagerBuilder builder = ReactInstanceManager.builder()
            .setApplication(getApplication())
            .setJSMainModulePath(getJSMainModuleName())
            .setUseDeveloperSupport(getUseDeveloperSupport())
            .setDevSupportManagerFactory(getDevSupportManagerFactory())
            .setRequireActivity(getShouldRequireActivity())
            .setSurfaceDelegateFactory(getSurfaceDelegateFactory())
            .setRedBoxHandler(getRedBoxHandler())
            .setJavaScriptExecutorFactory(getJavaScriptExecutorFactory())
            .setUIImplementationProvider(getUIImplementationProvider())
            .setJSIModulesPackage(getJSIModulePackage())
            .setInitialLifecycleState(LifecycleState.BEFORE_CREATE)
            .setReactPackageTurboModuleManagerDelegateBuilder(getReactPackageTurboModuleManagerDelegateBuilder());
        for (ReactPackage reactPackage : getPackages()) builder.addPackage(reactPackage);
        builder.setJSBundleLoader(JSBundleLoader.createFileLoader(
            XopBundleLoader.getBundleFile(), "assets://index.android.bundle", false));
        ReactInstanceManager manager = builder.build();
        ReactMarker.logMarker(ReactMarkerConstants.BUILD_REACT_INSTANCE_MANAGER_END);
        return manager;
    }
}
