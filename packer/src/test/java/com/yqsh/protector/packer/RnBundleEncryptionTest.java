package com.yqsh.protector.packer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import static org.junit.jupiter.api.Assertions.*;

class RnBundleEncryptionTest {
    @TempDir Path root;
    @Test void requiresAdapter() {
        assertThrows(IllegalStateException.class,
            () -> AssetsEncryptor.encryptRnBundle(root.toFile(), new byte[16]));
    }
    @Test void protectsBinaryBundleAndPreservesOtherAssets() throws Exception {
        Path assets = Files.createDirectories(root.resolve("assets"));
        Files.writeString(assets.resolve("xop-rn-adapter-v1"), "1");
        byte[] binary = new byte[]{0, -1, 32, -128, 0, 42};
        Files.write(assets.resolve("index.android.bundle"), binary);
        Files.writeString(assets.resolve("vehicle-config.xml"), "untouched");
        var result = AssetsEncryptor.encryptRnBundle(root.toFile(), new byte[16]);
        assertEquals(1, result.encrypted);
        assertFalse(Files.exists(assets.resolve("index.android.bundle")));
        assertEquals("untouched", Files.readString(assets.resolve("vehicle-config.xml")));
        byte[] encrypted = Files.readAllBytes(assets.resolve("protector/aenc/index.android.bundle"));
        assertArrayEquals(AssetsEncryptor.MAGIC, Arrays.copyOf(encrypted, 4));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[16], "AES"),
            new GCMParameterSpec(128, Arrays.copyOfRange(encrypted, 4, 16)));
        assertArrayEquals(binary, cipher.doFinal(Arrays.copyOfRange(encrypted, 16, encrypted.length)));
        encrypted[encrypted.length-1] ^= 1;
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(new byte[16], "AES"),
            new GCMParameterSpec(128, Arrays.copyOfRange(encrypted, 4, 16)));
        assertThrows(Exception.class, () -> cipher.doFinal(Arrays.copyOfRange(encrypted, 16, encrypted.length)));
    }
    @Test void explicitCliFlag() throws Exception {
        assertTrue(PackerMain.parseArgs(new String[]{"in.apk", "--encrypt-rn-bundle"}).encryptRnBundle);
        assertThrows(IllegalArgumentException.class, () -> PackerMain.parseArgs(
            new String[]{"in.apk", "--encrypt-rn-bundle", "--encrypt-assets"}));
    }
}
