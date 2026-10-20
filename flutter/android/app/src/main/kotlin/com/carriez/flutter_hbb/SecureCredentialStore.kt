package com.carriez.flutter_hbb

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts LAN access credentials with a non-exportable Android Keystore key.
 *
 * Only the Rust core calls this class, through JNI, so a plaintext password never
 * enters the Dart layer. Every value is stored as `Base64(iv || AES-GCM
 * ciphertext)` inside private shared preferences; the encryption key cannot be
 * exported from the Keystore.
 */
object SecureCredentialStore {
    private const val TAG = "SecureCredentialStore"
    private const val PREFERENCES = "subnetdesk_secure_credentials"
    private const val KEY_ALIAS = "subnetdesk_lan_credentials_v1"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128
    private const val IV_BYTES = 12

    @Volatile
    private var cachedKey: SecretKey? = null

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    @Synchronized
    private fun secretKey(): SecretKey {
        cachedKey?.let { return it }
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: generateKey()
        cachedKey = key
        return key
    }

    private fun generateKey(): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey() as SecretKey
    }

    @JvmStatic
    fun put(context: Context, entry: String, value: String): Boolean {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey())
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            val blob = ByteArray(iv.size + ciphertext.size)
            iv.copyInto(blob, 0)
            ciphertext.copyInto(blob, iv.size)
            preferences(context)
                .edit()
                .putString(entry, Base64.encodeToString(blob, Base64.NO_WRAP))
                .commit()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to store a LAN credential", e)
            false
        }
    }

    @JvmStatic
    fun get(context: Context, entry: String): String? {
        val encoded = preferences(context).getString(entry, null) ?: return null
        return try {
            val blob = Base64.decode(encoded, Base64.NO_WRAP)
            require(blob.size > IV_BYTES) { "Credential blob is too short" }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey(),
                GCMParameterSpec(GCM_TAG_BITS, blob, 0, IV_BYTES)
            )
            String(cipher.doFinal(blob, IV_BYTES, blob.size - IV_BYTES), Charsets.UTF_8)
        } catch (e: Exception) {
            // A restored backup, a cleared Keystore or a rotated key leaves an
            // undecryptable blob behind. Drop it so the user is asked again
            // instead of being stuck with a credential that can never work.
            Log.w(TAG, "Discarding an unreadable LAN credential", e)
            preferences(context).edit().remove(entry).commit()
            null
        }
    }

    @JvmStatic
    fun remove(context: Context, entry: String): Boolean {
        return try {
            preferences(context).edit().remove(entry).commit()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete a LAN credential", e)
            false
        }
    }
}
