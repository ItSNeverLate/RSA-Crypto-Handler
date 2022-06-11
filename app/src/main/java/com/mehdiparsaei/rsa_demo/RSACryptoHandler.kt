package com.mehdiparsaei.rsa_demo

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

private const val TAG = "MainActivity"

object RSACryptoHandler {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val RSA_KEY_SIZE = 2048

    private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    private val keyPairGenerator: KeyPairGenerator =
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }
    private val oaepParamSpec = OAEPParameterSpec(
        "SHA-256",
        "MGF1",
        MGF1ParameterSpec("SHA-1"),
        PSource.PSpecified.DEFAULT
    )

    private fun getParameterSpec(alias: String) = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    ).apply {
        setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
        setKeySize(RSA_KEY_SIZE)
    }.build()

    private fun generateKeyPair(alias: String) {
        with(keyPairGenerator) {
            initialize(getParameterSpec(alias))
            genKeyPair()
        }
    }

    private fun createIfNotExists(alias: String) {
        if (!keyStore.containsAlias(alias) || keyStore.getCertificate(alias) == null) {
            generateKeyPair(alias)
        }
    }

    private fun getPublicKey(alias: String): PublicKey {
        createIfNotExists(alias)
        return keyStore.getCertificate(alias).publicKey
    }

    fun getPublicKeyPEM(keyId: String) =
        "-----BEGIN PUBLIC KEY-----\n${
            Base64.encodeToString(
                getPublicKey(keyId).encoded,
                Base64.DEFAULT
            )
        }-----END PUBLIC KEY-----"

    private fun getPrivatKey(alias: String): Key {
        createIfNotExists(alias)
        return keyStore.getKey(alias, null)
    }

    fun encryptData(data: ByteArray, keyId: String): ByteArray {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, getPublicKey(keyId),oaepParamSpec)
        }
        return cipher.doFinal(data)
    }

    fun decryptData(data: ByteArray, keyId: String): ByteArray {
        val cipher: Cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getPrivatKey(keyId), oaepParamSpec)
        }
        return cipher.doFinal(data)
    }
}