package com.mehdiparsaei.rsa_demo

import android.os.Bundle
import android.util.Base64
import android.util.Log
import androidx.appcompat.app.AppCompatActivity

private const val TAG = "MainActivity"

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val keyId = "3"

        Log.d(TAG, "public key PEM: ${RSACryptoHandler.getPublicKeyPEM(keyId)}")

        val plainData = "Hello!".toByteArray()
        Log.d(TAG, "plainText: ${Base64.encodeToString(plainData, Base64.DEFAULT)}")
        val encryptedData = RSACryptoHandler.encryptData(plainData, keyId)
        Log.d(
            TAG,
            "encryptedData: ${Base64.encodeToString(encryptedData, Base64.DEFAULT)}"
        )
        try {
            val decryptedData = RSACryptoHandler.decryptData(encryptedData, keyId)
            Log.d(
                TAG,
                "decryptedData: ${Base64.encodeToString(decryptedData, Base64.DEFAULT)}"
            )
        } catch (ex: Exception) {
            Log.e(
                TAG,
                "Exception: $ex"
            )
        }
    }
}