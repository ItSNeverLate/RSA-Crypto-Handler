package com.mehdiparsaei.rsa_demo

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.Cipher

class RSA {
    private var privateKey: PrivateKey? = null
    private var publicKey: PublicKey? = null

    @Throws(Exception::class)
    fun encrypt(message: String): String {
        val messageToBytes = message.toByteArray()
        val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes: ByteArray = cipher.doFinal(messageToBytes)
        return encode(encryptedBytes)
    }

    private fun encode(data: ByteArray): String {
        return Base64.getEncoder().encodeToString(data)
    }

    @Throws(Exception::class)
    fun decrypt(encryptedMessage: String): String {
        val encryptedBytes = decode(encryptedMessage)
        val cipher: Cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val decryptedMessage: ByteArray = cipher.doFinal(encryptedBytes)
        return String(decryptedMessage)
    }

    private fun decode(data: String): ByteArray {
        return Base64.getDecoder().decode(data)
    }

    init {
        try {
            val generator: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
            generator.initialize(1024)
            val pair: KeyPair = generator.generateKeyPair()
            privateKey = pair.getPrivate()
            publicKey = pair.getPublic()
        } catch (ignored: Exception) {
        }
    }
}


fun main() {
    val rsa = RSA()
    try {
        val encryptedMessage = rsa.encrypt("Hello World")
        val decryptedMessage = rsa.decrypt(encryptedMessage)
        System.err.println("Encrypted:\n$encryptedMessage")
        System.err.println("Decrypted:\n$decryptedMessage")
    } catch (ingored: Exception) {
    }
}
