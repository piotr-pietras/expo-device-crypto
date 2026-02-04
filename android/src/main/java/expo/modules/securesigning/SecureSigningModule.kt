package expo.modules.securesigning

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyStore
import java.security.KeyPairGenerator
import java.security.KeyPair
import java.security.Signature
import android.security.keystore.KeyProperties
import android.security.keystore.KeyGenParameterSpec
import android.util.Base64
import android.content.pm.PackageManager
import android.content.pm.FeatureInfo

enum class SecureSigningModuleResult {
  KEY_PAIR_GENERATED,
  KEY_PAIR_ALREADY_EXISTS,
  NOT_AVAILABLE,
}

class SecureSigningModule : Module() {
  private fun isAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val appAttestKeystore = pm.hasSystemFeature(PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY)
    val hardwareKeystore = pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE)
    return appAttestKeystore && hardwareKeystore
  }

  private fun isStrongBoxAvailable(): Boolean {
    val pm = appContext.reactContext?.packageManager ?: return false
    val strongboxKeystore = pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    return strongboxKeystore
  }

  private fun getAliases() = KeyStore.getInstance("AndroidKeyStore").apply {
    load(null)
  }.aliases().toList()

  private fun getKeyStoreEntry(alias: String): KeyStore.Entry? {
    return KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }.getEntry(alias, null)
  }

  private fun retrievePublicKey(ks: KeyStore.Entry?): String? {
    if (ks !is KeyStore.PrivateKeyEntry) return null
    
    val publicKeyBytes: ByteArray = ks.certificate?.publicKey?.encoded ?: return null
    return Base64.encodeToString(publicKeyBytes, Base64.NO_WRAP)
  }

  private fun removeKeyStoreEntry(alias: String): Boolean {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply {
      load(null)
    }
    if (ks.getEntry(alias, null) == null) return false

    ks.deleteEntry(alias)
    return true
  }


  override fun definition() = ModuleDefinition {
    Name("SecureSigning")

    Function("generateKeyPair") { alias: String ->
      if (!isAvailable()) {
        return@Function SecureSigningModuleResult.NOT_AVAILABLE
      }
      if (getKeyStoreEntry(alias) != null) {
        return@Function SecureSigningModuleResult.KEY_PAIR_ALREADY_EXISTS
      }
      
      val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
      )

      val parameterSpec: KeyGenParameterSpec = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
      ).run {
        setDigests(KeyProperties.DIGEST_SHA256)
        setIsStrongBoxBacked(isStrongBoxAvailable())
        build()
      }
      kpg.initialize(parameterSpec)
      val kp = kpg.generateKeyPair()

      return@Function SecureSigningModuleResult.KEY_PAIR_GENERATED
    }

    Function("removeKeyPair") { alias: String ->
      return@Function removeKeyStoreEntry(alias)
    }

    Function("aliases") {
      return@Function getAliases()
    }

    Function("getPublicKey") { alias: String ->
      val entry = getKeyStoreEntry(alias)
      return@Function retrievePublicKey(entry)
    }

    Function("sign") { alias: String, data: String ->
      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) return@Function null
      
      val signature: ByteArray = Signature.getInstance("SHA256withECDSA").apply {
        initSign(entry.privateKey)
        update(data.toByteArray(Charsets.UTF_8))
      }.sign()
      return@Function Base64.encodeToString(signature, Base64.NO_WRAP)
    }

    Function("verify") { alias: String, data: String, signature: String ->
      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) return@Function null
      
      val valid: Boolean = Signature.getInstance("SHA256withECDSA").apply {
        initVerify(entry.certificate)
        update(data.toByteArray(Charsets.UTF_8))
      }.verify(Base64.decode(signature, Base64.NO_WRAP))
      return@Function valid
    }
  }
}
