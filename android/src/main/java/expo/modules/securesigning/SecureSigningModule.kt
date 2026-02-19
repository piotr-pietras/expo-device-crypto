package expo.modules.securesigning

import android.content.pm.PackageManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.security.KeyPairGenerator
import java.security.KeyStore
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import expo.modules.kotlin.Promise
import java.security.Signature
import android.widget.Toast


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


  private fun showAuthPrompt(
    onSuccess: () -> Unit,
    onError: (String) -> Unit
  ) {
    val activity = appContext.currentActivity as? FragmentActivity ?: run {
      onError("No active FragmentActivity found")
      return
    }

    activity.runOnUiThread {
      val executor = ContextCompat.getMainExecutor(activity)
      val biometricPrompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {

          override fun onAuthenticationSucceeded(
            result: BiometricPrompt.AuthenticationResult
          ) {
            super.onAuthenticationSucceeded(result)
            onSuccess()
          }

          override fun onAuthenticationError(
            errorCode: Int,
            errString: CharSequence
          ) {
            super.onAuthenticationError(errorCode, errString)
            onError(errString.toString())
          }
        }
      )

      val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Unlock")
        .setSubtitle("Enter your PIN to continue")
        .setAllowedAuthenticators(
          BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        .build()

      biometricPrompt.authenticate(promptInfo)
    }
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
        setUserAuthenticationRequired(true)
        setUserAuthenticationParameters(
          0,
          KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
        build()
      }
      kpg.initialize(parameterSpec)
      kpg.generateKeyPair()

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

    AsyncFunction("sign") { alias: String, data: String, promise: Promise ->
      // val entry = getKeyStoreEntry(alias)
      // if (entry !is KeyStore.PrivateKeyEntry) return@AsyncFunction null
      
      // val signature: ByteArray = Signature.getInstance("SHA256withECDSA").apply {
      //   initSign(entry.privateKey)
      //   update(data.toByteArray(Charsets.UTF_8))
      // }.sign()
      // return@AsyncFunction Base64.encodeToString(signature, Base64.NO_WRAP)

      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) {
        promise.resolve(null)
        return@AsyncFunction
      }

      showAuthPrompt(
        onSuccess = {
          try {
            val signature = Signature.getInstance("SHA256withECDSA").apply {
              initSign(entry.privateKey)
              update(data.toByteArray(Charsets.UTF_8))
            }
            val signed = signature.sign()
            promise.resolve(Base64.encodeToString(signed, Base64.NO_WRAP))
            appContext.reactContext?.let { context ->
              Toast.makeText(context.applicationContext, Base64.encodeToString(signed, Base64.NO_WRAP), Toast.LENGTH_LONG).show()
            }
          } catch (e: Exception) {
            promise.reject("ERR_SIGN_FAILED", "Unable to sign payload", e)
          }
        },
        onError = { error ->
          promise.reject("ERR_AUTH_FAILED", error, null)
        }
      )
    }

    Function("verify") { alias: String, data: String, signature: String ->
      val entry = getKeyStoreEntry(alias)
      if (entry !is KeyStore.PrivateKeyEntry) return@Function null
      
      val valid: Boolean = Signature.getInstance("SHA256withECDSA").apply {
        initVerify(entry.certificate)
        update(data.toByteArray(Charsets.UTF_8))
      }.verify(Base64.decode(signature, Base64.NO_WRAP))
      return@Function true
    }
  }
}
