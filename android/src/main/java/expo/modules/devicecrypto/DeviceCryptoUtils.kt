package expo.modules.devicecrypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

fun hkdfSha256(
  ikm: ByteArray,
  length: Int,
  salt: ByteArray? = null,
  info: ByteArray? = null
): ByteArray {
  val mac = Mac.getInstance("HmacSHA256")
  val actualSalt = salt ?: ByteArray(32)
  mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
  val prk = mac.doFinal(ikm)

  val result = ByteArray(length)
  var t = ByteArray(0)
  var offset = 0
  var counter = 1

  while (offset < length) {
    val macExpand = Mac.getInstance("HmacSHA256")
    macExpand.init(SecretKeySpec(prk, "HmacSHA256"))

    macExpand.update(t)
    if (info != null) macExpand.update(info)
    macExpand.update(counter.toByte())

    t = macExpand.doFinal()

    val toCopy = minOf(t.size, length - offset)
    System.arraycopy(t, 0, result, offset, toCopy)

    offset += toCopy
    counter++
  }

  return result
}
