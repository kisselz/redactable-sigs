package rss;

/**
 * This class serves as the super class for all redactable signature schemes.
 * @author Zach Kissel
 */
public abstract class RedactableSignature
{
  public abstract SignatureKeyPair keyGen(int secParam);
  public abstract byte[] sign(byte[] sk, byte[] msg);
  public abstract boolean vrfy(byte[] vk, byte[] sig, byte msg);
  public abstract byte[] redact(byte[] msg1, byte[] msg2, byte[] sig);
}
