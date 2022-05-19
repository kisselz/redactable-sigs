package rss.sets;

import java.security.Signature;
import rss.SignatureKeyPair;
import rss.RedactableSignature;

public class KisselSetSignature extends RedactableSignature
{
  public KisselSetSignature()
  {

  }

  public SignatureKeyPair keyGen(int secParam)
  {
    return new SignatureKeyPair();
  }

  public byte[] sign(byte[] sk, byte[] msg)
  {
    return null;
  }

  public  boolean vrfy(byte[] vk, byte[] sig, byte msg)
  {
    return false;
  }

  public byte[] redact(byte[] msg1, byte[] msg2, byte[] sig)
  {
    return null;
  }
}
