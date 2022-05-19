package rss;

import java.util.Arrays;

/**
 * This class implements a basic signature key pair class. It assumes that
 * the signing key and verification key are represented as bytes.
 * @author Zach Kissel
 */
 public class SignatureKeyPair
 {
   byte[] sk;   // The signing key.
   byte[] vk;   // The verification key.

   /**
    * Constructor to build key pair (sk, vk).
    * @param sk the signing key.
    * @param vk the verification key.
    */
   public SignatureKeyPair(byte[] sk, byte[] vk)
   {
     this.sk = Arrays.copyOf(sk, sk.length);
     this.vk = Arrays.copyOf(vk, vk.length);
   }

   /**
    * The default constructor builds an empty key pair.
    */
   public SignatureKeyPair()
   {
     /* Empty */
   }

   /**
    * Returns the signing key to the caller.
    * @return sk the signing key.
    */
   public byte[] getSigningKey()
   {
     return sk;
   }

   /**
    * Returns the verification key to the caller.
    * @return vk the verification key.
    */
   public byte[] getVerificationKey()
   {
     return vk;
   }

   /**
    * Set the signing key to sk.
    * @param sk the signing key.
    */
   public void setSigningKey(byte[] sk)
   {
     this.sk = Arrays.copyOf(sk, sk.length);
   }

   /**
    * Set the verfication key to vk.
    * @param vk the verification key.
    */
   public void setVerificationKey(byte[] vk)
   {
     this.vk = Arrays.copyOf(vk, vk.length);
   }


 }
