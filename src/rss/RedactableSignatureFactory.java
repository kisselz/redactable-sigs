package rss;

import rss.sets.KisselSetSignature;

/**
 * This object implements a redactble signature scheme factory.
 * @author Zach Kissel
 */
 public class RedactableSignatureFactory
 {
   public static RedactableSignature getRedactableSignature(String mechanism)
   {
     if (mechanism.equals("kissel-set"))
      return new KisselSetSignature();
    return null;
   }
 }
