package datastructures.bloom;

import java.io.UnsupportedEncodingException;

/**
 * This file implements the Fowler–Noll–Vo (FNV) hash algorithm. Specifically,
 * FNV-1a.
 * @author Zach Kissel
 */
 public class FNVHash
 {
   private static final long FNV_OFFSET_BASIS_64 = 0xCBF29CE484222325L;
   private static final long FNV_PRIME_64 = 0x100000001B3L;
   private static final int FNV_OFFSET_BASIS_32 = 0x811C9DC5;
   private static final int FNV_PRIME_32 =  0x01000193;

   /**
    * Hashes a block of bytes into a 32-bit value.
    * @param data the array of bytes to hash.
    * @return the hash value as a 32-bit number.
    */
   public static int hash32(final byte[] data)
   {
     int hashValue = FNV_OFFSET_BASIS_32;

     for (int i = 0; i < data.length; i++)
     {
        hashValue = hashValue ^ ((int) data[i]);
        hashValue *= FNV_PRIME_32;
     }
     return hashValue;
   }

   /**
    * Hashes a string into a 32-bit value.
    * @param data the string to hash.
    * @return the hash value as a 32-bit number.
    */
   public static int hash32(final String data)
   {
     try
     {
       return hash32(data.getBytes("UTF-8"));
     }
     catch (UnsupportedEncodingException ex)
     {
       ex.printStackTrace();
       return -1;
     }
   }

   /**
    * Hashes a block of bytes into a 64-bit value.
    * @param data the array of bytes to hash.
    * @return the hash value as a 64-bit number.
    */
   public static long hash64(final byte[] data)
   {
     long hashValue = FNV_OFFSET_BASIS_64;

     for (int i = 0; i < data.length; i++)
     {
        hashValue = hashValue ^ ((long) data[i]);
        hashValue *= FNV_PRIME_64;
     }
     return hashValue;
   }

   /**
    * Hashes a string into a 64-bit value.
    * @param data the string to hash.
    * @return the hash value as a 64-bit number.
    */
   public static long hash64(final String data)
   {
     try
     {
       return hash64(data.getBytes("UTF-8"));
     }
     catch (UnsupportedEncodingException ex)
     {
       ex.printStackTrace();
       return -1L;
     }
   }
 }
