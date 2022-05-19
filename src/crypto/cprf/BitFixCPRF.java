package crypto.cprf;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import java.util.regex.Pattern;
import java.util.BitSet;
import java.util.Base64;
import java.util.Arrays;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.util.regex.PatternSyntaxException;

/**
 * This class implements a canonical bit-fixed CPRF using AES as the underlying
 * PRF (via the assumptiong that AES is a PRP and thus a PRF via the
 * switching lemma). The constrained key generation will uses a string
 * over the alphabet {0, 1, ?} to define the bit fixing pattern.
 * @author Zach Kissel
 */
 public class BitFixCPRF
 {
   private SecretKey[][] masterKey; // The key block for the PRF.
   private int domainSize;    // The domain size in bits.
   private KeyGenerator keyGen;
   private Cipher aesCipher;

   /**
    * This constructor setups of a CPRF with a domain size of domainSize bits.
    * @param domainSize a non-negative number of bits in the domain.
    * @throws UnsupportedOperationException if the domainSize is greater than
    * 128.
    */
   public BitFixCPRF(int domainSize) throws UnsupportedOperationException
   {
     // Check for a valid domain size.
     if (domainSize > 128)
      throw new UnsupportedOperationException(
          "Domain size limited to 128 bits.");

    // Set the domain size; we know it's valid.
    this.domainSize = domainSize;

     // Create an empty key block.
     masterKey = new SecretKey[2][];
     masterKey[0] = new SecretKey[domainSize];
     masterKey[1] = new SecretKey[domainSize];

     // Setup an AES key generator object.
     try
     {
       keyGen = KeyGenerator.getInstance("AES");
       keyGen.init(128);
     }
     catch(NoSuchAlgorithmException nsae)
     {
       nsae.printStackTrace();
     }

     // Setup the AES cipher to encrypt in ECB mode with no padding. This
     // mode is chosen as we are only encrypting a single block.
     try
     {
       aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
     }
     catch(NoSuchAlgorithmException nsae)
     {
       nsae.printStackTrace();
     }
     catch(NoSuchPaddingException nspe)
     {
       nspe.printStackTrace();
     }
   }

   /**
    * This method generates the a secret key for the CPRF.
    */
    public void keyGen()
		{
			// Build the key block.
		  for (int i = 0; i < this.domainSize; i++)
      {
        this.masterKey[0][i] = generateKey();
        this.masterKey[1][i] = generateKey();
      }
		}

    /**
     * This method takes an existing key and constrains it to the
     * bit fixed pattern specified by {@code pattern}.
     * @param pattern a valid bit fix pattern with symbols from the alphabet
     * {0, 1, ?}.
     * @return a new secret key for the PRF as a matrix of Base64 encoded strings.
     */
    public String[][] constrainKey(String pattern)
    {
      String[][] constrainedKey;

      // Make sure the bit fixing pattern is OK.
      if (pattern.length() != this.domainSize)
        throw new IllegalArgumentException("Pattern not of correct length.");

      try
      {
        if (!Pattern.matches("[01?]{" + this.domainSize + "}", pattern))
          throw new IllegalArgumentException("Pattern contains illegal symbols.");
      }
      catch(PatternSyntaxException ex)
      {
        System.err.println("Internal error: bad regex syntax.");
        ex.printStackTrace();
      }

      // Allocate the space for the key.
      constrainedKey = new String[2][];
      constrainedKey[0] = new String[this.domainSize];
      constrainedKey[1] = new String[this.domainSize];

      // Build the constrainedKey being careful to preserve endianess.
      for (int i = 0; i < pattern.length(); i++)
      {
        switch (pattern.charAt(i))
        {
          case '0':
            constrainedKey[0][this.domainSize - i - 1] = Base64.getEncoder().encodeToString(masterKey[0][this.domainSize - i - 1].getEncoded());
            constrainedKey[1][this.domainSize - i - 1] = Base64.getEncoder().encodeToString(generateKey().getEncoded());
          break;
          case '1':
            constrainedKey[0][this.domainSize - i - 1] = Base64.getEncoder().encodeToString(generateKey().getEncoded());
            constrainedKey[1][this.domainSize - i -1] = Base64.getEncoder().encodeToString(masterKey[1][this.domainSize - i - 1].getEncoded());
          break;
          case '?':
            constrainedKey[0][this.domainSize - i - 1] = Base64.getEncoder().encodeToString(masterKey[0][this.domainSize - i - 1].getEncoded());
            constrainedKey[1][this.domainSize - i - 1] = Base64.getEncoder().encodeToString(masterKey[1][this.domainSize - i - 1].getEncoded());
          break;
        }
      }
      return constrainedKey;
    }

    /**
     * Outputs the master key as an array of Base64 encoded strings.
     * @return a base64 encoded array of keys.
     */
    public String[][] getMasterKey()
    {
      String[][] key;

      // Allocate the space for the key.
      key = new String[2][];
      key[0] = new String[this.domainSize];
      key[1] = new String[this.domainSize];

      for (int i = 0; i < this.domainSize; i++)
      {
        key[0][i] = Base64.getEncoder().encodeToString(masterKey[0][i].getEncoded());
        key[1][i] = Base64.getEncoder().encodeToString(masterKey[1][i].getEncoded());
      }

      return key;
    }

    /**
     * Sets the master key to mKey.
     * @param mKey the master key encoded as base64 strings.
     */
    public void setMasterKey(String[][] mKey)
    {
      for (int i = 0; i < this.domainSize; i++)
      {
        masterKey[0][i] = new SecretKeySpec(Base64.getDecoder().decode(mKey[0][i]), "AES");
        masterKey[1][i] = new SecretKeySpec(Base64.getDecoder().decode(mKey[1][i]), "AES");
      }
    }

    /**
     * Evaluates the PRF on message give the key.
     * @param msg the upto 16 byte message.
     * @return the 16-byte PRF output.
     * @throws IllegalArgumentException when the message greater than 16 bytes.
     */
    public byte[] evaluate(byte[] msg) throws IllegalArgumentException
    {
      BitSet bits;
      BitSet result = new BitSet(128);

      if (msg.length > 16)
        throw new IllegalArgumentException("Message is too long.");

      // Extend the size of the array if needed.
      if (msg.length < 16)
        msg = Arrays.copyOf(msg, 16);


      // Evaluate the PRF using the correct keys in the correct order.
      bits = BitSet.valueOf(msg);
      for (int i = 0; i < this.domainSize; i++)
        result.xor(BitSet.valueOf(
            encrypt(masterKey[((bits.get(i))? 1:0)][i], msg)));

      return result.toByteArray();
    }

    /**
     * Generates a secret key for AES-128.
     * @return A new secret key (128 bits).
     */
    private SecretKey generateKey()
    {
  		  return keyGen.generateKey();
    }

    /**
     * Uses the AES-128 cipher to encrypt {@code msg} with {@code key}.
     * @param key the encryption key.
     * @param msg the message to encrypt (is 16-bytes in size).
     */
    private byte[] encrypt(SecretKey key, byte msg[])
    {
      try
      {
        aesCipher.init(Cipher.ENCRYPT_MODE, key);
        return aesCipher.doFinal(msg);
      }
      catch (InvalidKeyException ike)
      {
        ike.printStackTrace();
      }
      catch (IllegalBlockSizeException ibse)
      {
        ibse.printStackTrace();
      }
      catch (BadPaddingException bpe)
      {
        bpe.printStackTrace();
      }

      return null;
    }
 }
