package frontend;

import datastructures.bloom.BloomFilter;
import datastructures.merkletree.MerkleTree;
import crypto.cprf.BitFixCPRF;
import crypto.cprf.LeftRightCPRF;
import crypto.cprf.LRKeyPair;
import java.util.ArrayList;
import java.util.Base64;

/**
 * This is the front end for the redactable signature program.
 * it provides command line access to all of the operations supported
 * on a redactable signature scheme.
 * @author Zach Kissel
 */
public class Main
{
  /**
   * The entry point.
   * @param args the command line arguments.
   */
  public static void main(String[] args)
  {
      ArrayList<byte[]> leaves = new ArrayList<byte[]>();
      ArrayList<byte[]> proof;
      MerkleTree tree = new MerkleTree();
      BloomFilter bf;
      BitFixCPRF prf;
      LeftRightCPRF prf2;

      byte[] leaf1 = new byte[2];
      byte[] leaf2 = new byte[2];
      byte[] leaf3 = new byte[2];
      byte[] leaf4 = new byte[2];
      byte[] leaf5 = new byte[2];

      leaf1[0] = 'L';
      leaf1[1] = '1';
      leaf2[0] = 'L';
      leaf2[1] = '2';
      leaf3[0] = 'L';
      leaf3[1] = '3';
      leaf4[0] = 'L';
      leaf4[1] = '4';
      leaf5[0] = 'L';
      leaf5[1] = '5';

      leaves.add(leaf1);
      leaves.add(leaf2);
      leaves.add(leaf3);
      leaves.add(leaf4);
      leaves.add(leaf5);

      // Test the Merkle tree.
      System.out.println(" === Merkle Tree ===");
      System.out.print("Building tree . . . ");
      tree.buildTree(leaves);
      System.out.println("[ DONE ]");
      System.out.println("Root Hash: " +
          Base64.getEncoder().encodeToString(tree.getRootHash()));
      System.out.print("Getting proof . . . ");
      proof = tree.getProof(leaf3);
      System.out.println("[ DONE ]");
      System.out.print("Verifying proof . . . ");
      if (tree.verifyProof(proof, leaf3, tree.getRootHash()))
        System.out.println("[ OK ]");
      else
        System.out.println("[ FAIL ]");


     // Test the Bloom Filter
     System.out.println("\n\n === Bloom Filter ===");
     bf = new BloomFilter(1000, 0.0000001);
     bf.add(leaf1);
     bf.add(leaf2);
     bf.add(leaf3);
     bf.add(leaf4);
     bf.add(leaf5);

     System.out.println("Check for leaf2: " + bf.contains(leaf2));
     System.out.println("Check for leaf4: " + bf.contains(leaf4));
     System.out.println("Filter Size: " + bf.getFilter().length * 8 + " bits.");

     // Test the Bit-Fix CPRF
     System.out.println("\n\n === Bit-Fixed Constrained PRF ===");
     byte[] input = new byte[1];
     prf = new BitFixCPRF(8);    // CPRF with an input of 8 bits.
     prf.keyGen();                // Generate the master key.
     System.out.print("Constraining key to 11??00?? . . . ");
     String[][] constrainedKey = prf.constrainKey("11??00??");
     System.out.println("[ DONE ]");
     input[0] = (byte) (0xF0 & 0xFF);
     System.out.println("PRF(mk, 11110000) = " + Base64.getEncoder().encodeToString(prf.evaluate(input)));
     prf.setMasterKey(constrainedKey);
     System.out.println("PRF(ck, 11110000) = " + Base64.getEncoder().encodeToString(prf.evaluate(input)));

     // Test the Left-Right CPRF
     System.out.println("\n\n === Left-Right Constrained PRF ===");
     prf2 = new LeftRightCPRF(8);   // CPRF with an input of 8 bits.
     prf2.keyGen();
     System.out.print("Generating key pair Left = 1111, Right = 0 . . . ");
     LRKeyPair kp = prf2.constrainKey("1111", "0");
     System.out.println("[ DONE ]");
     input[0] = (byte) (0xF0 & 0xFF);
     System.out.println("PRF(msk, 11110000) = " +
         Base64.getEncoder().encodeToString(prf2.evaluate(input)));
     prf2.setMasterKey(kp.getLeftKey());
     System.out.println("PRF(lck, 11110000) = " +
         Base64.getEncoder().encodeToString(prf2.evaluate(input)));
     prf2.setMasterKey(kp.getRightKey());
     System.out.println("PRF(rck, 11110000) = " +
         Base64.getEncoder().encodeToString(prf2.evaluate(input)));
  }
}
