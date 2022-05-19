package datastructures.merkletree;

import java.util.LinkedList;
import java.util.ArrayList;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class implements a Merkle tree using a the SHA256 cryptographic hash
 * function.
 * @author Zach Kissel
 */
 public class MerkleTree
 {
   TreeNode root;
   ArrayList<TreeNode> leafList;
   MessageDigest sha256;      // The hash function.

   /**
    * The default Merkle tree constructor -- it builds an empty tree.
    */
   public MerkleTree()
   {
     root = null;

     try
     {
       sha256 = MessageDigest.getInstance("SHA-256");
     }
     catch(NoSuchAlgorithmException ex)
     {
       System.err.println("Internal error!");
       ex.printStackTrace();
       System.exit(1);
     }
   }

   /**
    * This constructor sets the leaves and builds the tree.
    * @param leaves and array list of leaf values.
    */
   public MerkleTree(ArrayList<byte[]> leaves)
   {
     try
     {
       sha256 = MessageDigest.getInstance("SHA-256");
     }
     catch(NoSuchAlgorithmException ex)
     {
       System.err.println("Internal error!");
       ex.printStackTrace();
       System.exit(1);
     }
     buildTree(leaves);
   }

   /**
    * This method builds the Merkle tree from the leaves up.
    * @param leaves a non-null array list of leaf data.
    */
   public void buildTree(ArrayList<byte[]> leaves)
   {
     LinkedList<TreeNode> forest = new LinkedList<TreeNode>();
     LinkedList<TreeNode> tmp = new LinkedList<TreeNode>();
     leafList = new ArrayList<TreeNode>();

     if (leaves == null)
     {
       root = null;
       return;
     }

      // Build the forest from the leaves.
      for (int i = 0; i < leaves.size(); i++)
      {
        TreeNode newNode = new TreeNode(leaves.get(i));
        forest.add(newNode);
        leafList.add(newNode);
      }

      // Keep merging the forest until we end up with a single tree.
      while (forest.size() != 1)
      {

        // Merge the current forest into a forest about half the size.
        while (forest.size() != 0)
        {
          TreeNode node = new TreeNode();

          if (forest.size() > 1)
          {
            TreeNode left = forest.removeFirst();
            left.setParent(node);
            TreeNode right = forest.removeFirst();
            right.setParent(node);
            node.setLeft(left);
            node.setRight(right);
            node.setData(hash(left.getData(), right.getData()));
            tmp.add(node);
          }
          else
          {
             // Forest size is one and therefore we only have a left child.
             // To deal with this situation we will just carry this node
             // along until we reach a point where we have an even number
             // of nodes and then hash this in. Of course, this results in
             // the creation of an unbalanced tree.
            TreeNode left = forest.removeFirst();
            tmp.add(left);
          }
        }
        forest.addAll(tmp);
        tmp.clear();
      }
      root = forest.getFirst();
   }

   /**
    * Returns the root hash value.
    * @return the SHA256 hash value of the Merkle root.
    */
   public byte[] getRootHash()
   {
     return root.getData();
   }

   /**
    * Returns a proof that val is in the Merkle tree.
    * @param val the value to build the proof of membership for.
    * @return the proof of membership as an ArrayList.
    */
   public ArrayList<byte[]> getProof(byte[] val)
   {
     ArrayList<byte[]> proof = new ArrayList<byte[]>();
     TreeNode node = null;
     byte[] loc = new byte[1];

     // We must first find the leaf node represented by val we do
     // this by walking the leaf list.
     for (int i = 0; i < leafList.size(); i++)
      if (Arrays.equals(leafList.get(i).getData(), val))
        node = leafList.get(i);

     // If the node was not found, there is no proof we can give.
     if (node == null)
      return null;

     // Store if the node is a left or right child.
     if (isLeftChild(node))
      loc[0] = 'L';
     else
      loc[0] = 'R';
     proof.add(loc);

     // Build the proof
     while (!isRoot(node.getParent()))
     {
       if (isLeftChild(node))
        proof.add(node.getParent().getRight().getData());
       else
        proof.add(node.getParent().getLeft().getData());
       node = node.getParent();
     }

     // Add the corect subtree root of the root node to the proof.
     if(isLeftChild(node))
      proof.add(node.getParent().getRight().getData());
     else
      proof.add(node.getParent().getLeft().getData());

     return proof;
   }

   /**
    * Verifies the proof that val is in the Merkle tree.
    * @param proof the proof (intermediate hash values) aiding the verification
    * of membership for {@code val}
    * @param val the value membership is being proved for.
    * @param rootVal the value of the Merkle tree root hash.
    * @return true if the proof verifies; otherwise, false.
    */
   public boolean verifyProof(ArrayList<byte[]> proof, byte[] val,
       byte[] rootVal)
   {
     byte[] currHash = val;
     boolean isLeft = (proof.get(0)[0] == 'L');

     for (int i = 1; i < proof.size(); i++)
     {
      if ((isLeft && (i % 2) == 1) || (!isLeft && (i % 2) == 0))
        currHash = hash(currHash, proof.get(i));
      else if ((isLeft && (i % 2) == 0) || (!isLeft && (i % 2) == 1))
        currHash = hash(proof.get(i), currHash);
     }
     return Arrays.equals(currHash, rootVal);
   }

   /**
    * Hashes the left and right subtree roots into one value.
    * @param left the root of the left subtree.
    * @param right the root of the right subtree.
    * @returns the hash of the left and right subtree.
    */
   private byte[] hash(byte[] left, byte[] right)
   {
     sha256.update(left);
     return sha256.digest(right);
   }

   /**
    * Hashes the left into one value.
    * @param left the root of the left subtree.
    * @returns the hash of the left subtree.
    */
   private byte[] hash(byte[] left)
   {
     return sha256.digest(left);
   }

   /**
    * Returns true if the node is a left child.
    * @return true if node is left childe; otherwise, false.
    */
   private boolean isLeftChild(TreeNode node)
   {
     if (node.getParent() == null)
      return false;

     return node.getParent().getLeft().equals(node);
   }

   /**
    * Returns true if the node is the root.
    * @return true if the node is the root; otherwise, false.
    */
   private boolean isRoot(TreeNode node)
   {
     return (node.getParent() == null);
   }

 }
