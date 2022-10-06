/*
 *   Policy-Based Redactable Set Signature Schemes
 *   Copyright (C) 2022  Zachary A. Kissel
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package policylang.ast;

import policylang.ast.nodes.SyntaxNode;
import policylang.Environment;
import java.math.BigInteger;
import util.Pair;

/**
 * Represents a syntax tree for the language.
 * @author Zach Kissel
 */
public class SyntaxTree
{
  SyntaxNode root;  // The root of the syntax tree.
  Environment env;  // The executional environment.

  /**
   * Constructs a new syntax tree with root {@code root}.
   * @param root the root node of the tree.
   */
  public SyntaxTree(SyntaxNode root)
  {
    this.root = root;
    this.env = new Environment();
  }

  /**
   * Construct an empty syntax tree.
   */
  public SyntaxTree()
  {
    this(null);
  }

  /**
   * Sets the root node to {@code root}
   * @param root the object to set the root node to.
   */
   public void setRootNode(SyntaxNode root)
   {
     this.root = root;
   }

   /**
    * Gets the root node of the tree.
    * @return a reference to the root node of the tree.
    */
    public SyntaxNode getRootNode()
    {
      return this.root;
    }

   /**
    * Evaluate the syntax tree.
    * @return the object representing the result of the evaluation.
    */
    public Object evaluate()
    {
      return root.evaluate(env);
    }

    /**
     * Get a copy of the current executional evironment.
     * @return the environment associated with this exeuction.
     */
    public Environment getEnvironment()
    {
      return env;
    }

    /**
     * Set the executional environment to {@code env}
     * @param env the executional environment.
     */
     public void setEnvironment(Environment env)
     {
       this.env = env;
     }

     /**
      * Gets the shares associated with the leaves of the policy tree.
      * @param secret the secret that this node shares out.
      * @return a copy of the environment containing the shares.
      */
     public Environment getShares(BigInteger secret)
     {
       return root.getShares(env, new Pair<BigInteger>(BigInteger.ZERO, secret));
     }

     /**
      * Given an environment with shares associated with labels, reconstruct
      * the secret value.
      * @param env the environment contains the element names associated with
      * their shares.
      * @return the secret assocaited with the tree.
      */
     public BigInteger reconstructSecret(Environment env)
     {
       Pair<BigInteger> secret = root.reconstruct(env);
       if (secret != null)
        return secret.getSecond();
       return null;
     }
}
