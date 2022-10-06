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
package crypto.accumulator;

/**
 * Represents a key pair for an accumulator.
 *
 * @author Zach Kissel
 */
public class AccumulatorKeyPair
{
  AccumulatorPrivateKey sk;
  AccumulatorPublicKey pk;

  /**
   * Constructs a new accumulator key pair with private key {@code sk} and
   * public key {@code pk}.
   * @param sk the accumulator's private key.
   * @param pk the accumulator's public key.
   */
  public AccumulatorKeyPair(AccumulatorPrivateKey sk, AccumulatorPublicKey pk)
  {
    this.sk = sk;
    this.pk = pk;
  }

  /**
   * Gets the private key.
   * @return the accumulator's private key.
   */
  public AccumulatorPrivateKey getPrivate()
  {
    return sk;
  }

  /**
   * Gets the public key.
   * @return the accumulator's public key.
   */
  public AccumulatorPublicKey getPublic()
  {
    return pk;
  }

  /**
   * Gets a string representation of the key pair.
   * @return the keypair as a string.
   */
  @Override
  public String toString()
  {
    return pk + "\n\n " + sk;
  }
}
