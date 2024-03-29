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
package util.exception;

import java.io.IOException;

/**
 * A bad file format exception.
 * @author Zach Kissel
 */
 public class BadFileFormatException extends IOException
 {
   /**
    * Overloaded constructor that allows the users to specify the
    * message associated with the bad file format.
    * @param msg the message associated with the exception.
    */
   public BadFileFormatException(String msg)
   {
     super(msg);
   }

   /**
    * Default constructor that informs the user of a bad file format.
    */
   public BadFileFormatException()
   {
     super("Bad file format.");
   }
 }
