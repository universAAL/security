/*******************************************************************************
 * Copyright 2016 Universidad Politécnica de Madrid UPM
 *
 * Based on code @ http://coding.westreicher.org/?p=23
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/
package org.universAAL.security.cryptographic.services.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * @author amedrano
 *
 */
public class BlockChipher {

	Cipher cipher;

	/**
	 *
	 */
	public BlockChipher(Cipher c) {
		cipher = c;
	}

	public byte[] encrypt(String plaintext, Key key)
			throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = plaintext.getBytes("UTF-8");

		byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE);

		return encrypted;
	}

	public String decrypt(byte[] encrypted, Key key)
			throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] decrypted = blockCipher(encrypted, Cipher.DECRYPT_MODE);

		return new String(decrypted, "UTF-8");
	}

	private byte[] blockCipher(byte[] bytes, int mode) throws IllegalBlockSizeException, BadPaddingException {
		// string initialize 2 buffers.
		// scrambled will hold intermediate results
		byte[] scrambled = new byte[0];

		// toReturn will hold the total result
		byte[] toReturn = new byte[0];
		// if we encrypt we use 100 byte long blocks. Decryption requires 128
		// byte long blocks (because of RSA)
		int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

		// another buffer. this one will hold the bytes that have to be modified
		// in this step
		byte[] buffer = new byte[length];

		for (int i = 0; i < bytes.length; i++) {

			// if we filled our buffer array we have our block ready for de- or
			// encryption
			if ((i > 0) && (i % length == 0)) {
				// execute the operation
				scrambled = cipher.doFinal(buffer);
				// add the result to our total result.
				toReturn = append(toReturn, scrambled);
				// here we calculate the length of the next buffer required
				int newlength = length;

				// if newlength would be longer than remaining bytes in the
				// bytes array we shorten it.
				if (i + length > bytes.length) {
					newlength = bytes.length - i;
				}
				// clean the buffer array
				buffer = new byte[newlength];
			}
			// copy byte into our buffer.
			buffer[i % length] = bytes[i];
		}

		// this step is needed if we had a trailing buffer. should only happen
		// when encrypting.
		// example: we encrypt 110 bytes. 100 bytes per run means we "forgot"
		// the last 10 bytes. they are in the buffer array
		scrambled = cipher.doFinal(buffer);

		// final step before we can return the modified data.
		toReturn = append(toReturn, scrambled);

		return toReturn;
	}

	private byte[] append(byte[] prefix, byte[] suffix) {
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i = 0; i < prefix.length; i++) {
			toReturn[i] = prefix[i];
		}
		for (int i = 0; i < suffix.length; i++) {
			toReturn[i + prefix.length] = suffix[i];
		}
		return toReturn;
	}

}
