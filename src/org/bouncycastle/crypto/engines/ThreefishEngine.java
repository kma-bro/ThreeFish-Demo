package org.bouncycastle.crypto.engines;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.crypto.Bits;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.FastByteBuffer;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ThreefishParameters;

/**
 * An implementation of Threefish (1.3) encryption algorithm.
 * 
 * Threefish is tweakable block encryption algorithm designed by Bruce Schneier,
 * Niels Ferguson, Stefan Lucks, Doug Whiting, Mihir Bellare, Tadayoshi Kohno,
 * Jon Callas, and Jesse Walker.
 * 
 */
public class ThreefishEngine implements BlockCipher {

	/**
	 * Word permutation for 1024 bits key
	 */
	private static final int[] P_16 = { 0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1 };

	/**
	 * Reverse word permutation for 1024 bits key
	 */
	private static final int[] P_16__1 = { 0, 15, 2, 11, 6, 13, 4, 9, 14, 1, 8, 5, 10, 3, 12, 7 };

	/**
	 * Word permutation for 256 bits key
	 */
	private static final int[] P_4 = { 0, 3, 2, 1 };

	/**
	 * Reverse word permutation for 256 bits key
	 */
	private static final int[] P_4__1 = { 0, 3, 2, 1 };

	/**
	 * Word permutation for 512 bits key
	 */
	private static final int[] P_8 = { 2, 1, 4, 7, 6, 5, 0, 3 };

	/**
	 * Reverse word permutation for 512 bits key
	 */
	private static final int[] P_8__1 = { 6, 1, 0, 7, 2, 5, 4, 3 };

	/**
	 * Rotation constants for 1024 bits key
	 */
	private static final int[][] R_16 = { { 24, 13, 8, 47, 8, 17, 22, 37 }, { 38, 19, 10, 55, 49, 18, 23, 52 },
			{ 33, 4, 51, 13, 34, 41, 59, 17 }, { 5, 20, 48, 41, 47, 28, 16, 25 }, { 41, 9, 37, 31, 12, 47, 44, 30 },
			{ 16, 34, 56, 51, 4, 53, 42, 41 }, { 31, 44, 47, 46, 19, 42, 44, 25 }, { 9, 48, 35, 52, 23, 31, 37, 20 } };

	/**
	 * Rotation constants for 256 bits key
	 */
	private static final int[][] R_4 = { { 14, 16 }, { 52, 57 }, { 23, 40 }, { 5, 37 }, { 25, 33 }, { 46, 12 }, { 58, 22 },
			{ 32, 32 } };

	/**
	 * Rotation constants for 512 bits key
	 */
	private static final int[][] R_8 = { { 46, 36, 19, 37 }, { 33, 27, 14, 42 }, { 17, 49, 36, 39 }, { 44, 9, 54, 56 },
			{ 39, 30, 34, 24 }, { 13, 50, 10, 17 }, { 25, 29, 39, 43 }, { 8, 35, 56, 22 } };

	public static long[] bytesToWords(byte[] ba, int length, int offset) {
		long[] result = new long[length / 8];
		long l = 0;
		int rc = 0;
		for (int i = 0; i < length; i++) {
			l |= ((long) (ba[i + offset] & 0xFF)) << ((i) * 8);
			if ((i - 7) % 8 == 0) {
				result[rc++] = l;
				l = 0;
			}
		}
		return result;
	}
        

	public static void wordsToBytes(long[] la, byte[] dest, int offset) {
		for (int i = 0; i < la.length; i++) {
			long l = la[i];
			dest[offset + 0 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 1 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 2 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 3 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 4 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 5 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 6 + i * 8] = (byte) (0xff & l);
			l = l >> 8;
			dest[offset + 7 + i * 8] = (byte) (0xff & l);
		}
	}


	/**
	 * Work mode.<br/>
	 * <code>true</code> for encryption<br/>
	 * <code>false</code> for decryption
	 */
	public boolean encryptMode;

	/**
	 * Tweak as words
	 */
	protected final long[] t = new long[3];

	/**
	 * Block size in bytes
	 */
	private final int blockSize;        
	/**
	 * Number of rounds
	 */
	private final int Nr;

	/**
	 * Number of words in the key (and thus also in the plaintext)
	 */
	private final int Nw;

	/**
	 * Word permutation
	 */
	private final int[] p;

	/**
	 * Reverse word permutation (p^-1)
	 */
	private final int[] p_1;

	/**
	 * Rotation constants
	 */
	private final int[][] r;

	/**
	 * Subkeys.
	 */
	protected long[][] subKeys;



        /**
	 * Initialization Vector
	 */
        byte[] IV = {1, 0, 1, 0, 1, 9, 5, 4, 3, 0, 0, 4, 1, 9, 7, 5, 1, 0, 1, 0, 1, 9, 5, 4, 3, 0, 0, 4, 1, 9, 7, 5};


	public ThreefishEngine() {
		this(256);
	}

	public ThreefishEngine(int keyLength) {
		switch (keyLength) {
		case 256:
			this.blockSize = 32;
			this.Nw = 32 / 8;
			this.Nr = 72;
			this.r = R_4;
			this.p = P_4;
			this.p_1 = P_4__1;
			break;
		case 512:
			this.blockSize = 64;
			this.Nw = 64 / 8;
			this.Nr = 72;
			this.r = R_8;
			this.p = P_8;
			this.p_1 = P_8__1;
			break;
		case 1024:
			this.blockSize = 128;
			this.Nw = 128 / 8;
			this.Nr = 80;
			this.r = R_16;
			this.p = P_16;
			this.p_1 = P_16__1;
			break;
		default:
			throw new IllegalArgumentException("Invalid Key length - should be 32, 64 or 128 bytes");
		}
	}

	private void decryptBlock(long[] v, long[] c) {
		for (int round = Nr; round > 0; round--) {
			final long[] f = new long[Nw];
			if (round % 4 == 0) {
				final int s = round / 4;
				for (int i = 0; i < Nw; i++) {
					f[i] = v[i] - subKeys[s][i];
				}
			} else {
				for (int i = 0; i < Nw; i++) {
					f[i] = v[i];
				}
			}

			long[] e = new long[Nw];
			for (int i = 0; i < Nw; i++) {
				e[i] = f[p_1[i]];
			}

			for (int i = 0; i < Nw / 2; i++) {
				long[] y = new long[2];
				y[0] = e[i * 2];
				y[1] = e[i * 2 + 1];

				long[] x = demix(y, i, round - 1);

				v[i * 2] = x[0];
				v[i * 2 + 1] = x[1];
			}

		}


		for (int i = 0; i < Nw; i++) {
			c[i] = v[i] - subKeys[0][i];
		}

	}

	private long[] demix(long[] y, final int j, final int round) {
		long[] x = new long[2];
		y[1] ^= y[0];
		final long rotr = r[round % 8][j];
		x[1] = (y[1] << (Long.SIZE - rotr)) | (y[1] >>> rotr);
		x[0] = y[0] - x[1];
		return x;
	}

	private void encryptBlock(long[] v, long[] c) {
		for (int round = 0; round < Nr; round++) {
			final long[] e = new long[Nw];
			if (round % 4 == 0) {
				final int s = round / 4;
				for (int i = 0; i < Nw; i++) {
					e[i] = v[i] + subKeys[s][i];
				}
			} else {
				for (int i = 0; i < Nw; i++) {
					e[i] = v[i];
				}
			}

			long[] f = new long[Nw];
			for (int i = 0; i < Nw / 2; i++) {
				long[] x = new long[2];
				x[0] = e[i * 2];
				x[1] = e[i * 2 + 1];

				long[] y = mix(x, i, round);

				f[i * 2] = y[0];
				f[i * 2 + 1] = y[1];
			}

			for (int i = 0; i < Nw; i++) {
				v[i] = f[p[i]];
			}

		}

		for (int i = 0; i < Nw; i++) {
			c[i] = v[i] + subKeys[Nr / 4][i];
		}

	}

	@Override
	public String getAlgorithmName() {
		return "Threefish";
	}

	@Override
	public int getBlockSize() {
		return this.blockSize;
	}

	@Override
	public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
		byte[] key;
		byte[] tweak;
		this.encryptMode = forEncryption;
		if (params instanceof ThreefishParameters) {
			tweak = ((ThreefishParameters) params).getTweak();
			key = ((ThreefishParameters) params).getKey();
		} else if (params instanceof KeyParameter) {
			tweak = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			key = ((KeyParameter) params).getKey();
		} else {
			throw new IllegalArgumentException(
                                "Invalid parameter passed to Threefish init - " 
                                + params.getClass().getName());
		}

		if (tweak == null || tweak.length != 16) {
			throw new IllegalArgumentException(
                                "Invalid Tweak length - should be 16 bytes");
		}
		if (key == null || key.length != this.blockSize) {
			throw new IllegalArgumentException(
                                "Invalid Key length - should be " + this.blockSize + " bytes");
		}

		setkey(key, tweak);
	}

	private long[] mix(long[] x, final int j, final int round) {
            
		long[] y = new long[2];
		y[0] = x[0] + x[1];
		final long rotl = r[round % 8][j];
		y[1] = (x[1] << rotl) | (x[1] >>> (Long.SIZE - rotl));
		y[1] ^= y[0];
		return y;
	}

        public byte[] encryptECB(byte[] content) {
            FastByteBuffer fbb = new FastByteBuffer();

            int length = content.length;
            int blockCount = length / blockSize;
            int remaining = length;
                                                        System.out.println("content length: "+content.length);

            int offset = 0;
            for (int i = 0; i < blockCount; i++) {

                if (remaining == blockSize) {

                    break;

                }

                byte[] encrypted = new byte[blockSize];

                processBlock(content, offset, encrypted, 0);

                fbb.append(encrypted);
                offset += blockSize;
                remaining -= blockSize;


            }


            if (remaining != 0) {


                // process remaining bytes
                byte[] block = new byte[blockSize];

                System.arraycopy(content, offset, block, 0, remaining - 1);


                byte[] encrypted = new byte[blockSize];

                processBlock(block, 0, encrypted, 0);

                fbb.append(encrypted);

            }
            System.out.println("encrypted length: " + fbb.size());

            return fbb.toArray();
        }
        
        

            /**
             * Decrypts the whole content, block by block.
             */
            public byte[] decryptECB(byte[] encryptedContent) {

                FastByteBuffer fbb = new FastByteBuffer();
                this.encryptMode = false;

                int length = encryptedContent.length;
                int blockCount = length / blockSize;

                int offset = 0;
                for (int i = 0; i < blockCount - 1; i++) {
                    byte[] decrypted = new byte[blockSize];
                    processBlock(encryptedContent, offset, decrypted, 0);

                    fbb.append(decrypted);

                    offset += blockSize;

                }



		// process last block
		byte[] decrypted = new byte[blockSize];
                processBlock(encryptedContent, offset,decrypted,0);
                System.out.println(Arrays.toString(decrypted));

		// find terminator
//		int ndx = blockSize - 1;

//		while (ndx >= 0) {
//			if (decrypted[ndx] == -1) {
//				break;
//			}
//			ndx--;
//		}
//                System.out.println("decrypting: "+Arrays.toString(decrypted));

		fbb.append(decrypted);
                                                                        System.out.println("decrypt length: "+fbb.size());


		return fbb.toArray();
	}
            
            
            
            /**
             * CBC mode
             */   
        public byte[] encryptCBC(byte[] content) {
            FastByteBuffer fbb = new FastByteBuffer();
            byte[] encrypted = new byte[blockSize];
            int length = content.length;
            int blockCount = length / blockSize;
            int remaining = length;
            byte[] processedContent = content;       
            int offset = 0;
            
            for (int i = 0; i < blockCount; i++) {
                if (remaining == blockSize) {
                    break;

                }
                if(i==0){
                    xorBlock(processedContent, IV, offset);
                }
                else{
                    xorBlock(processedContent, encrypted, offset);
                }
                processBlock(processedContent, offset, encrypted, 0);

                fbb.append(encrypted);
                offset += blockSize;
                remaining -= blockSize;

            }


            if (remaining != 0) {
                // process remaining bytes
                byte[] block = new byte[blockSize];

                System.arraycopy(processedContent, offset, block, 0, remaining - 1);


    //                block[remaining - 1] = -1;
                xorBlock(block, encrypted, 0);


                processBlock(block, 0, encrypted, 0);

                fbb.append(encrypted);
                
            }

            return fbb.toArray();
        } 
        
        public byte[] decryptCBC(byte[] encryptedContent) {

            FastByteBuffer fbb = new FastByteBuffer();
            this.encryptMode = false;
            byte[] decrypted = new byte[blockSize];
            byte[] pEncryptedContent = new byte[blockSize];       
            
            int length = encryptedContent.length;
            int blockCount = length / blockSize;

            int offset = 0;
            for (int i = 0; i < blockCount - 1; i++) {

                processBlock(encryptedContent, offset, decrypted, 0);
                
                if(i==0){
                    xorBlock(decrypted, IV, offset);
                }
                else{
                    System.arraycopy(encryptedContent, offset-blockSize, pEncryptedContent, 0, blockSize);
                    xorBlock(decrypted, pEncryptedContent, 0);
                }

                fbb.append(decrypted);

                offset += blockSize;

            }

            // process last block
            processBlock(encryptedContent, offset, decrypted, 0);
            System.arraycopy(encryptedContent, offset-blockSize, pEncryptedContent, 0, blockSize);

            xorBlock(decrypted, pEncryptedContent, 0);

                    // find terminator
    //		int ndx = blockSize - 1;
    //		while (ndx >= 0) {
    //			if (decrypted[ndx] == -1) {
    //				break;
    //			}
    //			ndx--;
    //		}
    //                System.out.println("decrypting: "+Arrays.toString(decrypted));
            fbb.append(decrypted);

            return fbb.toArray();
        }    

            
//      XOR util
        public int xorBlock(byte[] plainText,byte[] iniVector, int offset){
            int i = offset;
            for (byte b : iniVector) {
                plainText[i] = (byte) (plainText[i++] ^ b);
//                System.out.println(i);
            }
            return i;
        }

	@Override
	public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
//            System.out.println("in length: "+in.length);
            if (subKeys == null) {
			throw new IllegalStateException("Threefish not initialised");
		}

		if ((inOff + this.blockSize) > in.length) {
			throw new DataLengthException("input buffer too short");
		}

		if ((outOff + this.blockSize) > out.length) {
			throw new DataLengthException("output buffer too short");
		}

		long[] v = bytesToWords(in, this.blockSize, inOff);
		long[] c = new long[v.length];
                

		if (encryptMode) {
			encryptBlock(v, c);
		} else {
			decryptBlock(v, c);
		}

		wordsToBytes(c, out, outOff);

		return this.blockSize;
	}

	@Override
	public void reset() {
	}

	/**
	 * Key sheduler.
	 * 
	 * @param keyData
	 *            byte array of key
	 * @param tweakData
	 *            byte array of Tweak
	 */
	private void setkey(byte[] keyData, byte[] tweakData) {
		final long[] K = bytesToWords(keyData, this.blockSize, 0);
		final long[] T = bytesToWords(tweakData, 16, 0);
		final long[] key = new long[Nw + 1];
		long kNw = 0x1BD11BDAA9FC1A22l;
		for (int i = 0; i < Nw; i++) {
			kNw ^= K[i];
			key[i] = K[i];
		}

		key[key.length - 1] = kNw;

		t[0] = T[0];
		t[1] = T[1];
		t[2] = T[0] ^ T[1];

		this.subKeys = new long[Nr / 4 + 1][Nw];

		for (int round = 0; round <= Nr / 4; round++) {
			for (int i = 0; i < Nw; i++) {
				subKeys[round][i] = key[(round + i) % (Nw + 1)];
				if (i == Nw - 3) {
					subKeys[round][i] += t[round % 3];
				} else if (i == Nw - 2) {
					subKeys[round][i] += t[(round + 1) % 3];
				} else if (i == Nw - 1) {
					subKeys[round][i] += round;
				}
			}
		}
	}

}
