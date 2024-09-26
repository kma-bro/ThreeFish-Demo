package net.malkowscy.threefish;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.params.KeyParameter;



public class Helper {

	public static void main(String[] args){
//            NewJFrame jf = new NewJFrame();
//            jf.setVisible(true);
                String keyStr = "ilovekma000000001111111133333333";
                String inputStr = "00000000000000000000000000000000";
                byte[] decodedKey = keyStr.getBytes(StandardCharsets.UTF_8);
               
                KeyParameter kp = new KeyParameter(decodedKey);
                ThreefishEngine tf = new ThreefishEngine(256);
                tf.init(true, kp);
                byte[] inputByte = inputStr.getBytes(StandardCharsets.UTF_8);
                byte[] outputByte = new byte[inputByte.length];
                tf.processBlock(inputByte, 0, outputByte, 0);
                System.out.println("output bytes :"+Arrays.toString(outputByte));
//                tf.init(false, kp);
//                byte[] decryptedByte = new byte[inputByte.length];
//                tf.processBlock(outputByte, 0, decryptedByte, 0);
//                System.out.println("decrypted bytes :"+Arrays.toString(decryptedByte));
	}

}
