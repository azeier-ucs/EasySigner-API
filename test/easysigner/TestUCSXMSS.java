package easysigner;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import easysigner.EasySigner;
import easysigner.KeyManager;
import easysigner.StatefulKeyManager;
import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.KeystoreParameters;
import easysigner.parameters.XMSSParameters;

class TestUCSXMSS {

	@BeforeAll
	static void initialize() {
		Provider bcpqcProvider = new BouncyCastlePQCProvider();
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcpqcProvider);
		Security.addProvider(bcProvider);
		
		File file = new File("data/keyXMSS");
		file.delete();
	}
	
	@AfterEach
	void clean() {
		File file = new File("data/keyXMSS");
		file.delete();
	}
	
	@Test
	void testKeyManager() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		assertTrue(keyManager.getPrivateKey() instanceof BCXMSSPrivateKey);
		assertTrue(keyManager instanceof StatefulKeyManager);
	}

	@Test
	void testSigning() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
	}
	
	@Test
	void testSignMultipleTimes() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		byte[] sig1 = signer.sign("Hello, World!".getBytes());
		assertTrue(EasySigner.verify("Hello, World!".getBytes(), sig1, signer.getPublicKey()));
		byte[] sig2 = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(sig2), signer.getPublicKey()));
		byte[] sig3 = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(sig3), signer.getPublicKey()));
		byte[] sig4 = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(sig4), signer.getPublicKey()));
        
		assertTrue(!Arrays.equals(sig1, sig2));
	}
	
	@Test 
	void getPrivateKeyIndex() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);

		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();
		
		assertEquals(statefulKeyManager.getKeyIndex() , 0);
		
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		
		assertEquals(statefulKeyManager.getKeyIndex(), 1);
	}
	
	@Test
	void signMultipleTimesAndOnlyUpdateOnce() throws Exception {
		
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);

		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();

		statefulKeyManager.updateKeyInAdvance(2);
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 2);
		
		byte[] signature = null;
		
		signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(signature), statefulKeyManager.getPublicKey()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 2);
		
		signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(signature), statefulKeyManager.getPublicKey()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 2);

		signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(signature), statefulKeyManager.getPublicKey()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 3);
		
		signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(signature), statefulKeyManager.getPublicKey()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 4);
		
		statefulKeyManager.updateKeyInAdvance(5);
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 9);
		
	}
	
	@Test
	void initializeWithProfiles() throws Exception {
		
		AlgorithmParameters algorithmParameters = AlgorithmParameters.XMSSforSmallSignatures();
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);

		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();
		
		XMSSParameters parameters = (XMSSParameters) statefulKeyManager.getParameters();
		assertEquals(parameters.getHeight(), 5);
		assertEquals(parameters.getTreeDigest(), "SHA256");
		
	}
	
	@Test
	void verifySignature() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		
		byte[] signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()), new ByteArrayInputStream(signature), signer.getPublicKey()));
	}
	
//	@Test
//	void remainingKeysWarning() throws Exception {
//		KeyManager keyManager = KeyManager.getInstance(KeyManager.Algorithm.XMSS, new XMSSParameters(3, "SHA256"), null);
//		keyManager.castToStatefulKeyManager().updateKeyInAdvance(7);
//	}
	
	@Test
	void storeAndLoadKeys() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		KeyManager keyManager = signer.getKeyManager();
		
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		
		assertEquals(3, keyManager.castToStatefulKeyManager().getKeyIndex());
		
		EasySigner signer2 = EasySigner.withExistingKeyPair(keystoreParameters);
		
		KeyManager keyManager2 = signer2.getKeyManager();
		
		assertEquals(3, keyManager2.castToStatefulKeyManager().getKeyIndex());
		
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		
		assertEquals(7, keyManager2.castToStatefulKeyManager().getKeyIndex());
	}
	
	@Test
	void usingConstructor() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		EasySigner signer = new EasySigner(keyManager);
		byte[] signature = signer.sign("Hello, World!".getBytes());
		assertTrue(EasySigner.verify("Hello, World!".getBytes(), signature, signer.getPublicKey()));
	}
	
	@Test
	void signMultiple() throws Exception {
		XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSS"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		EasySigner signer = new EasySigner(keyManager);
		
		byte[][] data = {"1".getBytes(), "2".getBytes(), "3".getBytes()};
		ArrayList<byte[]> signatures = signer.signMultipleData(data);
		
		for  (int i = 0; i < signatures.size(); i++) {
			assertTrue(EasySigner.verify(data[i], signatures.get(i), signer.getPublicKey()));
		}	
	}
	
//	@Test
//	void getMultiplePrivateKeys() throws Exception {
//		XMSSParameterSpec parameterSpec = new XMSSParameterSpec(5, XMSSParameterSpec.SHA256);
//		KeyManager keyManager = KeyManager.getInstance(KeyManager.XMSS, parameterSpec);
//		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) keyManager;
//		
//		PrivateKey[] privateKeys = statefulKeyManager.getPrivateKeys(5);
//		
//		assertEquals(privateKeys.length, 5);
//		assertEquals(statefulKeyManager.getKeyIndex(privateKeys[0]), 0);
//		assertEquals(statefulKeyManager.getKeyIndex(privateKeys[4]), 4);		
//	}
}
