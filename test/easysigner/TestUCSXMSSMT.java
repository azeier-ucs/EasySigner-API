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
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import easysigner.EasySigner;
import easysigner.KeyManager;
import easysigner.StatefulKeyManager;
import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.KeystoreParameters;
import easysigner.parameters.XMSSMTParameters;
import easysigner.parameters.XMSSParameters;

class TestUCSXMSSMT {

	@BeforeAll
	static void initialize() {
		Provider bcpqcProvider = new BouncyCastlePQCProvider();
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcpqcProvider);
		Security.addProvider(bcProvider);

		File file = new File("data/keyXMSSMT");
		file.delete();
	}

	@AfterEach
	void clean() {
		File file = new File("data/keyXMSSMT");
		file.delete();
	}

	@Test
	void testKeyManager() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		assertTrue(keyManager.getPrivateKey() instanceof BCXMSSMTPrivateKey);
		assertTrue(keyManager instanceof StatefulKeyManager);
	}

	@Test
	void testSigning() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
	}

	@Test
	void testSignMultipleTimes() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		byte[] sig1 = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		byte[] sig2 = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));

		assertTrue(!Arrays.equals(sig1, sig2));
	}

	@Test
	void getPrivateKeyIndex() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();

		assertEquals(statefulKeyManager.getKeyIndex(), 1);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));

		assertEquals(statefulKeyManager.getKeyIndex(), 2);
	}

	@Test
	void signMultipleTimesAndOnlyUpdateOnce() throws Exception {

		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();

		statefulKeyManager.updateKeyInAdvance(4);
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 5);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 5);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 5);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 5);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 5);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 6);

		statefulKeyManager.updateKeyInAdvance(10);
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 16);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 16);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 16);

		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		assertEquals(statefulKeyManager.getCurrentStoredIndex(), 16);

	}

	@Test
	void initializeWithProfiles() throws Exception {

		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		StatefulKeyManager statefulKeyManager = (StatefulKeyManager) signer.getKeyManager();

		XMSSMTParameters parameters = (XMSSMTParameters) statefulKeyManager.getParameters();
		assertEquals(parameters.getHeight(), 10);
		assertEquals(parameters.getLayers(), 2);
		assertEquals(parameters.getTreeDigest(), "SHA256");

	}

	@Test
	void verifySignature() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		byte[] signature = signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));

		assertTrue(EasySigner.verify(new ByteArrayInputStream("Hello, World!".getBytes()),
				new ByteArrayInputStream(signature), signer.getPublicKey()));
	}

	@Test
	void storeAndLoadKeys() throws Exception {
		AlgorithmParameters algorithmParameters = AlgorithmParameters.XMSSMTforFastSigning();
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer.sign(new ByteArrayInputStream("Hello, World!".getBytes()));

		assertEquals(4, signer.getKeyManager().castToStatefulKeyManager().getKeyIndex());

		EasySigner signer2 = EasySigner.withExistingKeyPair(keystoreParameters);

		assertEquals(4, signer2.getKeyManager().castToStatefulKeyManager().getKeyIndex());

		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));
		signer2.sign(new ByteArrayInputStream("Hello, World!".getBytes()));

		assertEquals(8, signer2.getKeyManager().castToStatefulKeyManager().getKeyIndex());
	
	}

	@Test
	void task4() throws Exception {
		String[] messages = new String[] { "1", "2", "3" };

		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
		for (String toBeSignedString : messages) {
			byte[] toBeSigned = toBeSignedString.getBytes();
			byte[] signature = signer.sign(new ByteArrayInputStream(toBeSigned));
		}
		
		
	}
	
	@Test
	void usingConstructor() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		EasySigner signer = new EasySigner(keyManager);
		byte[] signature = signer.sign("Hello, World!".getBytes());
		assertTrue(EasySigner.verify("Hello, World!".getBytes(), signature, signer.getPublicKey()));
	}
	
	@Test
	void signMultiple() throws Exception {
		XMSSMTParameters algorithmParameters = new XMSSMTParameters(10, 2, XMSSMTParameters.SHA256);
		KeystoreParameters keystoreParameters = new KeystoreParameters(new File("data/keyXMSSMT"), "12345");
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
		EasySigner signer = new EasySigner(keyManager);
		
		byte[][] data = {"1".getBytes(), "2".getBytes(), "3".getBytes()};
		ArrayList<byte[]> signatures = signer.signMultipleData(data);
		
		for  (int i = 0; i < signatures.size(); i++) {
			assertTrue(EasySigner.verify(data[i], signatures.get(i), signer.getPublicKey()));
		}	
	}

	// @Test
	// void getMultiplePrivateKeys() throws Exception {
	// XMSSMTParameterSpec parameterSpec = new XMSSMTParameterSpec(10, 2,
	// XMSSMTParameterSpec.SHA256);
	// KeyManager keyManager = KeyManager.getInstance(KeyManager.XMSSMT,
	// parameterSpec);
	// StatefulKeyManager statefulKeyManager = (StatefulKeyManager) keyManager;
	//
	// PrivateKey[] privateKeys = statefulKeyManager.getPrivateKeys(20);
	//
	// assertEquals(privateKeys.length, 20);
	// assertEquals(statefulKeyManager.getKeyIndex(privateKeys[0]), 0);
	// assertEquals(statefulKeyManager.getKeyIndex(privateKeys[19]), 19);
	// }

	// @Test
	// public void testKeyRebuild()
	// throws Exception
	// {
	// byte[] msg = Strings.toByteArray("Cthulhu Fthagn --What a wonderful
	// phrase!Cthulhu Fthagn --Say it and you're crazed!");
	//
	// KeyPairGenerator kpg = KeyPairGenerator.getInstance("XMSSMT", "BCPQC");
	//
	// kpg.initialize(new XMSSMTParameterSpec(6, 3, XMSSMTParameterSpec.SHA256), new
	// SecureRandom());
	//
	// KeyPair kp = kpg.generateKeyPair();
	//
	// Signature sig = Signature.getInstance("SHA256withXMSSMT", "BCPQC");
	//
	// assertTrue(sig instanceof StateAwareSignature);
	//
	// StateAwareSignature xmssSig = (StateAwareSignature)sig;
	//
	//// BCXMSSMTPrivateKey xmssmtPrivateKey = (BCXMSSMTPrivateKey) kp.getPrivate();
	////
	//// BCXMSSMTPrivateKey xmssmtPrivateKey2 = (BCXMSSMTPrivateKey)
	// StatefulKeyManager.copyPrivateKey(xmssmtPrivateKey);
	////
	//// xmssSig.initSign(xmssmtPrivateKey);
	////
	//// xmssSig.update(msg, 0, msg.length);
	////
	//// byte[] signature1 = xmssSig.sign();
	////
	//// xmssSig.initSign(xmssmtPrivateKey2);
	////
	//// xmssSig.update(msg, 0, msg.length);
	////
	//// byte[] signature2 = xmssSig.sign();
	////
	//// assertEquals(signature1, signature2);
	//
	// PrivateKey pKey = kp.getPrivate();
	//
	// System.out.println("Before init: " + StatefulKeyManager.getKeyIndex(pKey));
	////
	// xmssSig.initSign(pKey);
	////
	// System.out.println("After init: " + StatefulKeyManager.getKeyIndex(pKey));
	//
	// for (int i = 0; i != 5; i++)
	// {
	// xmssSig.initSign(pKey);
	// xmssSig.update(msg, 0, msg.length);
	//
	// xmssSig.sign();
	//
	// System.out.println("While sign: " + StatefulKeyManager.getKeyIndex(pKey));
	// }
	//
	// pKey = xmssSig.getUpdatedPrivateKey();
	////
	// System.out.println("After update: " + StatefulKeyManager.getKeyIndex(pKey));
	//
	//// PrivateKey pKey = kp.getPrivate();
	//
	//// System.out.println(StatefulKeyManager.getKeyIndex(pKey));
	////
	//// pKey = xmssSig.getUpdatedPrivateKey();
	////
	//// System.out.println(StatefulKeyManager.getKeyIndex(pKey));
	//
	//// PrivateKeyInfo pKeyInfo = PrivateKeyInfo.getInstance(pKey.getEncoded());
	////
	//// KeyFactory keyFactory = KeyFactory.getInstance("XMSSMT", "BCPQC");
	////
	//// ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());
	////
	//// // create a new PrivateKeyInfo containing a key with no BDS state.
	//// pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
	//// new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0),
	// seq.getObjectAt(1) }));
	////
	//// BCXMSSMTPrivateKey privKey =
	// (BCXMSSMTPrivateKey)keyFactory.generatePrivate(new
	// PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));
	//
	// BCXMSSMTPrivateKey privKey = (BCXMSSMTPrivateKey)
	// StatefulKeyManager.copyPrivateKey(pKey);
	//
	//// xmssSig.initSign(pKey);
	////
	//// xmssSig.update(msg, 0, msg.length);
	////
	//// byte[] sig1 = xmssSig.sign();
	//
	//
	//
	// xmssSig.initSign(privKey);
	//
	// xmssSig.update(msg, 0, msg.length);
	//
	// byte[] sig2 = xmssSig.sign();
	//
	//// privKey = (BCXMSSMTPrivateKey) xmssSig.getUpdatedPrivateKey();
	////
	//// xmssSig.initSign(privKey);
	////
	//// xmssSig.update(msg, 0, msg.length);
	////
	//// byte[] sig3 = xmssSig.sign();
	////
	//// privKey = (BCXMSSMTPrivateKey) xmssSig.getUpdatedPrivateKey();
	////
	//// xmssSig.initSign(privKey);
	////
	//// xmssSig.update(msg, 0, msg.length);
	////
	//// byte[] sig4 = xmssSig.sign();
	////
	//// privKey = (BCXMSSMTPrivateKey) xmssSig.getUpdatedPrivateKey();
	//
	//
	//
	//
	// // make sure we get the same signature as the two keys should now
	// // be in the same state.
	//// assertTrue(Arrays.areEqual(sig1, sig2));
	// }
}
