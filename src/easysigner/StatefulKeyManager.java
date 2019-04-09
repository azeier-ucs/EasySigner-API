package easysigner;

import java.io.File;
import java.nio.file.FileAlreadyExistsException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.StateAwareSignature;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.XMSSMTParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.XMSSParameterSpec;

import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.KeystoreParameters;
import easysigner.parameters.StorageParameters;
import easysigner.parameters.XMSSMTParameters;
import easysigner.parameters.XMSSParameters;

/**
 * To initialize, use the static methods {@link #loadKeyPair(StorageParameters storageParameters)} or 
 * {@link #createNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)} 
 * of {@link KeyManager}.
 * <p>
 * This KeyManager handles stateful key pairs. Currently the signatures schemes
 * XMSS and XMSSMT are supported. In these schemes the private key is stateful,
 * meaning it has to be updated after every signature to keep the scheme secure.
 * The update process as well as the persistent storage of the key material is
 * taken care of by the KeyManager.
 * <p>
 * When choosing the parameters to be used for stateful signature schemes, the
 * limited number of signatures that can be created has to be taken into
 * account. This KeyManager will give out a warning when the available
 * signatures will reach their end, so that a new key pair can be created right
 * in time.
 * 
 *
 */
public class StatefulKeyManager extends KeyManager {

	private static final Logger log = Logger.getLogger(KeyManager.class.getName());

	private static String PROVIDER = "BCPQC";

	private String algorithmWithDigest;
	// private StateAwareSignature sig;
	private long currentlyStoredIndex;
	private AlgorithmParameterSpec parameterSpec;

	StatefulKeyManager() {

	}

	public static KeyManager createNewKeyPair(AlgorithmParameters algorithmParameters,
			StorageParameters storageParameters)
			throws FileAlreadyExistsException, NoSuchAlgorithmException, IllegalArgumentException {

		if (storageParameters instanceof KeystoreParameters) {
			KeyManager keyManager = createNewKeyPairToKeyStore(algorithmParameters, ((KeystoreParameters) storageParameters));
			log.info("A new stateful keypair was created and stored in a KeyStore file. If you are using the EasySigner, the state will be handled for you. "
					+ "Never copy the KeyStore file. This will probably lead to multiple usage of a single state and compromise the key pair.");
			return keyManager;
		} else {
			throw new IllegalArgumentException("The given type of storageParameters is currently not supported!");
		}

	}

	private static KeyManager createNewKeyPairToKeyStore(AlgorithmParameters algorithmParameters,
			KeystoreParameters keystoreParameters) throws NoSuchAlgorithmException, FileAlreadyExistsException, IllegalArgumentException {

		if (algorithmParameters == null || keystoreParameters == null) {
			throw new IllegalArgumentException("algorithmParameters and storageParameters must not be null!");
		}

		StatefulKeyManager keyManager = new StatefulKeyManager();
		AlgorithmParameters.Algorithm algorithm;

		if (algorithmParameters instanceof XMSSParameters) {
			algorithm = AlgorithmParameters.Algorithm.XMSS;
			keyManager.algorithm = algorithm;
		} else if (algorithmParameters instanceof XMSSMTParameters) {
			XMSSMTParameters xmssmtParameters = (XMSSMTParameters) algorithmParameters;
			if (xmssmtParameters.getHeight() < 8) {
				throw new IllegalArgumentException("Height has to be 8 or more.");
			}
			if ((xmssmtParameters.getHeight() / xmssmtParameters.getLayers()) < 4) {
				throw new IllegalArgumentException("Height / layers has to be 4 or more.");
			}
			algorithm = AlgorithmParameters.Algorithm.XMSSMT;
			keyManager.algorithm = algorithm;
		} else {
			throw new NoSuchAlgorithmException("The algorithm is currently not supported!");
		}

		keyManager.algorithmParameters = algorithmParameters;
		keyManager.storageParameters = keystoreParameters;
		
		String hashAlgorithm;

		if (algorithm == AlgorithmParameters.Algorithm.XMSS) {
			XMSSParameters xmssParams = (XMSSParameters) algorithmParameters;
			hashAlgorithm = xmssParams.getTreeDigest();
			keyManager.algorithmWithDigest = hashAlgorithm + "with" + "XMSS"; 
			XMSSParameterSpec xmssSpec = new XMSSParameterSpec(xmssParams.getHeight(), xmssParams.getTreeDigest());
			keyManager.parameterSpec = xmssSpec;
		} else if (algorithm == AlgorithmParameters.Algorithm.XMSSMT) {
			XMSSMTParameters xmssmtParams = (XMSSMTParameters) algorithmParameters;
			hashAlgorithm = xmssmtParams.getTreeDigest();
			keyManager.algorithmWithDigest = hashAlgorithm + "with" + "XMSSMT"; 
			XMSSMTParameterSpec xmssmtSpec = new XMSSMTParameterSpec(xmssmtParams.getHeight(), xmssmtParams.getLayers(),
					xmssmtParams.getTreeDigest());
			keyManager.parameterSpec = xmssmtSpec;
		} else {
			throw new NoSuchAlgorithmException("Algorithm not supported!");
		}
		
		if (hashAlgorithm != "SHA256" && hashAlgorithm != "SHA512" && hashAlgorithm != XMSSParameters.SHAKE128 && hashAlgorithm != XMSSParameters.SHAKE256) {
			throw new IllegalArgumentException("The chosen hash algorithm \"" + hashAlgorithm + "\" is not supported.");
		}

		File file = keystoreParameters.getFile();
		if (file.exists() && !file.isDirectory()) {
			throw new FileAlreadyExistsException(file.getPath());
		} else {
			KeyPairGenerator kpg;
			try {
				kpg = KeyPairGenerator.getInstance(algorithm.getAlgorithm(), PROVIDER);
				kpg.initialize(keyManager.parameterSpec, new SecureRandom());
				KeyPair kp = kpg.generateKeyPair();

				keyManager.privateKey = kp.getPrivate();
				keyManager.publicKey = kp.getPublic();

				if (algorithm == AlgorithmParameters.Algorithm.XMSSMT) {
					// init key to circumvent strange behaviour that when copying the key, it is not
					// initialized
					XMSSMTParameters xmssmtParameters = (XMSSMTParameters) algorithmParameters;
					StateAwareSignature xmssSig = (StateAwareSignature) Signature.getInstance(xmssmtParameters.getTreeDigest() + "withXMSSMT",
							"BCPQC");
					xmssSig.initSign(keyManager.privateKey);
					keyManager.privateKey = xmssSig.getUpdatedPrivateKey();
				}

				keyManager.storeKey(keyManager.privateKey, keyManager.publicKey, null);
			} catch (NoSuchProviderException | InvalidAlgorithmParameterException | InvalidKeyException
					| CertificateException e) {
				// User has no impact on those parameters
				e.printStackTrace();
			}

		}
		
		return keyManager;
	}

	/**
	 * Get the private key managed by the KeyManager. The private key is then
	 * updated by the KeyManager and stored at the location specified in
	 * storageLocation.
	 * 
	 * @return The private key.
	 */
	@Override
	synchronized public PrivateKey getPrivateKey() {

		PrivateKey oldPrivateKey = copyPrivateKey(privateKey);
		privateKey = updateKey(1);

		if (getKeyIndex(privateKey) > currentlyStoredIndex) {
			try {
				storeKey(privateKey, publicKey, null);
			} catch (CertificateException e) {
				// This can be ignored, only the private key is updated, no new certificate
				// chain is stored.
			}
		}

		return oldPrivateKey;

	}

	/**
	 * Updates the stateful private key n times in advance (n being the given
	 * numberOfUpdates) and stores it at the specified storage location, reserving
	 * the n states between the origin state and the updates state for signing. <br>
	 * After using this method n signatures can be done without storing the private
	 * key again, leading to more efficient signing.
	 * <p>
	 * This method should only be used with caution. The reserved n states will be
	 * lost after reloading the key from the storage location (e.g. when the
	 * application was restarted).
	 * <p>
	 * Updating the private key in advance to do 3 signatures would look like this:
	 * 
	 * <pre>
	 * {@code
	 * ...
	 * StorageParameters storageParameters = ...;
	 * KeyManager keyManager = KeyManager.loadKeyPair(storageParameters);
	 * keyManager.castToStatefulKeyManager().updateKeyInAdvance(3);
	 * byte[] signature1 = signer.sign(data1);
	 * byte[] signature2 = signer.sign(data2);
	 * byte[] signature3 = signer.sign(data3);
	 * }
	 * </pre>
	 * 
	 * 
	 * @param numberOfUpdates
	 *            The number of times the private key is updated in advanced.
	 * @see StatefulKeyManager More information about stateful signature schemes.
	 */
	@Override
	public void updateKeyInAdvance(int numberOfUpdates) {

		PrivateKey keyToStore = updateKey(numberOfUpdates);

		try {
			storeKey(keyToStore, publicKey, null);
		} catch (CertificateException e) {
			// Should not happen, because no new certificate is stored.
			e.printStackTrace();
		}

	}

	String getAlgorithmWithDigest() {
		return algorithmWithDigest;
	}

	long getCurrentStoredIndex() {
		return currentlyStoredIndex;
	}

	PrivateKey updateKey(int numberOfUpdates) {

		PrivateKey privateKey = null;

		try {
			privateKey = this.privateKey;
			StateAwareSignature sig = (StateAwareSignature) Signature.getInstance("SHA256" + "with" + this.getAlgorithm(), PROVIDER);
			for (int i = 0; i < numberOfUpdates; i++) {
				sig.initSign(privateKey);
				sig.update("Create Next Signature".getBytes());
				sig.sign();
				privateKey = sig.getUpdatedPrivateKey();
			}
		} catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Can one of the exceptions happen at this point? How to handle them?
			e.printStackTrace();
		}

		double remainingKeys = 1 - StatefulKeyManager.getKeyIndex(privateKey) / Math.pow(2, this.getHeight(privateKey));
		if (remainingKeys <= 0.25) {
			if (remainingKeys > 0.05) { // TODO warning every time or just at some thresholds?
				log.warning("Only " + remainingKeys * 100 + "% of key states remaining! New keypair is required soon.");
			} else if (remainingKeys <= 0.05) {
				log.severe("Only " + remainingKeys * 100
						+ "% of key states remaining! New keypair is required very soon to do further signing.");
			}
		}

		return privateKey;
	}

	long getKeyIndex() {

		if (algorithm == AlgorithmParameters.Algorithm.XMSS) {
			BCXMSSPrivateKey xmssPrivateKey = (BCXMSSPrivateKey) privateKey;
			XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters) xmssPrivateKey.getKeyParams();
			return keyParams.getIndex();
		} else if (algorithm == AlgorithmParameters.Algorithm.XMSSMT) {
			BCXMSSMTPrivateKey xmssPrivateKey = (BCXMSSMTPrivateKey) privateKey;
			XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters) xmssPrivateKey.getKeyParams();
			return keyParams.getIndex();
		} else
			return -1; // TODO better return value
	}

	static long getKeyIndex(PrivateKey privateKey) {

		if (privateKey.getAlgorithm() == "XMSS") {
			BCXMSSPrivateKey xmssPrivateKey = (BCXMSSPrivateKey) privateKey;
			XMSSPrivateKeyParameters keyParams = (XMSSPrivateKeyParameters) xmssPrivateKey.getKeyParams();
			return keyParams.getIndex();
		} else if (privateKey.getAlgorithm() == "XMSSMT") {
			BCXMSSMTPrivateKey xmssPrivateKey = (BCXMSSMTPrivateKey) privateKey;
			XMSSMTPrivateKeyParameters keyParams = (XMSSMTPrivateKeyParameters) xmssPrivateKey.getKeyParams();
			return keyParams.getIndex();
		} else
			return -1; // TODO better return value
	}

	long getHeight(PrivateKey privateKey) {
		if (algorithm == AlgorithmParameters.Algorithm.XMSS) {
			BCXMSSPrivateKey xmssPrivateKey = (BCXMSSPrivateKey) privateKey;
			return xmssPrivateKey.getHeight();
		} else if (algorithm == AlgorithmParameters.Algorithm.XMSSMT) {
			BCXMSSMTPrivateKey xmssmtPrivateKey = (BCXMSSMTPrivateKey) privateKey;
			return xmssmtPrivateKey.getHeight();
		} else
			return -1; // TODO better return value
	}

	@Override
	void storeKey(PrivateKey privateKey, PublicKey publicKey, Certificate[] certChain) throws CertificateException {

		currentlyStoredIndex = getKeyIndex(privateKey);
		super.storeKey(privateKey, publicKey, certChain);

	}

	static PrivateKey copyPrivateKey(PrivateKey privateKey) {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm(), "BCPQC");
			PrivateKeyInfo pKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
			ASN1Sequence seq = ASN1Sequence.getInstance(pKeyInfo.parsePrivateKey());

			if (privateKey instanceof BCXMSSPrivateKey) {
				pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(),
						new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0), seq.getObjectAt(1) }));
			} else if (privateKey instanceof BCXMSSMTPrivateKey) {
				pKeyInfo = new PrivateKeyInfo(pKeyInfo.getPrivateKeyAlgorithm(), 
						new DERSequence(new ASN1Encodable[] { seq.getObjectAt(0), seq.getObjectAt(1) }));
			}

			return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(pKeyInfo.getEncoded()));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
}
