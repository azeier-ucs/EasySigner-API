package easysigner;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey;

import apiusability.helper.HelperFunctions;
import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.ECDSAParameters;
import easysigner.parameters.KeystoreParameters;
import easysigner.parameters.RSAParameters;
import easysigner.parameters.StorageParameters;
import easysigner.parameters.XMSSMTParameters;
import easysigner.parameters.XMSSParameters;

/**
 * The KeyManager handles a stateless or stateful key pair and the corresponding
 * certificates. To initialize a KeyManager object, the static methods 
 * {@link #loadKeyPair(StorageParameters storageParameters)} or {@link #createNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)}
 * can be used to load an existing key pair or create a new one. 
 * 
 * <p>
 * See {@link easysigner.StatelessKeyManager
 * StatelessKeyManager} and
 * {@link easysigner.StatefulKeyManager StatefulKeyManager}
 * for details about the different KeyManagers.
 * 
 * 
 *
 */
public abstract class KeyManager {

	AlgorithmParameters.Algorithm algorithm;
	AlgorithmParameters algorithmParameters;

	PublicKey publicKey;
	PrivateKey privateKey;
	Certificate certificate;

	StorageParameters storageParameters;

	KeyStore keystore;
	
	static HashMap<String, KeyManager> keyManagers = new HashMap<String, KeyManager>();

	static {
		Provider bcpqcProvider = new BouncyCastlePQCProvider();
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcpqcProvider);
		Security.addProvider(bcProvider);
	}
	
	/**
	 * Creates a  KeyManager with a newly generated key pair. The location of the key pair and other information to access the key pair
	 * are given by the {@link StorageParameters storageParameters}. The algorithm to use with all necessary parameters are given by the
	 * {link AlgorithmParameters algorithmParameters}. Depending on the algorithm, a {@link StatelessKeyManager} or a {@link StatefulKeyManager}
	 * is created.
	 * <p>
	 * Example (creating an XMSS key pair):
	 * <pre>
	 * {@code
	 * XMSSParameters algorithmParameters = new XMSSParameters(5, XMSSParameters.SHA256)
	 * KeystoreParameters keystoreParameters = new KeystoreParameters("data/keyXMSS", "123456");
	 * KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, keystoreParameters);
	 * }
	 * </pre>
	 * 
	 * @param algorithmParameters The parameters defining the signature algorithm with the necessary parameters.
	 * @param storageParameters The parameters defining the storage location and everything else necessary to access the key pair.
	 * @return An instance of the KeyManager.
	 * @throws FileAlreadyExistsException If the file already exists.
	 * @throws NoSuchAlgorithmException If the key pair belongs to an algorithm that is not supported by this KeyManager.
	 */
	public static KeyManager createNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters) throws NoSuchAlgorithmException, FileAlreadyExistsException {

		if (algorithmParameters instanceof XMSSParameters || algorithmParameters instanceof XMSSMTParameters) {
			return StatefulKeyManager.createNewKeyPair(algorithmParameters, storageParameters);
		}
		else if (algorithmParameters instanceof RSAParameters || algorithmParameters instanceof ECDSAParameters) {
			throw new NoSuchAlgorithmException("RSA and ECDSA signature schemes are not implemented in this prototype.");
		}
		else {
			throw new NoSuchAlgorithmException("The given algorithm is currently not supported!");
		}
		
	}
	
	/**
	 * Creates a KeyManager with an existing key pair. The location of the key pair and other information to access the key pair are
	 * given by the {@link StorageParameters storageParameters}. Depending on the type of keys, a {@link StatelessKeyManager} or a {@link StatefulKeyManager}
	 * is created.
	 * <p>
	 * Example (loading an XMSSMT key pair):
	 * <pre>
	 * {@code
	 * KeystoreParameters keystoreParameters = new KeystoreParameters("data/keyXMSSMT", "123456");
	 * KeyManager keyManager = KeyManager.loadKeyPair(keystoreParameters);
	 * }
	 * </pre>
	 * 
	 * @param storageParameters The parameters defining the storage location and everything else necessary to access the key pair.
	 * @return The KeyManager
	 * @throws FileNotFoundException If the file couldn't be found.
	 * @throws NoSuchAlgorithmException If the key pair belongs to an algorithm that is not supported by this KeyManager.
	 */
	public static KeyManager loadKeyPair(StorageParameters storageParameters) throws FileNotFoundException, NoSuchAlgorithmException, IllegalArgumentException {
		
		if (storageParameters instanceof KeystoreParameters) {
			KeystoreParameters keystoreParameters = (KeystoreParameters) storageParameters;
			if (keyManagers.containsKey(keystoreParameters.getFile().getAbsolutePath())) {
				return keyManagers.get(keystoreParameters.getFile().getAbsolutePath());
			}
			return loadKeyPairFromKeyStore((keystoreParameters));
		}
		else {
			throw new IllegalArgumentException("This type of storageParameters is currently not supported!");
		}

	}

	private static KeyManager loadKeyPairFromKeyStore(KeystoreParameters keystoreParameters) throws NoSuchAlgorithmException {

		KeyManager keyManager = null;
		
		FileInputStream fio;
		try {
			fio = new FileInputStream(keystoreParameters.getFile());
			KeyStore keystore = KeyStore.getInstance("jks");
			keystore.load(fio, keystoreParameters.getKeystorePassword().toCharArray());
			PrivateKey privateKey = (PrivateKey) keystore.getKey(keystoreParameters.getPrivateKeyAlias(),
					keystoreParameters.getPrivateKeyPassword().toCharArray());
			PublicKey publicKey = keystore.getCertificate(keystoreParameters.getCertifictaeAlias()).getPublicKey();
			Certificate certificate = keystore.getCertificate(keystoreParameters.getCertifictaeAlias());
			fio.close();

			if (privateKey instanceof BCXMSSPrivateKey && publicKey instanceof BCXMSSPublicKey) {
				BCXMSSPrivateKey xmssPrivateKey = (BCXMSSPrivateKey) privateKey;
				keyManager = new StatefulKeyManager();
				AlgorithmParameters.Algorithm algorithm = AlgorithmParameters.Algorithm.XMSS;
				XMSSParameters parameters = new XMSSParameters(xmssPrivateKey.getHeight(),
						xmssPrivateKey.getTreeDigest());
				keyManager.algorithm = algorithm;
				keyManager.algorithmParameters = parameters;
				keyManager.privateKey = StatefulKeyManager.copyPrivateKey(privateKey); // create BDS state
			} else if (privateKey instanceof BCXMSSMTPrivateKey && publicKey instanceof BCXMSSMTPublicKey) {
				BCXMSSMTPrivateKey xmssmtPrivateKey = (BCXMSSMTPrivateKey) privateKey;
				keyManager = new StatefulKeyManager();
				AlgorithmParameters.Algorithm algorithm = AlgorithmParameters.Algorithm.XMSSMT;
				XMSSMTParameters parameters = new XMSSMTParameters(xmssmtPrivateKey.getHeight(),
						xmssmtPrivateKey.getLayers(), xmssmtPrivateKey.getTreeDigest());
				keyManager.algorithm = algorithm;
				keyManager.algorithmParameters = parameters;
				keyManager.privateKey = StatefulKeyManager.copyPrivateKey(privateKey); // create BDS state
			} else if (privateKey instanceof RSAPrivateKey && publicKey instanceof RSAPublicKey) {
				throw new NoSuchAlgorithmException("TODO: RSA signature scheme not implemented in prototype.");
				//keyManager.privateKey = privateKey;
			} else {
				throw new NoSuchAlgorithmException("The key pair stored in the KeyStore is currently not supported.");
			}
			
			keyManager.publicKey = publicKey;
			keyManager.certificate = certificate;
			
			keyManager.storageParameters = keystoreParameters;
			keyManager.keystore = keystore;

		} catch (KeyStoreException | CertificateException | IOException | UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return keyManager;

	}

	/**
	 * Get the algorithm name.
	 * 
	 * @return The name of the algorithm.
	 */
	public String getAlgorithm() {
		return algorithm.getAlgorithm();
	}

	AlgorithmParameters getParameters() {
		return algorithmParameters;
	}

	/**
	 * Get the public part of the key pair managed by the KeyManager.
	 * 
	 * @return The public key.
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Get the private part of the key pair managed by the KeyManager.
	 * 
	 * @return The private key.
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Get the certificate associated with the public key managed by the KeyManager.
	 * 
	 * @return The certificate.
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	/**
	 * Casts this KeyManager to an instance of {@link StatefulKeyManager} in case some of the 
	 * special functionality only provided by a StatefulKeyManager is needed.
	 * 
	 * @return This KeyManager as an instance of {@link StatefulKeyManager}.
	 */
	public StatefulKeyManager castToStatefulKeyManager() {
		return (StatefulKeyManager) this;
	}
	
	void storeKey(Certificate[] certChain) throws KeyStoreException { // TODO Exception Handling

		try {

			Certificate[] chain = { HelperFunctions.createSelfSignedCertificate(publicKey, privateKey) };
			if (chain != null) {
				chain = certChain;
			}

			// Create keystore
			if (keystore == null) {
				KeyStore ks = KeyStore.getInstance("jks");
				ks.load(null, null);
				keystore = ks;
			}

			// Store key
			keystore.setKeyEntry(((KeystoreParameters) storageParameters).getPrivateKeyAlias(), privateKey, ((KeystoreParameters) storageParameters).getPrivateKeyPassword().toCharArray(), chain);
			keystore.setCertificateEntry(((KeystoreParameters) storageParameters).getCertifictaeAlias(), chain[0]);

			FileOutputStream out = new FileOutputStream(((KeystoreParameters) storageParameters).getFile()); // TODO generalize
			keystore.store(out, ((KeystoreParameters) storageParameters).getKeystorePassword().toCharArray());
			out.flush();
			out.close();
		} catch (OperatorCreationException | CertificateException | IOException
				| NoSuchAlgorithmException e) {// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	void storeKey(PrivateKey privateKey, PublicKey publicKey, Certificate[] certChain) throws CertificateException {

		try {
			Certificate[] chain = null;

			if (certChain != null) {
				chain = certChain;
				certificate = certChain[certChain.length - 1]; // TODO in which order are the certificates listed?
			}

			// Create keystore
			if (keystore == null) { // TODO load existing keystore
				if (chain == null) {
					chain = new Certificate[] { HelperFunctions.createSelfSignedCertificate(publicKey, privateKey) };
					certificate = chain[chain.length - 1];
				}

				keystore = KeyStore.getInstance("jks");
				keystore.load(null, null);
			}

			if (chain == null) {
				chain = new Certificate[] { keystore.getCertificate(((KeystoreParameters) storageParameters).getCertifictaeAlias()) };
				certificate = chain[chain.length - 1];
			}

			// Store key
			keystore.setKeyEntry(((KeystoreParameters) storageParameters).getPrivateKeyAlias(), privateKey, ((KeystoreParameters) storageParameters).getPrivateKeyPassword().toCharArray(), chain);
			keystore.setCertificateEntry(((KeystoreParameters) storageParameters).getCertifictaeAlias(), chain[0]);

			FileOutputStream out = new FileOutputStream(((KeystoreParameters) storageParameters).getFile()); // TODO generalize
			keystore.store(out, ((KeystoreParameters) storageParameters).getKeystorePassword().toCharArray());
			out.flush();
			out.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | IOException | OperatorCreationException e) {
			// do nothing
			e.printStackTrace();
		}

	}

	/**
	 * This method should only be implemented for stateful schemes. To provide an identical interface for all schemes,
	 * this method can be called from stateless schemes with no effect.
	 * 
	 * @param numberOfUpdates
	 *            The number of times the private key is updated in advanced.
	 * @see StatefulKeyManager More information about stateful signature schemes.
	 */
	public void updateKeyInAdvance(int numberOfUpdates) {
		// does nothing for stateless schemes
	}
	
	/**
	 * This method returns an instance of {@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}, depending on the given {@link Algorithm}. Further
	 * parameters for the algorithm have to be specified as parameterSpec. Instead
	 * {@link KeyManager#getInstance(Profile, String)} methods can be used, offering
	 * predefined profiles.
	 * 
	 * @param algorithm
	 *            The cryptography {@link Algorithm} to be used.
	 * @param parameters
	 *            The parameters to be used for the given {@link Algorithm}.
	 * @param storageLocation
	 *            The path under which the KeyStore file should be stored. When
	 *            given null as parameter the default location "data/key" is used.
	 * @return An instance of {@link KeyManager} ({@link StatelessKeyManager} or
	 *         {@link StatefulKeyManager}).
	 * @throws Exception
	 */
//	private static KeyManager getInstance(AlgorithmParameters parameters, StorageParameters storageParameters)
//			throws NoSuchAlgorithmException, IllegalArgumentException {
//
//		if (algorithm == null) {
//			throw new IllegalArgumentException("Algorithm has to be set.");
//		}
//
//		if (algorithm == Algorithm.XMSS || algorithm == Algorithm.XMSSMT) {
//			return new StatefulKeyManager(algorithm, parameters, storageLocation);
//		} else if (algorithm == Algorithm.RSA || algorithm == Algorithm.ECDSA) {
//			return new StatelessKeyManager(algorithm, parameters, storageLocation);
//		} else {
//			throw new NoSuchAlgorithmException("The algorithm is not supported.");
//		}
//
//	}

	/**
	 * Returns an instance of {@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}, depending on the given {@link Profile}. The
	 * profile holds the necessary parameters to create a new key pair. For more
	 * control over the used parameters,
	 * {@link KeyManager#getInstance(Algorithm, AlgorithmParameters, String)} method
	 * can be used. If there is already a file stored at storageLocation, the
	 * KeyManager will try to load the file. Otherwise, a new file is generated.
	 * TODO specified parameters match the loaded keystore
	 * 
	 * 
	 * @param profile
	 *            The {@link Profile} that should be used.
	 * @param storageLocation
	 *            The path under which the KeyStore file should be stored. When
	 *            given null as parameter the default location "data/key" is used.
	 * @return An instance of KeyManager (StatelessKeyManager or
	 *         StatefulKeyManager).
	 * @throws NoSuchAlgorithmException
	 * @throws IllegalArgumentException
	 */
//	public static KeyManager getInstance(Profile profile, String storageLocation)
//			throws NoSuchAlgorithmException, IllegalArgumentException {
//
//		if (profile == null) {
//			throw new IllegalArgumentException("Profile has to be set.");
//		}
//
//		if (profile == Profile.XMSSforFASTandSMALLSIGNATURES || profile == Profile.XMSSMTforMANYSIGNATURES) {
//			return new StatefulKeyManager(profile, storageLocation);
//		}
//		// else if (algorithm == "RSA" || algorithm == "ECDSA") {
//		// return new StatelessKeyManager(algorithm, profile);
//		// } TODO RSA and ECDSA profiles
//		else {
//			throw new IllegalArgumentException(
//					"Please use one of the supported profiles: XMSSforFASTandSMALLSIGNATURES, XMSSMTforMANYSIGNATURES");
//		}
//
//	}

	/**
	 * Get the path to the location where the key pair is stored.
	 * 
	 * @return The location path.
	 */
//	public String getStorageLoaction() {
//		return storageLocation;
//	}

	/**
	 * Set the path to the location where the key pair is stored.
	 * 
	 * @param storageLocation
	 *            The location path.
	 */
//	public void setStorageLoaction(String storageLocation) {
//		this.storageLocation = storageLocation;
//	}

}
