package easysigner;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.FileAlreadyExistsException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey;

import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.StorageParameters;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

/**
 * The EasySigner is a signer that can handle stateless and stateful signature
 * schemes. The keypair used for signing is handled by an instance of {@link KeyManager}. After
 * initializing the EasySigner, no further interaction with the key material is
 * needed, but possible.
 * <p>
 * Use {@link EasySigner#withExistingKeyPair(StorageParameters storageParameters)} to initialize the EasySigner with
 * an existing keypair, e.g. from an {@link java.security.KeyStore KeyStore} file, or
 * {@link EasySigner#withNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)}
 * to let the EasySigner create a new keypair with the parameters given by {@link AlgorithmParameters algorithmParamters}.
 * In both cases, {@link StorageParameters storageParameters} holds all the necessary information to load and store 
 * the keypair.
 * <p>
 * When using a stateful signature scheme like XMSS or XMSSMT, <b>the statful key is automatically updated
 * and stored</b> at the specified storage location to ensure the same state is never used twice. 
 * <p>
 * <b>Example:</b> 
 * Initializing the signer for {@link easysigner.parameters.XMSSMTParameters XMSSMT} with a newly generated key pair, 
 * sign a message and verify the generated signature may look like this:
 * 
 * <pre>
 * {@code
 * String password = ...;
 * AlgorithmParameters algorithmParameters = AlgorithmParameters.XMSSMTforFastSigning();
 * KeystoreParameters keystoreParameters = new KeystoreParameters("data/keyXMSSMT", password);
 * EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
 * String toBeSigned = "Sign me!";
 * byte[] signature = signer.sign(toBeSigned.getBytes());
 * signer.verify(toBeSigned.getBytes(), signature);
 * }
 * </pre>
 * 
 *
 */
public class EasySigner {

	private KeyManager keyManager;
	private String hashAlgorithm = "SHA256";

	/**
	 * The constructor of the EasySigner. Takes an instance of {@link easysigner.KeyManager KeyManager} as parameter, containing all the 
	 * necessary information for the key pair to be used. Instead, the static methods {@link #withExistingKeyPair(StorageParameters storageParameters)} or 
	 * {@link #withNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)} can be used, creating the KeyManager for you.
	 * 
	 * @param keyManager The {@link easysigner.KeyManager KeyManager}.
	 */
	public EasySigner(KeyManager keyManager) {
		
		this.keyManager = keyManager;
		
	}
	
	/**
	 * Creates a EasySigner with an existing key pair. The location of the key pair and other information to access the key pair are
	 * given by the {@link StorageParameters storageParameters}.
	 * <p>
	 * Example (loading in XMSSMT key pair):
	 * <pre>
	 * {@code
	 * KeystoreParameters keystoreParameters = new KeystoreParameters("data/keyXMSSMT", "123456");
	 * EasySigner signer = EasySigner.withExistingKeyPair(keystoreParameters);
	 * }
	 * </pre>
	 * 
	 * @param storageParameters The parameters defining the storage location and everything else necessary to access the key pair.
	 * @return The EasySigner
	 * @throws FileNotFoundException If the file couldn't be found.
	 * @throws NoSuchAlgorithmException If the key pair belongs to an algorithm that is not supported by this Signer.
	 * @throws IllegalArgumentException If the arguments are not valid, e.g. null.
	 */
	public static EasySigner withExistingKeyPair(StorageParameters storageParameters) throws FileNotFoundException, NoSuchAlgorithmException {
		
		KeyManager keyManager = KeyManager.loadKeyPair(storageParameters);
		EasySigner signer = new EasySigner(keyManager);
		return signer;
		
	}
	
	/**
	 * Creates a EasySigner with a newly generated key pair. The location of the key pair and other information to access the key pair
	 * are given by the {@link StorageParameters storageParameters}. The algorithm to use with all necessary parameters are given by the
	 * {link AlgorithmParameters algorithmParameters}.
	 * <p>
	 * Example (creating an XMSS key pair):
	 * <pre>
	 * {@code
	 * XMSSParameters algorithmParameters = new XMSSParameters(20, XMSSParameters.SHA256)
	 * KeystoreParameters keystoreParameters = new KeystoreParameters("data/keyXMSS", "123456");
	 * EasySigner signer = EasySigner.withNewKeyPair(algorithmParameters, keystoreParameters);
	 * }
	 * </pre>
	 * 
	 * @param algorithmParameters The parameters defining the signature algorithm with the necessary parameters.
	 * @param storageParameters The parameters defining the storage location and everything else necessary to access the key pair.
	 * @return An instance of the EasySigner.
	 * @throws FileAlreadyExistsException If the file already exists.
	 * @throws NoSuchAlgorithmException If the key pair belongs to an algorithm that is not supported by this Signer.
	 */
	public static EasySigner withNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)
			throws FileAlreadyExistsException, NoSuchAlgorithmException {
		
		KeyManager keyManager = KeyManager.createNewKeyPair(algorithmParameters, storageParameters);
		EasySigner signer = new EasySigner(keyManager);
		return signer;
		
	}

	/**
	 * Sign the given byte[] toBeSigned.
	 * <p>
	 * Depending on the type of KeyManager ({@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}), a corresponding sign method is called. For the
	 * StatefulKeyManager, this signing method is synchronized to prevent concurrent
	 * signing with the stateful key. When using the StatefulKeyManager, the private
	 * key is updated after every call of the sign method and stored at the storage
	 * location specified in the KeyManager.
	 * <p>
	 * The hash algorithm used to calculate the digest which is then signed instead of 
	 * the byte[] {@code toBeSigned} is SHA256 by default.
	 * <p>
	 * Using the InputStream will leave it empty after signing is completed.
	 * <p>
	 * Signing a string message would look like this:
	 * 
	 * <pre>
	 * {@code
	 * byte[] toBeSigned = ...;
	 * byte[] signature = signer.sign(toBeSigned);
	 * }
	 * </pre>
	 * 
	 * @param toBeSigned
	 *            The File that should be signed.
	 * @return The Signature in form of a byte array.
	 * @throws IOException
	 *             if no data from the given InputStream can be read.
	 */
	public byte[] sign(byte[] toBeSigned) throws IOException {

		return sign(new ByteArrayInputStream(toBeSigned));

	}

	/**
	 * Sign the given {@link InputStream} toBeSigned. An InputStream can be
	 * generated e.g. from an byte[] with {@link ByteArrayInputStream} or a File
	 * with {@link FileInputStream}.
	 * <p>
	 * Depending on the type of keyManager ({@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}), a corresponding sign method is called. For the
	 * StatefulKeyManager, this signing method is synchronized to prevent concurrent
	 * signing with the stateful key. When using the StatefulKeyManager, the private
	 * key is updated after every call of the sign method and stored at the storage
	 * location specified in the KeyManager.
	 * <p>
	 * The hash algorithm used to calculate the digest which is then signed instead of 
	 * the byte[] {@code toBeSigned} is SHA256 by default.
	 * <p>
	 * Using the InputStream will leave it empty after signing is completed.
	 * <p>
	 * Signing a file from disk would look like this:
	 * 
	 * <pre>
	 * {@code
	 * FileInputStream toBeSigned = new FileInputStream("data/file.txt");
	 * byte[] signature = signer.sign(toBeSigned);
	 * }
	 * </pre>
	 * 
	 * @param toBeSigned
	 *            The data that should be signed.
	 * @return The Signature in form of a byte array.
	 * @throws IOException
	 *             if no data from the given InputStream can be read.
	 */
	public byte[] sign(InputStream toBeSigned) throws IOException {
		
		byte[] signature = doSigning(toBeSigned, getHashAlgorithm());
		toBeSigned.close();
		return signature;
		
	}
	
	/**
	 * Sign one or more {@link InputStream}s {@code toBeSigned}. An InputStream can be
	 * generated e.g. from an byte[] with {@link ByteArrayInputStream} or a File
	 * with {@link FileInputStream}.
	 * <p>
	 * Depending on the type of keyManager ({@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}), a corresponding sign method is called. For the
	 * StatefulKeyManager, this signing method is synchronized to prevent concurrent
	 * signing with the stateful key. When using the StatefulKeyManager, the private key
	 * is updated for every data given in {@code toBeSigned} and then stored once at the location given
	 * in the {@code StorageParameters} before executing the signatures. This method should be used instead
	 * of implementing a loop to minimize the number of store operations and thus increase the performance.
	 * <p>
	 * The hash algorithm used to calculate the digest which is then signed instead of 
	 * the byte[] {@code toBeSigned} is SHA256 by default.
	 * <p>
	 * Using the InputStream will leave it empty after signing is completed.
	 * <p>
	 * Signing two files would look like this:
	 * 
	 * <pre>
	 * {@code
	 * FileInputStream toBeSigned1 = new FileInputStream("data/file1.txt");
	 * FileInputStream toBeSigned2 = new FileInputStream("data/file2.zip");
	 * ArrayList<byte[]> signatures = signer.signMultipleData(toBeSigned1, toBeSigned2);
	 * }
	 * </pre>
	 * 
	 * @param toBeSigned
	 *            The data that should be signed. This can be one ore more {@link InputStream}s or an array of InputStreams.
	 * @return The Signatures in form of an array of a List of byte[]s.
	 * @throws IOException
	 *             if no data from the given InputStream can be read.
	 */
	public ArrayList<byte[]> signMultipleData(InputStream... toBeSigned) throws IOException {
		ArrayList<byte[]> signatures = new ArrayList<byte[]>();
		
		keyManager.castToStatefulKeyManager().updateKeyInAdvance(toBeSigned.length);
		
		for (int i = 0; i < toBeSigned.length; i++) {
			signatures.add(sign(toBeSigned[i]));
		}
		
		return signatures;
	}
	
	/**
	 * Sign one or more byte[]s {@code toBeSigned}.
	 * <p>
	 * Depending on the type of keyManager ({@link StatelessKeyManager} or
	 * {@link StatefulKeyManager}), a corresponding sign method is called. For the
	 * StatefulKeyManager, this signing method is synchronized to prevent concurrent
	 * signing with the stateful key. When using the StatefulKeyManager, the private key
	 * is updated for every data given in {@code toBeSigned} and then stored once at the location given
	 * in the {@code StorageParameters} before executing the signatures. This method should be used instead
	 * of implementing a loop to minimize the number of store operations and thus increase the performance.
	 * <p>
	 * The hash algorithm used to calculate the digest which is then signed instead of 
	 * the byte[] {@code toBeSigned} is SHA256 by default.
	 * <p>
	 * Signing two string messages would look like this:
	 * 
	 * <pre>
	 * {@code
	 * byte[] toBeSigned1 = "Sign me!".getBytes();
	 * byte[] toBeSigned2 = "Sign me, too!".getBytes();
	 * ArrayList<byte[]> signatures = signer.signMultipleData(toBeSigned1, toBeSigned2);
	 * }
	 * </pre>
	 * 
	 * @param toBeSigned
	 *            The data that should be signed. This could be one or more byte[] or an array of byte[].
	 * @return The Signatures in form of array of List of byte[]s.
	 * @throws IOException
	 *             if no data from the given InputStream can be read.
	 */
	public ArrayList<byte[]> signMultipleData(byte[]... toBeSigned) throws IOException {
		ArrayList<byte[]> signatures = new ArrayList<byte[]>();
		
		keyManager.castToStatefulKeyManager().updateKeyInAdvance(toBeSigned.length);
		
		for (int i = 0; i < toBeSigned.length; i++) {
			signatures.add(sign(toBeSigned[i]));
		}
		
		return signatures;
	}

	/**
	 * Verify the given signature, meaning that it was created from the given data
	 * with the publicKey stored in the KeyManager. The parameters must be given
	 * as {link InputStream InputStreams}. An InputStream can be generated e.g. from
	 * an byte[] with {@link ByteArrayInputStream} or a File with
	 * {@link FileInputStream}. If the data was signed with an external key, the
	 * static
	 * {@link EasySigner#verify(InputStream data, InputStream signature, PublicKey publicKey)
	 * verify} or
	 * {@link EasySigner#verify(InputStream data, InputStream signature, InputStream certificatePEM)}
	 * methods can be used.
	 * <p>
	 * Using the InputStream will leave it empty after verifying is completed.
	 * <p>
	 * Verifying a signature with this method would look like this:
	 * 
	 * <pre>
	 * {@code
	 * ...
	 * String pathToFile = ...;
	 * byte[] signature = ...;
	 * signer.verify(new FileInputStream(pathToFile), new ByteArrayInputStream(signature));
	 * }
	 * </pre>
	 * 
	 * @param data
	 *            The data that is assumed to be signed with the given publicKey.
	 * @param signature
	 *            The signature that should be verified.
	 * @return True, if the signature is valid, false otherwise.
	 * @throws SignatureException
	 *             if the given signature's format is invalid.
	 * @throws InvalidKeyException
	 *             if the public key managed by the EasySigner is not valid.
	 * @throws IOException
	 *             if no data from one of the given InputStreams can be read.
	 */
	public boolean verify(InputStream data, InputStream signature)
			throws InvalidKeyException, SignatureException, IOException {

		PublicKey publicKey = keyManager.getPublicKey();

		return verify(data, signature, publicKey);

	}

	/**
	 * Verify the given {@code signature}, meaning that it was created with the given
	 * {@code publicKey} from the given {@code data}. This method is static and can be used without
	 * initializing an instance of {@link EasySigner}. 
	 * <p>
	 * Verifying a signature with this method would look like this:
	 * 
	 * <pre>
	 * {@code
	 * ...
	 * String toBeSigned = ...;
	 * byte[] signature = ...;
	 * PublicKey publicKey = ...;
	 * signer.verify(toBeSigned.getBytes(), signature, publicKey);
	 * }
	 * </pre>
	 * 
	 * 
	 * @param data
	 *            The data that is assumed to be signed with the given publicKey.
	 * @param signature
	 *            The signature that should be verified.
	 * @param publicKey
	 *            The public key corresponding to the private key that was used to
	 *            sign the given data.
	 * @return True, if the signature is valid, false otherwise.
	 * @throws InvalidKeyException
	 *             if the given public key is not valid.
	 * @throws SignatureException
	 *             if the given signature's format is invalid.
	 * @throws IllegalArgumentException
	 *             if one of the given signature is null.
	 * @throws IOException
	 *             if no data from one of the given InputStreams can be read.
	 */
	public static boolean verify(byte[] data, byte[] signature, PublicKey publicKey)
			throws InvalidKeyException, SignatureException, IllegalArgumentException, IOException {

		return verify(new ByteArrayInputStream(data), new ByteArrayInputStream(signature), publicKey);

	}

	/**
	 * Verify the given {@code signature}, meaning that it was created with the given
	 * {@code publicKey} from the given {@code data}. The parameters data and signature have to be
	 * given as {link InputStream InputStreams}. An InputStream can be generated
	 * e.g. from an byte[] with {@link ByteArrayInputStream} or a File with
	 * {@link FileInputStream}. This method is static and can be used without
	 * initializing an instance of {@link EasySigner}.
	 * <p>
	 * Using the InputStream will leave it empty after verifying is completed.
	 * <p>
	 * Verifying a signature with this method would look like this:
	 * 
	 * <pre>
	 * {@code
	 * ...
	 * String filePath = ...;
	 * byte[] signature = ...;
	 * String certificatePath = ...;
	 * signer.verify(new FileInputStream(filePath), new ByteArrayInputStream(signature), new FileInputStream(certificatePath));
	 * }
	 * </pre>
	 * 
	 * @param data
	 *            The data that is assumed to be signed with the given publicKey.
	 * @param signature
	 *            The signature that should be verified.
	 * @param certificatePEM
	 *            The certificate formatted as PEM containing the public key
	 *            corresponding to the private key that was used to sign the data.
	 * @return True, if the signature is valid, false otherwise.
	 * @throws CertificateException
	 *             if the given certificate is not valid.
	 * @throws InvalidKeyException
	 *             if the certificate contains an invalid public key.
	 * @throws SignatureException
	 *             if the given signature's format is invalid.
	 * @throws IllegalArgumentException
	 *             if one of the given signature is null.
	 * @throws IOException
	 *             if no data from one of the given InputStreams can be read.
	 */
	public static boolean verify(InputStream data, InputStream signature, InputStream certificatePEM)
			throws CertificateException, InvalidKeyException, SignatureException, IOException {

		Provider bcpqcProvider = new BouncyCastlePQCProvider();
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcpqcProvider);
		Security.addProvider(bcProvider);

		CertificateFactory fact = new CertificateFactory();
		X509Certificate cer = (X509Certificate) fact.engineGenerateCertificate(certificatePEM);
		PublicKey key = cer.getPublicKey();

		return EasySigner.verify(data, signature, key);

	}

//	private byte[] signStateless(InputStream toBeSigned) throws IOException {
//		return doSigning(toBeSigned, getHashAlgorithm());
//	}
//
//	private byte[] signStateful(InputStream toBeSigned) throws IOException {
//		// StatefulKeyManager statefulKeyManager = (StatefulKeyManager) keyManager;
//		// statefulKeyManager.updateKey(1);
//		return doSigning(toBeSigned, getHashAlgorithm());
//	}

	private byte[] doSigning(InputStream toBeSigned, String hashAlgorithm) throws IOException {
		Signature sig;

		try {
			sig = Signature.getInstance(hashAlgorithm + "with" + keyManager.getAlgorithm(), "BCPQC");
			sig.initSign(keyManager.getPrivateKey());

			byte[] buf = new byte[66442];
			int n;
			while ((n = toBeSigned.read(buf)) > 0) {
				sig.update(buf, 0, n);
			}

			byte[] signature = sig.sign();

			return signature;
		} catch (NoSuchProviderException | NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			// This shouldn't happen because the user has no influence on the parameters
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Verify the given {@code signature}, meaning that it was created with the given
	 * {@code publicKey} from the given {@code data}. The parameters data and signature have to be
	 * given as {link InputStream InputStreams}. An InputStream can be generated
	 * e.g. from an byte[] with {@link ByteArrayInputStream} or a File with
	 * {@link FileInputStream}. This method is static and can be used without
	 * initializing an instance of {@link EasySigner}.
	 * <p>
	 * Using the InputStream will leave it empty after verifying is completed.
	 * <p>
	 * Verifying a signature with this method would look like this:
	 * 
	 * <pre>
	 * {@code
	 * ...
	 * String filePath = ...;
	 * byte[] signature = ...;
	 * PublicKey publicKey = ...;
	 * signer.verify(new FileInputStream(filePath), new ByteArrayInputStream(signature), publicKey);
	 * }
	 * </pre>
	 * 
	 * @param data
	 *            The data that is assumed to be signed with the given publicKey.
	 * @param signature
	 *            The signature that should be verified.
	 * @param publicKey
	 *            The public key corresponding to the private key that was used to
	 *            sign the given data.
	 * @return True, if the signature is valid, false otherwise.
	 * @throws InvalidKeyException
	 *             if the certificate contains an invalid public key.
	 * @throws SignatureException
	 *             if the given signature's format is invalid.
	 * @throws IllegalArgumentException
	 *             if one of the given signature is null.
	 * @throws IOException
	 *             if no data from one of the given InputStreams can be read.
	 */
	public static boolean verify(InputStream data, InputStream signature, PublicKey publicKey)
			throws InvalidKeyException, SignatureException, IllegalArgumentException, IOException {

		Provider bcpqcProvider = new BouncyCastlePQCProvider();
		Provider bcProvider = new BouncyCastleProvider();
		Security.addProvider(bcpqcProvider);
		Security.addProvider(bcProvider);

		String algorithm = publicKey.getAlgorithm();

		Signature sig;

		boolean success = false;

		try {
			if (algorithm == "XMSS") {
//				BCXMSSPublicKey xmssPublicKey = (BCXMSSPublicKey) publicKey;
				String fullAlgorithm = "SHA256" + "with" + algorithm;
				sig = Signature.getInstance(fullAlgorithm, "BCPQC");
			} else if (algorithm == "XMSSMT") {
//				BCXMSSMTPublicKey xmssPublicKey = (BCXMSSMTPublicKey) publicKey;
				String fullAlgorithm = "SHA256" + "with" + algorithm;
				sig = Signature.getInstance(fullAlgorithm, "BCPQC");
			} else if (algorithm == "RSA" || algorithm == "ECDSA") {
				sig = Signature.getInstance("SHA256" + "with" + algorithm, "BC");
			} else {
				throw new NoSuchAlgorithmException("The algorithm of the public key is not supported.");
			}

			sig.initVerify(publicKey);

			byte[] buf = new byte[66442];
			int n;
			while ((n = data.read(buf)) > 0) {
				sig.update(buf, 0, n);
			}

			byte[] signatureArray = new byte[66442];
			int signatureSize = signature.read(signatureArray);
			success = sig.verify(signatureArray, 0, signatureSize);

		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			// Can't happen, provider can't be chosen by the user.
		}

		return success;

	}

	/**
	 * Get the {@link PublicKey} from the {@link KeyManager}.
	 * 
	 * @return The {@link PublicKey}.
	 */
	public PublicKey getPublicKey() {
		return keyManager.getPublicKey();
	}

	/**
	 * Get the {@link Certificate} from the {@link KeyManager}.
	 * 
	 * @return The {@link Certificate}.
	 */
	public Certificate getCertificate() {
		return keyManager.getCertificate();
	}
	
	/**
	 * Get the {@link KeyManager}
	 * 
	 * @return The {@link KeyManager}.
	 */
	public KeyManager getKeyManager() {
		return keyManager;
	}
	
	/**
	 * Stores a byte[] to disk at the given {@code path}.
	 * 
	 * @param signature The signature that should be stored. 
	 * @param path The {@code path} where the certificate should be stored.
	 * @throws FileAlreadyExistsException If the file at {@code path} already exists.
	 * @throws IOException If the file couldn't be written.
	 */
	public static void exportSignature(byte[] signature, String path) throws FileAlreadyExistsException, IOException {
		File outputFile = new File(path);
		if (outputFile.exists()) {
			throw new FileAlreadyExistsException(path);
		}
		FileOutputStream fos = new FileOutputStream(outputFile);
		fos.write(signature);
		fos.flush();
		fos.close();
	}
	
	/**
	 * Exports a {@link Certificate} to the given {@code path} as a PEM encoded file.
	 * 
	 * @param certificate The {@link Certificate} that should be exported.
	 * @param path The {@code path} where the certificate should be stored.
	 * @throws FileAlreadyExistsException If the file at {@code path} already exists.
	 * @throws IOException If the file couldn't be written.
	 * @throws CertificateEncodingException If the certificate couldn't be encoded.
	 */
	public static void exportCertificate(Certificate certificate, String path) throws FileAlreadyExistsException, IOException, CertificateEncodingException {

		File certificateFile = new File(path);
		if (certificateFile.exists()) {
			throw new FileAlreadyExistsException(path);
		}
		FileOutputStream certificateOut = new FileOutputStream(certificateFile);
		BASE64Encoder encoder = new BASE64Encoder();
		certificateOut.write(X509Factory.BEGIN_CERT.getBytes());
		certificateOut.write("\n".getBytes());
		encoder.encodeBuffer(certificate.getEncoded(), certificateOut);
		certificateOut.write("\n".getBytes());
		certificateOut.write(X509Factory.END_CERT.getBytes());
		certificateOut.write("\n".getBytes());
		certificateOut.flush();
		certificateOut.close();
		
	}
	
	/**
	 * Imports a {@link Certificate} in PEM format from the given {@code path}.
	 * 
	 * @param path The path where the certificate is stored.
	 * @return The {@link Certificate} read from the given {@code path}.
	 * @throws CertificateException If the certificate couldn't be created.
	 * @throws FileNotFoundException If the file couldn't be found.
	 */
	public static Certificate importCertificate(String path) throws CertificateException, FileNotFoundException {
		CertificateFactory fact = new CertificateFactory();
		return fact.engineGenerateCertificate(new FileInputStream(path));
	}
	
	/**
	 * Gets the hash algorithm used when creating a signature (the given data is first 
	 * hashed with this algorithm and then signed).
	 * 
	 * @return The hash algorithm used for signing.
	 */
	private String getHashAlgorithm() {
		return hashAlgorithm;
	}
	
	/**
	 * Sets the hash algorithm used when creating a signature (the given data is first 
	 * hashed with this algorithm and then signed). Possible algorithms are SHA256 and SHA512.
	 * 
	 * @param hashAlgorithm The hash algorithm to be used for signing.
	 */
	public void setHashAlgorithm(String hashAlgorithm) {
		if (hashAlgorithm == "SHA256" || hashAlgorithm == "SHA512") {
			this.hashAlgorithm = hashAlgorithm;			
		}
		else {
			throw new IllegalArgumentException("The given hash algorithm is not supported. Please use SHA256 or SHA512.");
		}
	}
	
}
