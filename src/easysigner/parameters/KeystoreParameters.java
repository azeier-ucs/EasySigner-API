package easysigner.parameters;

import java.io.File;

/**
 * This class contains the necessary parameters to use the {@link easysigner.EasySigner UCSSigner} with an {@link java.security.KeyStore KeyStore}.
 * An object of this class specifies the location of the KeyStore on disk, Passwords to load the KeyStore and the PrivateKey 
 * and the aliases of a corresponding Private and Public Key and the Certificate. The location path and the KeyStore password are 
 * mandatory, for all the other parameters default values are available. 
 * <p>
 * When using the {@link easysigner.EasySigner EasySigner} or {@link easysigner.KeyManager KeyManager} to create a new key pair with these parameters, a self signed certificate will be created
 * as a placeholder. 
 * 
 *
 */
public class KeystoreParameters implements StorageParameters {
	
	private File file = new File("data/keypair");
	private String keystorePassword;
	private String publicKeyAlias = "PublicKey";
	private String certifictaeAlias = "Certificate";
	private String privateKeyAlias = "PrivateKey";
	private String privateKeyPassword;
	
	/**
	 * This constructor only takes the {@code path} to the {@link java.security.KeyStore KeyStore} file
	 * and the password for the KeyStore. For all other parameters, default values will be used. These are:
	 * "PublicKey" as the alias for the public key, "PrivateKey" as the alias for the private key, "Certificate"
	 * as the alias for the certificate. The password for the private key will be the same as for the KeyStore.
	 * <p>
	 * When using the {@link easysigner.EasySigner EasySigner} or {@link easysigner.KeyManager KeyManager} to create a new key pair with these parameters, a self signed certificate will be created
	 * as a placeholder. 
	 * 
	 * @param file The {@link java.security.KeyStore KeyStore} file.
	 * @param keystorePassword The KeyStore password.
	 */
	public KeystoreParameters(File file, String keystorePassword) {
		super();
		this.file = file;
		this.keystorePassword = keystorePassword;
		this.privateKeyPassword = keystorePassword;
	}
	
	/**
	 * This constructor takes all the parameters to access the key pair stored in the 
	 * {@link java.security.KeyStore KeyStore} file. Instead, {@link easysigner.parameters.KeystoreParameters#KeystoreParameters(File file, String keystorePassword)}
	 * can be used, providing default values for most of the parameters.
	 * <p>
	 * When using the {@link easysigner.EasySigner EasySigner} or {@link easysigner.KeyManager KeyManager} to create a new key pair with these parameters, a self signed certificate will be created
	 * as a placeholder. 
	 * 
	 * @param file The {@link java.security.KeyStore KeyStore} file.
	 * @param keystorePassword The KeyStore password.
	 * @param publicKeyAlias The alias of the public key. 
	 * @param certifictaeAlias The alias of the certificate.
	 * @param privateKeyAlias The alias of the private key.
	 * @param privateKeyPassword The private key password.
	 */
	public KeystoreParameters(File file, String keystorePassword, String publicKeyAlias, String certifictaeAlias,
			String privateKeyAlias, String privateKeyPassword) {
		super();
		this.file = file;
		this.keystorePassword = keystorePassword;
		this.publicKeyAlias = publicKeyAlias;
		this.certifictaeAlias = certifictaeAlias;
		this.privateKeyAlias = privateKeyAlias;
		this.privateKeyPassword = privateKeyPassword;
	}
	
	public File getFile() {
		return file;
	}

	public void setFile(File file) {
		this.file = file;
	}

	public String getKeystorePassword() {
		return keystorePassword;
	}

	public void setKeystorePassword(String keystorePassword) {
		this.keystorePassword = keystorePassword;
	}

	public String getPublicKeyAlias() {
		return publicKeyAlias;
	}

	public void setPublicKeyAlias(String publicKeyAlias) {
		this.publicKeyAlias = publicKeyAlias;
	}

	public String getCertifictaeAlias() {
		return certifictaeAlias;
	}

	public void setCertifictaeAlias(String certifictaeAlias) {
		this.certifictaeAlias = certifictaeAlias;
	}

	public String getPrivateKeyAlias() {
		return privateKeyAlias;
	}

	public void setPrivateKeyAlias(String privateKeyAlias) {
		this.privateKeyAlias = privateKeyAlias;
	}

	public String getPrivateKeyPassword() {
		return privateKeyPassword;
	}

	public void setPrivateKeyPassword(String privateKeyPassword) {
		this.privateKeyPassword = privateKeyPassword;
	}
	
}
