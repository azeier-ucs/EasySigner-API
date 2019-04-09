package easysigner.parameters;

/**
 * The parameters required for the XMSS signature scheme. XMSS is a stateful
 * signature scheme where the private key needs to be updated after every
 * signature. <b>Multiple usage of the same state will render the scheme insecure.</b>
 * Therefore, the private key should never be copied to prevent
 * multiple usage of a single state.
 * <p>
 * A XMSS private key is a Merkle tree with given {@code height} with a one time
 * signature key at every leaf. The number of possible signatures is 2^height. 
 * Increasing the height will increase the number of possible signature, but also the size of 
 * the private key and the signatures.
 * The one time signature keys use a
 * {@code treeDigest} for signing. The available values for {@code treeDigest}
 * are defined as static values in this class, e.g.
 * {@code XMSSParameters.SHA512}.
 * 
 */
public class XMSSParameters implements AlgorithmParameters {

	/**
	 * Use SHA-256 for the tree generation function.
	 */
	public static final String SHA256 = "SHA256";

	/**
	 * Use SHA512 for the tree generation function.
	 */
	public static final String SHA512 = "SHA512";

	/**
	 * Use SHAKE128 for the tree generation function.
	 */
	public static final String SHAKE128 = "SHAKE128";

	/**
	 * Use SHAKE256 for the tree generation function.
	 */
	public static final String SHAKE256 = "SHAKE256";

	private final int height;
	private final String treeDigest;

	/**
	 * Creates a new {@link XMSSParameters} object with the given {@code height} and
	 * {@code} treeDigest. 
	 * XMSS is a stateful signature scheme where the private key needs to be updated after every
	 * signature. <b>Multiple usage of the same state will render the scheme insecure.</b> 
	 * Therefore, the private key should never be copied to prevent
	 * multiple usage of a single state.
	 * <p>
	 * Use {@link #XMSSforSmallSignatures()} to get recommended values for the parameters.
	 * 
	 * @param height
	 *            The height of the Merkle tree. A higher height results in more doable signatures, but also in 
	 *            a larger private key and signature.
	 * @param treeDigest
	 *            The hash algorithm used for signing.
	 */
	public XMSSParameters(int height, String treeDigest) {
		this.height = height;
		this.treeDigest = treeDigest;
	}
	
	/**
	 * Use XMSS to prioritize signature size over signing speed. For this, 
	 * a height of 20 is used together with SHA256 as tree digest.
	 * <p>
	 * If signing speed is more important, you should use {@link XMSSMTParameters#XMSSMTforFastSigning()} instead.
	 * 
	 * @return An {@link XMSSParameters} object with predefined values.
	 */
	public static XMSSParameters XMSSforSmallSignatures() {
		return new XMSSParameters(5, "SHA256");
	}

	/**
	 * Returns the {@code treeDigest}.
	 * 
	 * @return The hash algorithm used for signing.
	 */
	public String getTreeDigest() {
		return treeDigest;
	}

	/**
	 * Returns the {@code height} of the Merkle tree.
	 * 
	 * @return The height of the Merkle tree.
	 */
	public int getHeight() {
		return height;
	}

}
