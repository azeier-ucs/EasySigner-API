package easysigner.parameters;

/**
 * The parameters required for the XMSSMT signature scheme. XMSSMT is a stateful
 * signature scheme where the private key needs to be updated after every
 * signature. <b>Multiple usage of the same state will render the scheme insecure.</b>
 * Therefore, the private key should never be copied to prevent
 * multiple usage of a single state.
 * <p>
 * A XMSSMT private key is a Merkle tree with given {@code height} with a one
 * time signature key at every leaf. The number of possible signatures is 2^height.
 * Increasing the height will increase the number of possible signature, but also the size of 
 * the private key and the signatures. 
 * The tree is divided into subtrees given by
 * the number of {@code layers}. The parameters {@code height} and
 * {@code layers} must be chosen in a way that the reminder of
 * {@code height/layers} is zero. The one time signature keys use a
 * {@code treeDigest} for signing. The available values for {@code treeDigest}
 * are defined as static values in this class, e.g.
 * {@code XMSSMTParameters.SHA512}.
 * 
 */
public class XMSSMTParameters implements AlgorithmParameters {
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
	private final int layers;
	private final String treeDigest;

	/**
	 * Creates a new {@link XMSSParameters} object with the given {@code height}, 
	 * {@code layers} and {@code} treeDigest. XMSSMT is a stateful
	 * signature scheme where the private key needs to be updated after every
	 * signature. <b>Multiple usage of the same state will render the scheme insecure.</b> 
	 * Therefore, the private key should never be copied to prevent
	 * multiple usage of a single state.
	 * <p>
	 * Use {@link #XMSSMTforFastSigning()} to get recommended values for the parameters.
	 * 
	 * @param height
	 *            The height of the Merkle tree. A higher height results in more doable signatures, but also in 
	 *            a larger private key and signature.
	 * @param layers
	 *            The number of layers. Must divide the height without reminder.
	 * @param treeDigest
	 *            The hash algorithm used for signing.
	 */
	public XMSSMTParameters(int height, int layers, String treeDigest) {
		this.height = height;
		this.layers = layers;
		this.treeDigest = treeDigest;
	}
	
	/**
	 * Use XMSSMT to prioritize signing speed over signature size. For this,
	 * a height of 20 and 4 layers are used together with SHA256 as tree digest. 
	 * <p>
	 * If signing speed is more important, you should use {@link XMSSParameters#XMSSforSmallSignatures()} instead.
	 * 
	 * @return An {@link XMSSMTParameters} object with predefined values.
	 */
	public static XMSSMTParameters XMSSMTforFastSigning() {
		return new XMSSMTParameters(12, 2, "SHA256");
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
	 * Returns the {@code height}.
	 * 
	 * @return The height of the Merkle tree.
	 */
	public int getHeight() {
		return height;
	}

	/**
	 * Return the number of {@code layers}
	 * 
	 * @return The number of layers of Merkle trees.
	 */
	public int getLayers() {
		return layers;
	}
}
