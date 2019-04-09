package easysigner.parameters;

import easysigner.KeyManager;

/**
 * An interface for algorithm parameters. The purpose is to group all implementations of this interface, making agile implementations possible.
 * All classes implementing this interface are named:
 * <pre>
 * [AlgorithmName]Parameters
 * e.g. RSAParameters, XMSSParameters, ...
 * </pre>
 * 
 * 
 * @author Bouncy Castle
 *
 */
public interface AlgorithmParameters {
	
	/**
	 * List of all Algorithms supported by the {@link KeyManager}. <br>
	 * The available algorithms are RSA, ECDSA, XMSS and XMSSMT.
	 * <p>
	 * The algorithms can be used like static variable with
	 * 
	 * <pre>
	 * {@code
	 * KeyManager.Algorithm.[AlgorithmName]
	 * }
	 * </pre>
	 * 
	 *
	 */
	public enum Algorithm {
		/**
		 * Use XMSS as the signature algorithm.
		 */
		XMSS("XMSS"),

		/**
		 * Use XMSS as the signature algorithm.
		 */
		XMSSMT("XMSSMT"),

		/**
		 * Use XMSS as the signature algorithm.
		 */
		RSA("RSA"),

		/**
		 * Use XMSS as the signature algorithm.
		 */
		ECDSA("ECDSA");

		private final String algorithm;

		Algorithm(String algorithm) {
			this.algorithm = algorithm;
		}

		public String getAlgorithm() {
			return algorithm;
		}
	}
	
	/**
	 * Use XMSS to prioritize signature size over signing speed. For this, 
	 * a height of 20 is used together with SHA256 as tree digest.
	 * 
	 * @return An {@link XMSSParameters} object with predefined values.
	 */
	public static XMSSParameters XMSSforSmallSignatures() {
		return new XMSSParameters(5, "SHA256");
	}
	
	/**
	 * Use XMSSMT to prioritize signing speed over signature size. For this,
	 * a height of 20 and 4 layers are used together with SHA256 as tree digest. 
	 * 
	 * @return An {@link XMSSMTParameters} object with predefined values.
	 */
	public static XMSSMTParameters XMSSMTforFastSigning() {
		return new XMSSMTParameters(12, 2, "SHA256");
	}
	
	/**
	 * List of all predefined values to use with the {@link KeyManager}. <br>
	 * The available values are XMSSforFASTandSMALLSIGNATURES and
	 * XMSSMTforMANYSIGNATURES.
	 * <p>
	 * The profiles can be used like static variable with
	 * 
	 * <pre>
	 * {@code
	 * KeyManager.Profile.[ProfileName]
	 * }
	 * </pre>
	 * 
	 * @author Alexander Zeier
	 *
	 */
//	public enum PredefinedValues {
//		/**
//		 * The Profile to use XMSS for fast signing with small signatures. Therefore,
//		 * the number of signatures that can be generated is comparably small. If more
//		 * signatures are needed, the profile XMSSMTforMANYSIGNATURES is more
//		 * appropriate.
//		 */
//		XMSSforFastAndSmallSignatures(new XMSSParameters(5, "SHA256")),
//
//		/**
//		 * The Profile to use XMSSMT to do a huge amount of signatures. Therefore the
//		 * signature size is comparable big and signing takes longer. If faster signing
//		 * is needed and less signatures are acceptable, XMSSforFASTandSMALLSIGNATURES
//		 * is more appropriate.
//		 */
//		XMSSMTforManySignatures(new XMSSMTParameters(12, 2, "SHA512"));
//		
//		private final AlgorithmParameters algorithmParameters;
//
//		PredefinedValues(AlgorithmParameters algorithmParameters) {
//			this.algorithmParameters = algorithmParameters;
//		}
//		
//		public AlgorithmParameters getAlgorithmParameters() {
//			return algorithmParameters;
//		}
//	}
}
