package easysigner;

import easysigner.parameters.AlgorithmParameters;
import easysigner.parameters.StorageParameters;

/**
 * To initialize, use the static methods {@link #loadKeyPair(StorageParameters storageParameters)} or 
 * {@link #createNewKeyPair(AlgorithmParameters algorithmParameters, StorageParameters storageParameters)} 
 * of {@link KeyManager}.
 * <p>
 * This KeyManager handles stateless key pairs. Currently the signatures schemes
 * RSA and ECDSA are supported.
 * <p>
 * The StatelessKeyManager is not implemented in this protoype version.
 * 
 *
 */
public class StatelessKeyManager extends KeyManager {

//	StatelessKeyManager(Algorithm algorithm, AlgorithmParameters parameters, String storageLocation) {
//		this.algorithm = algorithm.getAlgorithm();
//		this.parameters = parameters;
//		
//		if (storageLocation != null) {
//			this.storageLocation = storageLocation;
//		}
//
//		// TODO
//	}
//	
//	StatelessKeyManager(Profile profile, String storageLocation) throws Exception {
//		if (storageLocation != null) {
//			this.storageLocation = storageLocation;
//		}
//		
//		// TODO
//	}
	
}
