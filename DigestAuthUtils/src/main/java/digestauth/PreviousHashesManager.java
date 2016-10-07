package digestauth;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.Set;

import config.AuthConfig;

public class PreviousHashesManager {
	private static Set<String> previousHashes = new HashSet<String>();
    private static Deque<String> previousHashesStack = new ArrayDeque<String>();
    
    public static synchronized boolean isDuplicatedHash(String hash) {
    	return previousHashes.contains(hash);
    }
    
    public static synchronized void addPreviousHash(String hash) {
    	previousHashes.add(hash);
    	previousHashesStack.add(hash);
    	// Make sure we don't pass the limit
    	while (previousHashesStack.size() > AuthConfig.maxPreviousHashesSize) {
    		String lastElement = previousHashesStack.pop();
    		previousHashes.remove(lastElement);
    	}
    }
}
