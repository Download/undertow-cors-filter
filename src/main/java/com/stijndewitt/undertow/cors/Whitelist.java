package com.stijndewitt.undertow.cors;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static java.nio.file.StandardWatchEventKinds.*;


/**
 * A whitelist-based CORS policy that allows all origins that match a regex in the whitelist whose absolute
 * file path is given in the constructor.
 * 
 * @see #Whitelist(String)
 * @see #isAllowed
 * @see Policy
 */
public class Whitelist implements Policy {
	private static final Logger LOG = Logger.getLogger(Whitelist.class.getName());
	
	/**
	 * The default match pattern that will be used if no parameter was given in the constructor.
	 * 
	 * <p>When using {@code Whitelist} without a parameter, it uses a list containing only 
	 * a single regex that matches all origin strings and is effectively the same as using 
	 * the {@code AllowAll} policy.</p>
	 * 
	 * @see #Whitelist(String)
	 * @see #getWhitelist
	 */
	public static String DEFAULT_MATCH_PATTERN = "^.*$";
	
	private String filePath;
	private List<Pattern> whitelist;
	private WatchService watcher;
	private WatchKey watchKey;

	/**
	 * Creates a new {@code AllowMatching} policy.
	 * 
	 * @param param The regex string parameter, may be {@code null} or empty.
	 * 
	 * @see Filter#getPolicyClass
	 * @see Filter#setPolicyClass
	 * @see Filter#getPolicyParam
	 * @see Filter#setPolicyParam
	 */
	public Whitelist(String param) {
		filePath = param != null && !param.isEmpty() ? param : null;
		if (filePath == null) {
			useDefaultWhitelist("policyParam should be configured with the path to a whitelist file.", null);
			return;
		}
		
		try {
			FileSystem fs = FileSystems.getDefault();
			Path path = fs.getPath(filePath);
			if (!Files.exists(path)) {
				useDefaultWhitelist("File path configured in policyParam does not exist: " + filePath, null);
				return;
			}
			
			if (Files.isDirectory(path)) {
				useDefaultWhitelist("File path configured in policyParam is a directory. File expected: " + filePath, null);
				return;
			}

			readWhitelist(path);
			setupWatcher(path.toAbsolutePath().getParent());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		if (filePath != null) {
		}
		if (whitelist.isEmpty()) ;
	}
	
	private void useDefaultWhitelist(String reason, Throwable cause) {
		whitelist = new ArrayList<Pattern>();
		LOG.log(Level.SEVERE, reason, cause);
		LOG.severe("Reverting to default whitelist that allows all domains.");
		whitelist.add(Pattern.compile(DEFAULT_MATCH_PATTERN));
	}
	
	private void readWhitelist(Path path) {
		whitelist = new ArrayList<Pattern>();
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(path.toFile()));
		    String line;
		    while ((line = br.readLine()) != null) {
		    	line = line.trim();
		    	if (line.isEmpty()) continue;
		    	if (line.startsWith("#") || line.startsWith("//")) continue;
		    	whitelist.add(Pattern.compile(line));
		    }
		} 
		catch (IOException e) {
			useDefaultWhitelist("Unable to read file " + path.toString() + ". All origins will be allowed.", e);
		}
		finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					LOG.log(Level.WARNING, "Unable to close file " + filePath, e);
				}
			}
		}
	}
	
	private void setupWatcher(Path path) throws IOException {
		FileSystem fs = FileSystems.getDefault();
		watcher = fs.newWatchService();
		watchKey = path.register(watcher, ENTRY_MODIFY);
	}
	
	/**
	 * Indicates whether the given {@code origin} should be allowed access.
	 * 
	 * <p>This method in {@code Whitelist} performs a regex match of the given {@code origin} 
	 * against all regex patterns in whitelist, returning {@code true} as soon as a match was found.
	 * If no pattern in whitelist matches the given {@code origin}, it returns {@code false}.</p>
	 * 
	 * @param origin The origin String, may be {@code null}.
	 * 
	 * @return {@code true} if the given {@code origin} matched a pattern in the whitelist, {@code false} otherwise.
	 * 
	 * @see #getWh
	 */
	@Override public boolean isAllowed(String origin) {
		if (origin == null) return false;
		for (Pattern pattern : getWhitelist()) {
			if (pattern.matcher(origin).matches())
				return true;
		}
		return false;
	}

	/**
	 * Gets the (absolute) file path of the whitelist file.
	 * 
	 * @return The file path, possibly {@code null}.
	 */
	public String getFilePath() {
		return filePath;
	}
	
	/**
	 * Gets the whitelist currently in use by this policy.
	 * 
	 * <p>There is no setter for this parameter. It can only be set when the policy is created.</p>
	 * 
	 * @return The whitelist, never {@code null} or empty.
	 * 
	 * @see #Whitelist(String)
	 */
	public List<Pattern> getWhitelist() {
		// first, check if the whitelist was modified and update if needed
		WatchKey key = watcher.poll();
		if (watchKey.equals(key)) {
			// the whitelist file was modified
			FileSystem fs = FileSystems.getDefault();
			readWhitelist(fs.getPath(filePath).normalize());
		}
		return whitelist;
	}
}
