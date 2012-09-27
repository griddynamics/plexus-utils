package org.codehaus.plexus.util.cli;

/*
 * Copyright The Codehaus Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.Vector;
import org.codehaus.plexus.util.Os;
import org.codehaus.plexus.util.ReaderFactory;
import org.codehaus.plexus.util.StringUtils;

import org.codehaus.plexus.util.IOUtil;

/**
 * @author <a href="mailto:trygvis@inamo.no">Trygve Laugst&oslash;l </a>
 * @version $Id$
 */
public abstract class CommandLineUtils
{

    static final long WAIT_AFTER_KILL_MILLIS = 1000; // 1 sec
    
    public static class StringStreamConsumer
        implements StreamConsumer
    {
        private final StringBuffer string = new StringBuffer();

        private final String ls = System.getProperty( "line.separator" );

        public void consumeLine( String line )
        {
            string.append( line ).append( ls );
        }

        public String getOutput()
        {
            return string.toString();
        }
    }
    
    public static abstract class AbstractProcessHelper {
    	/**
    	 * Gets native PID (Process ID) for given {@link java.lang.Process} object. 
    	 * @param process
    	 * @return the native PID of the given process object.
    	 */
    	public abstract long getPid(Process process);
//    	/**
//    	 * Gets native process PGID (Process Group ID) by given process PID. 
//    	 * @param pid the PID of the process whose Group ID is to be returned.
//    	 * @return the PGID
//    	 */
//    	long getPgid(long pid);
    	/**
    	 * Answers if the process with the given PID exists in the system.
    	 * @param pid
    	 * @return
    	 */
    	public abstract boolean exists(long pid);
    	/**
    	 * Gets all PIDs of child processes of the process with the given PID.
    	 * Note that this operation is not recursive: it returns only the *immediate* children of the process.
    	 * @param ppid the PID of the process whose immediate children are to be returned.
    	 * @return the PIDs of the child processes as an array of long. If the process does not have children, 
    	 * an empty array is returned.
    	 */
    	public abstract long[] getChildrenPIDs(long ppid);
    	/**
    	 * Gets all the children PIDs recursively.
    	 * The PIDs are returned in pre-order (parents first).
    	 * NB: note that the 'ppid' parameter itself is *not* included into the list.   
    	 * @param ppid the PID whose children are to be returned (recursively).
    	 * @return the list of children PIDs.
    	 */
    	public final List<Long> getChildrenPIDsRecirsive(final long ppid) {
    		final List<Long> list = new ArrayList<Long>(4);
			long[] pids = getChildrenPIDs(ppid);
			if (pids != null) {
				for (final long p: pids) {
		    		list.add(Long.valueOf(p)); // put the parent first
					List<Long> subList = getChildrenPIDsRecirsive(p); // *** recursive call
					list.addAll(subList);
				}
			}
			return list;
    	}
    	
    	/**
    	 * Kills the process or group of processes using OS means.
    	 * @param pgid the ID - positive for process (PID) and negative for Group ID (-PGID).
    	 * @param signal the signal to send to the process or all processes in the group.
    	 */
    	public abstract void nativeKill(final long pgid/*
				 * NB: positive for process, and
				 * negative for group
				 */, final int signal/* must be positive! */);
    	/**
    	 * Gets short name of the program executable, like "bash" or "java" 
    	 * @param pid
    	 * @return
    	 */
    	public abstract String getComm(final long pid);
    }

    public static class UnixProcessHelper extends AbstractProcessHelper {
    	// standard commonly used signals:
    	public static final int SIGQUIT = 3;
    	public static final int SIGKILL = 9;
    	public static final int SIGTERM = 15;
    	
    	// may be redefined somehow, if needed:
    	private final String ps = "/bin/ps";
    	private final String kill = "/bin/kill";
    	
//    	@Override
//    	public long getPgid(long pid) {
//			ProcessResult result = getProcessOutput(new String[] { ps, "-o", "pgid=", Long.toString(pid) });
//			if (result == null) {
//    			System.out.println("ERROR: ps command failed.");
//    			return -1L;
//			}
//			String output = result.stdOut.trim();
//			if (output.length() > 0) {
//				long pgid = Long.parseLong(output);
//				return pgid;
//			} 
//			return -1L;
//    	}
    	@Override
    	public long getPid(Process process) {
    		try {
    			Class<?> java_lang_UnixProcessClass = Class.forName("java.lang.UNIXProcess");
    			if (java_lang_UnixProcessClass.isInstance(process)) {
    				Field pidField = java_lang_UnixProcessClass.getDeclaredField("pid");
    				pidField.setAccessible(true);
    				Object x = pidField.get(process);
    				int pidInt = ((Integer)x).intValue();
    				return pidInt;
    			} else {
    				System.out.println("ERROR: process is not an instance of UNIXProcess, cannot get pid.");
    				return -1L;
    			}
    		} catch (Exception e) {
				System.out.println("ERROR: cannot get pid of the process:");
    			e.printStackTrace(System.out);
    			return -1L;
    		}
    	}
    	@Override
    	public boolean exists(final long pid) {
    		final ProcessResult result = getProcessOutput(new String[] { ps, Long.toString(pid) });
    		if (result == null) {
    			System.out.println("ERROR: ps commmand did not return a result.");
    			return false;
    		}
    		int status = result.exitCode; 
    		return (status == 0);
    	}
    	@Override
    	public long[] getChildrenPIDs(long ppid) {
    		ProcessResult result = getProcessOutput(new String[] { ps, "-o", "pid=", "--ppid", Long.toString(ppid) });
    		if (result == null) {
    			System.out.println("ERROR: ps command failed.");
    			return new long[0];
    		}
    		String output = result.stdOut.trim();
    		if (output.length() == 0) {
    			return new long[0]; // no children
    		}
    		String[] pidStrs = output.split("\\s+");
    		long[] pids = new long[pidStrs.length];
    		for (int i=0; i<pidStrs.length; i++) {
    			pids[i] = Long.parseLong(pidStrs[i]); 
    		}
    		return pids;
    	}
    	@Override
		public void nativeKill(final long pgid/*
											 * NB: positive for process, and
											 * negative for group
											 */, final int signal/* positive! */) {
    		if (signal < 0) {
    			throw new IllegalArgumentException("Zero or negative signal number: " + signal);
    		}
//			System.out.println("### Native killing of "
//					+ ((pgid > 0) ? "process" : "group") + " " + pgid
//					+ " invoked...");
			try {
				// NB: '/bin/kill' command differs in parameters parsing logic from the Bourne Shell/BASH 'kill' built-in:
				// the latter requires "--" separator before a negative PID, e.g.: 
				// bash$: kill -15 -- -1234
				// /bin/kill -15 -1234
				// Since there we don't use a shell, we should utilize the /bin/kill command syntax:
				final String[] cmd = new String[] { kill, "-" + Integer.toString(signal), Long.toString(pgid) };
				final ProcessResult processResult = getProcessOutput(cmd);
				if (processResult != null) {
					System.out.println("kill command " + Arrays.toString(cmd)
							+ " finished with exit code "
							+ processResult.exitCode + ". Output: ["
							+ processResult.stdOut + "]");
				}
			} catch (Exception e) {
				System.out.println("Error while killing the process:");
				e.printStackTrace(System.out);
			}
		}
    	@Override
    	public String getComm(long pid) {
    		// e.g. ps -o comm= 30296
			try {
				final String[] cmd = new String[] { ps, "-o", "comm=", Long.toString(pid) };
				final ProcessResult processResult = getProcessOutput(cmd);
				if (processResult == null) {
					System.out.println("Command " + Arrays.toString(cmd)
							+ " returned no result.");
					return null;
				} else {
					return processResult.stdOut.trim();
				}
			} catch (Exception e) {
				System.out.println("Error while killing the process:");
				e.printStackTrace(System.out);
				return null;
			}
    	}
    }  
    
    private static class ProcessHook extends Thread {
        private final Process process;

        private ProcessHook( Process process)
        {
            super("CommandlineUtils process shutdown hook");
            this.process = process;
            this.setContextClassLoader( null );
        }

        @Override
        public void run()
        {
        	System.out.println("############## "+getClass().getName()+": running shutdown hook...");
        	run(true/*do thread dump by default*/);
        	System.out.println("############## "+getClass().getName()+": shutdown hook finished.");
        }
        
        public boolean run(final boolean makeFullThreadDump)
        {
        	final boolean terminated = killProcessImpl(process, makeFullThreadDump);
        	if (!terminated) {
        		System.out.println("FATAL: faled to kill process or some of its child processes.");
        	}
        	return terminated;
        }
    }

    static boolean isUnixFamily() {
    	boolean unixFamily = Os.isFamily(Os.FAMILY_UNIX);
    	return unixFamily;
    }
    
    private static volatile AbstractProcessHelper processHelper;
    private static final AbstractProcessHelper stubHelper = new AbstractProcessHelper() {
		@Override
		public long[] getChildrenPIDs(long ppid) {
			return null;
		}
		
		@Override
		public long getPid(Process process) {
			return -1L;
		}
		@Override
		public void nativeKill(long pgid, int signal) {
		}
		@Override
		public boolean exists(long pid) {
			return false;
		}
		@Override
		public String getComm(long pid) {
			return null;
		}
	};
    
    public static AbstractProcessHelper getProcessHelper() {
    	if (processHelper == null) {
    		synchronized (CommandLineUtils.class) {
    			if (processHelper == null) {
    				processHelper = createProcessHelper();
    			}
    		}
    	}
    	return processHelper;
    }
    
    private static AbstractProcessHelper createProcessHelper() {
    	if (isUnixFamily()) {
    		return new UnixProcessHelper();
    	} else {
    		// TODO: may write helpers for other OSs.
    		return stubHelper;
    	}
    } 
    
    /**
     * Entry point method to terminate a process.
     * In contrast with {@link java.lang.Process#destroy()} it really makes guarantee that 
     * the process and all its child processes are terminated upon the exist from the method.
     * If it fails to kill all subprocesses, {@link System#exit(int)} invoked and JVM gets terminated.
     * This method used native OS commands such as ps and kill.
     * Currently this method implemented for Unix systems only. 
     * @param p the process to be killed.
     * @param makeFullThreadDump if we should make a full thread dump of all the Java processes in the group being killed.
     */
	public static boolean killProcessImpl(final Process p, final boolean makeFullThreadDump) {
		if (!isAlive(p)) {
			return true; // ok
		}
		final AbstractProcessHelper helper = getProcessHelper();
		long pid = -1L; // real (OS) pid of the process
		//long pgid = -1L; // process group id
		List<Long> childrenPids = null;
		// making the Full Thread Dump of the hung process, if needed:
		if (makeFullThreadDump && isAlive(p)) {
			if (isUnixFamily()) {
				pid = helper.getPid(p);
				if (pid <= 0) {
					System.out
							.println("WARN: Cannot make FTD since cannot determine the PID of the process.");
				} else {
					System.out.println("Making full thread dump on ["+pid+"] and children...");
					// NB: signal only java processes:
					childrenPids = killChildrenAndProcess(helper, pid, UnixProcessHelper.SIGQUIT, "java(\\.exe)?", childrenPids, 
							1/*attempt*/, WAIT_AFTER_KILL_MILLIS);
				}
			} else {
				System.out
					.println("WARN: Full thread dump only supported for Unix family systems.");
			}
		}

		if (isAlive(p)) {
			// destroy it with Java means:
			//p.destroy();
			//if (isAlive(p)) {
			//	safeSleep(WAIT_AFTER_KILL_MILLIS); // wait some time after #destroy() to let the process die.
			//	if (isAlive(p)) {
			//		System.out
			//				.println("########## WARN: ! Process#destroy() failed to kill the process.");
					// the process is still alive, get its pid:
					if (pid <= 0) {
						pid = helper.getPid(p);
					}
					if (pid <= 0) {
						System.out
								.println("ERROR: Cannot kill the process since cannot determine its PID. Sorry. Aborting JVM.");
						System.exit(78); // *** terminate JVM.
					} else {
						System.out.println("The process PID known to be "+pid+".");
						// kill -TERM:
						childrenPids = killChildrenAndProcess(helper, pid, UnixProcessHelper.SIGTERM, null, childrenPids, 2/*attempts*/, WAIT_AFTER_KILL_MILLIS);
						// kill -KILL:
						childrenPids = killChildrenAndProcess(helper, pid, UnixProcessHelper.SIGKILL, null, childrenPids, 10/*attempts*/, WAIT_AFTER_KILL_MILLIS * 2);
					}
			//	}
			//}
		}
		
		// finally check the result:
		if (pid > 0 && childrenPids == null) {
			childrenPids = helper.getChildrenPIDsRecirsive(pid);
		}
		final List<Long> aliveProcesses = getAlives(helper, pid, childrenPids);
		if (isAlive(p) 
				|| aliveProcesses.size() > 0) {
			// Damn it! The process is still alive...
			System.out.println("The following processes are still alive: "+ Arrays.toString(aliveProcesses.toArray()));
			System.out
					.println("######### FATAL: native kill faild to kill the process ["
							+ pid + "] or some of its child processes.");
			//System.exit(77); // *** terminate JVM.
			return false;
		} else {
			//System.out.println("Process " + ((pid > 0) ? (pid+" ") : "") + "and all its children are successfully killed.");
			return true;
		}
	}

	private static List<Long> getAlives(AbstractProcessHelper helper, long pid0, List<Long> pidList) {
		final List<Long> result = new ArrayList<Long>(4);
		if (pid0 > 0 && helper.exists(pid0)) {
			result.add(Long.valueOf(pid0));
		}
		if (pidList != null) {
			for (Long pid : pidList) {
				if (helper.exists(pid.longValue())) {
					result.add(pid);
				}
			}
		}
		return result;
	}
	
	private static List<Long> killChildrenAndProcess(
			final AbstractProcessHelper helper, 
			final long pid, 
			final int signal, 
			final String commRegex, 
			List<Long> childrenPids, 
			final int maxKillAttempts,
			final long sleepAfterKillMs) {
		if (childrenPids == null) {
			childrenPids = helper.getChildrenPIDsRecirsive(pid);
		}
		if (childrenPids == null) {
			System.out.println("ERROR: cannot determine children of process ["+pid+"].");
		} else {
			System.out
				.println("##### Trying to kill the process subtree of process PID=["
					+ pid + "]: "+Arrays.toString(childrenPids.toArray())+" with signal "+signal+"...");
			for (int i=childrenPids.size()-1; i>=0; i--) {
				final Long chPid = childrenPids.get(i);
				final KillResult killResult = killIfFilterMatches(helper, chPid, signal, commRegex, maxKillAttempts, sleepAfterKillMs);
				System.out.println(killResult);
			}
		}
		final KillResult killResult = killIfFilterMatches(helper, pid, signal, commRegex, maxKillAttempts, sleepAfterKillMs);
		System.out.println(killResult);
		return childrenPids;
	}

	/**
	 * 
	 * @param helper
	 * @param pid
	 * @param signal
	 * @param commRegex
	 * @return 'true' if the process with the given pid does not exist any more upon the method return, and 'false' otherwise. 
	 */
	private static KillResult killIfFilterMatches(final AbstractProcessHelper helper, final long pid, final int signal, final String commRegex, 
			final int maxKillAttempts, final long sleepAfterKillMs) {
		// the process might die already, so check that:
		if (!helper.exists(pid)) {
			//System.out.println("Process ["+pid+"] not found => not killed.");
			return new KillResult(pid, false, 0); // ok, already ended.
		}
		final boolean doKill; 
		if (commRegex != null) {
			final String comm = helper.getComm(pid);
			//System.out.println("comm = ["+comm+"], filter = ["+commRegex+"]");
			doKill = (comm != null && comm.matches(commRegex));
			if (!doKill) {
				System.out.println("PID ["+pid+"] not killeld since comm ["+comm+"] does not match regex ["+commRegex+"].");
			}
		} else {
			doKill = true;
		}
		if (doKill) {
			int killCount = 0;
			while (true) {
				helper.nativeKill(pid, signal);
				killCount++;
				safeSleep(sleepAfterKillMs);
				final boolean exists = helper.exists(pid);
				if (exists) {
					if (killCount >= maxKillAttempts) {
						return new KillResult(pid, true, killCount); // process exists, and there are no more attempts to kill it.
					}
				} else {
					return new KillResult(pid, false, killCount); // ok, killed or died.
				}
			}
		} else {
			return  new KillResult(pid, true, 0); // possibly exists, we did not try to kill it.
		}
	}
	
	private static class KillResult {
		public KillResult(long pid0, boolean exists0, int attempts0) {
			pid = pid0;
			processExists = exists0;
			killAttempts = attempts0;
		}
		public final long pid; 
		public final boolean processExists;
		public final int killAttempts;
		@Override
		public String toString() {
			if (processExists) {
				return "Process "+pid+" still exists after "+killAttempts+" attempts to kill it.";
			} else {
				return "Process "+pid+" successfully killed in "+killAttempts+" attempts.";
			}
		}
	}
	
	/*
	 * Sleeps given number of milliseconds and ignores all interrupts sent to the caller thread. 
	 */
	private static void safeSleep(final long millis) {
		final long t0 = System.currentTimeMillis();
		final long stop = t0 + millis;
		long toSleep; 
		while (true) {
			toSleep = stop - System.currentTimeMillis();
			if (toSleep > 0) {
				try { 
					Thread.sleep(toSleep);
				} catch (InterruptedException ie) {
					ie.printStackTrace(System.out);
				}
			} else {
				break;
			}
		}
		//System.out.println("Slept " + (System.currentTimeMillis() - t0) + " ms.");
	}
	
	private static class Pumper2 implements Runnable {
		private final InputStream is;
		private final OutputStream os;
		private final boolean closeOutput;
		public Pumper2(InputStream is0, OutputStream os0, boolean closeOutput0) {
			is = is0;
			os = os0;
			closeOutput = closeOutput0;
		}
		@Override
		public void run() {
			try {
			int b;
			while (true) {
				b = is.read();
				if (b < 0) {
					break; // EOS
				} else {
					os.write(b);
				}
			}
			} catch (IOException ioe) {
				ioe.printStackTrace();
			} finally {
				if (closeOutput && os != null) {
					try {
						os.close();
					} catch (IOException ioe) {
						ioe.printStackTrace(System.out);
					} 
				}
			}
		}
	}

	public static class ProcessResult {
		public ProcessResult(int ec, String out, String err) {
			exitCode = ec;
			stdOut = out;
			stdErr = err;
		}
		public final int exitCode;
		public final String stdOut; 
		public final String stdErr; 
	} 
	
	public static ProcessResult getProcessOutput(final String[] cmd) {
		return getProcessOutput(cmd, null);
	}
	
	/**
	 * Executes the specified command and returns its result.
	 * The caller thread is blocked until the process is finished.
	 * NB: err and out are merged together.
	 * @param cmd
	 * @return
	 */
	public static ProcessResult getProcessOutput(final String[] cmd, final Charset charset) {
		try {
			ProcessBuilder pb = new ProcessBuilder(cmd);
			pb.redirectErrorStream(true); // NB: merge sterr to stdout
			System.out.println("Running command "+Arrays.toString(cmd)+".");
			final ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
			Process p = pb.start();
			InputStream is = p.getInputStream();
			final Pumper2 pumper2 = new Pumper2(is, baos, true/*close output*/);
			Thread pumperThread = new Thread(pumper2);
			pumperThread.start();
			final int status = p.waitFor();
			//System.out.println("Command finished with exit code " + status);
			pumperThread.join();
			byte[] outBytes = baos.toByteArray();
			final String outStr;
			if (charset == null) {
				outStr = new String(outBytes); // NB: translated with default encoding
			} else {
				outStr = new String(outBytes, charset);
			}
			return new ProcessResult(status, outStr, null/*err*/);
		} catch (Exception e) {
			System.out.println("Error executing the command:");
			e.printStackTrace(System.out);
			return null;
		}
	} 

    public static int executeCommandLine( Commandline cl, StreamConsumer systemOut, StreamConsumer systemErr )
        throws CommandLineException
    {
        return executeCommandLine( cl, null, systemOut, systemErr, 0 );
    }

    public static int executeCommandLine( Commandline cl, StreamConsumer systemOut, StreamConsumer systemErr,
                                          int timeoutInSeconds )
        throws CommandLineException
    {
        return executeCommandLine( cl, null, systemOut, systemErr, timeoutInSeconds );
    }

    public static int executeCommandLine( Commandline cl, InputStream systemIn, StreamConsumer systemOut,
                                          StreamConsumer systemErr )
        throws CommandLineException
    {
        return executeCommandLine( cl, systemIn, systemOut, systemErr, 0 );
    }

    /**
     * @param cl               The command line to execute
     * @param systemIn         The input to read from, must be thread safe
     * @param systemOut        A consumer that receives output, must be thread safe
     * @param systemErr        A consumer that receives system error stream output, must be thread safe
     * @param timeoutInSeconds Positive integer to specify timeout, zero and negative integers for no timeout.
     * @return A return value, see {@link Process#exitValue()}
     * @throws CommandLineException or CommandLineTimeOutException if time out occurs
     * @noinspection ThrowableResultOfMethodCallIgnored
     */
    public static int executeCommandLine( Commandline cl, InputStream systemIn, StreamConsumer systemOut,
                                          StreamConsumer systemErr, int timeoutInSeconds )
        throws CommandLineException
    {
        final CommandLineCallable future =
            executeCommandLineAsCallable( cl, systemIn, systemOut, systemErr, timeoutInSeconds );
        return future.call();
    }

    private static final long WAIT_SLEEP_PERIOD_MS = 100;
    
    /**
     * Immediately forks a process, returns a callable that will block until process is complete.
     * @param cl               The command line to execute
     * @param systemIn         The input to read from, must be thread safe
     * @param systemOut        A consumer that receives output, must be thread safe
     * @param systemErr        A consumer that receives system error stream output, must be thread safe
     * @param timeoutInSeconds Positive integer to specify timeout, zero and negative integers for no timeout.
     * @return A CommandLineCallable that provides the process return value, see {@link Process#exitValue()}. "call" must be called on
     *         this to be sure the forked process has terminated, no guarantees is made about
     *         any internal state before after the completion of the call statements
     * @throws CommandLineException or CommandLineTimeOutException if time out occurs
     * @noinspection ThrowableResultOfMethodCallIgnored
     */
    public static CommandLineCallable executeCommandLineAsCallable( final Commandline cl, 
    		                                                      final InputStream systemIn,
                                                                  final StreamConsumer systemOut,
                                                                  final StreamConsumer systemErr,
                                                                  final int timeoutInSeconds )
        throws CommandLineException
    {
        if ( cl == null )
        {
            throw new IllegalArgumentException( "cl cannot be null." );
        }
        
        final Process p = cl.execute();

        final StreamFeeder inputFeeder = systemIn != null ?
             new StreamFeeder( systemIn, p.getOutputStream() ) : null;
        final StreamPumper outputPumper = new StreamPumper( p.getInputStream(), /*new PrintWriter(System.out),DEBUG*/ systemOut );
        final StreamPumper errorPumper = new StreamPumper( p.getErrorStream(), /*new PrintWriter(System.out),DEBUG*/ systemErr );

        if ( inputFeeder != null )
        {
            inputFeeder.start();
        }
        outputPumper.start();
        errorPumper.start();

        final ProcessHook processHookThread = new ProcessHook(p);

        ShutdownHookUtils.addShutDownHook( processHookThread );

        return new CommandLineCallable()
        {
        	@Override
            public Integer call()
                throws CommandLineException
            {
        	      boolean makeFullThreadDump = true;
                try
                {
                    int returnValue;
                    if ( timeoutInSeconds <= 0 )
                    {
                        returnValue = p.waitFor(); // NB: may be interrupt()-ed here.
                    }
                    else
                    {
                        final long now = System.currentTimeMillis();
                        final long timeoutInMillis = 1000L * timeoutInSeconds;
                        final long finish = now + timeoutInMillis;
                        while ( isAlive( p ) && ( System.currentTimeMillis() < finish ) )
                        {
                          Thread.sleep( WAIT_SLEEP_PERIOD_MS ); // NB: may be interrupt()-ed here.
                        }
                        if ( isAlive( p ) )
                        {
                          // process timeout:
                        	System.out.println("##### process timed out after "+timeoutInSeconds+" seconds.");
                            throw new CommandLineTimeOutException( "Process timeout out after " + timeoutInSeconds + " seconds." );
                        }
                        returnValue = p.exitValue();
                    }

                    waitForAllPumpers( inputFeeder, outputPumper, errorPumper );

                    final Exception outExc = outputPumper.getException();
                    if ( outExc != null )
                    {
                        throw new CommandLineException( "Error inside systemOut parser", outExc );
                    }
                    final Exception errExc = errorPumper.getException();
                    if ( errExc != null )
                    {
                        throw new CommandLineException( "Error inside systemErr parser", errExc );
                    }
                    if (returnValue != 0) {
                	      System.out.println("Process finished with exit status "+returnValue);
                    }
                    return returnValue;
                }
                catch (final InterruptedException ie)
                {
                  // NB: do not make FTD since this is *not* a real timeout: we just shouldn't wait for the process any more:
                  makeFullThreadDump = false;  
                  throw new CommandLineTimeOutException( "Interrupted while waiting for the test process to end: "+ie.toString(), ie );
                }
                finally
                {
                    ShutdownHookUtils.removeShutdownHook( processHookThread );

                    final boolean terminated = processHookThread.run(makeFullThreadDump/*make full thread dump*/);
                    if (terminated) {
                    	try {
                    		// fully read the output:
                    		waitForAllPumpers( inputFeeder, outputPumper, errorPumper );
                    	} catch (InterruptedException ie) {
                    		ie.printStackTrace(System.out);
                    	}
                    }
                    
                    // disable all pumpers:
                    if ( inputFeeder != null )
                    {
                    	inputFeeder.disable();
                    }
                    outputPumper.disable();
                    errorPumper.disable();

                    // close all pumpers:
                    try {
                    	if ( inputFeeder != null )
                    	{
                    		inputFeeder.close();
                    	}
                    	outputPumper.close();
                    	errorPumper.close();
                    } catch (Exception e) {
                    	System.out.println("Error while closing feeder and pumpers:");
                    	e.printStackTrace(System.out);
                    }
                    
                    if (!terminated) {
                    	// fail and abort the execution:
                    	throw new CommandLineException("Failed to terminate the process.");
                    }
                }
            }
        };
    }

    private static void waitForAllPumpers( StreamFeeder inputFeeder, StreamPumper outputPumper,
                                           StreamPumper errorPumper )
        throws InterruptedException
    {
        if ( inputFeeder != null )
        {
            inputFeeder.waitUntilDone();
        }

        outputPumper.waitUntilDone();
        errorPumper.waitUntilDone();
    }

    /**
     * Gets the shell environment variables for this process. Note that the returned mapping from variable names to
     * values will always be case-sensitive regardless of the platform, i.e. <code>getSystemEnvVars().get("path")</code>
     * and <code>getSystemEnvVars().get("PATH")</code> will in general return different values. However, on platforms
     * with case-insensitive environment variables like Windows, all variable names will be normalized to upper case.
     *
     * @return The shell environment variables, can be empty but never <code>null</code>.
     * @throws IOException If the environment variables could not be queried from the shell.
     * @see System#getenv() System.getenv() API, new in JDK 5.0, to get the same result
     *      <b>since 2.0.2 System#getenv() will be used if available in the current running jvm.</b>
     */
    public static Properties getSystemEnvVars()
        throws IOException
    {
        return getSystemEnvVars( !Os.isFamily( Os.FAMILY_WINDOWS ) );
    }

    /**
     * Return the shell environment variables. If <code>caseSensitive == true</code>, then envar
     * keys will all be upper-case.
     *
     * @param caseSensitive Whether environment variable keys should be treated case-sensitively.
     * @return Properties object of (possibly modified) envar keys mapped to their values.
     * @throws IOException .
     * @see System#getenv() System.getenv() API, new in JDK 5.0, to get the same result
     *      <b>since 2.0.2 System#getenv() will be used if available in the current running jvm.</b>
     */
    public static Properties getSystemEnvVars( boolean caseSensitive )
        throws IOException
    {

        // check if it's 1.5+ run 

        Method getenvMethod = getEnvMethod();
        if ( getenvMethod != null )
        {
            try
            {
                return getEnvFromSystem( getenvMethod, caseSensitive );
            }
            catch ( IllegalAccessException e )
            {
                throw new IOException( e.getMessage() );
            }
            catch ( IllegalArgumentException e )
            {
                throw new IOException( e.getMessage() );
            }
            catch ( InvocationTargetException e )
            {
                throw new IOException( e.getMessage() );
            }
        }

        Process p = null;

        try
        {
            Properties envVars = new Properties();

            Runtime r = Runtime.getRuntime();

            //If this is windows set the shell to command.com or cmd.exe with correct arguments.
            boolean overriddenEncoding = false;
            if ( Os.isFamily( Os.FAMILY_WINDOWS ) )
            {
                if ( Os.isFamily( Os.FAMILY_WIN9X ) )
                {
                    p = r.exec( "command.com /c set" );
                }
                else
                {
                    overriddenEncoding = true;
                    // /U = change stdout encoding to UTF-16LE to avoid encoding inconsistency
                    // between command-line/DOS and GUI/Windows, see PLXUTILS-124
                    p = r.exec( "cmd.exe /U /c set" );
                }
            }
            else
            {
                p = r.exec( "env" );
            }

            Reader reader = overriddenEncoding
                ? new InputStreamReader( p.getInputStream(), ReaderFactory.UTF_16LE )
                : new InputStreamReader( p.getInputStream() );
            BufferedReader br = new BufferedReader( reader );

            String line;

            String lastKey = null;
            String lastVal = null;

            while ( ( line = br.readLine() ) != null )
            {
                int idx = line.indexOf( '=' );

                if ( idx > 0 )
                {
                    lastKey = line.substring( 0, idx );

                    if ( !caseSensitive )
                    {
                        lastKey = lastKey.toUpperCase( Locale.ENGLISH );
                    }

                    lastVal = line.substring( idx + 1 );

                    envVars.setProperty( lastKey, lastVal );
                }
                else if ( lastKey != null )
                {
                    lastVal += "\n" + line;

                    envVars.setProperty( lastKey, lastVal );
                }
            }

            return envVars;
        }
        finally
        {
            if ( p != null )
            {
                IOUtil.close( p.getOutputStream() );
                IOUtil.close( p.getErrorStream() );
                IOUtil.close( p.getInputStream() );

                p.destroy();
            }
        }
    }

    public static boolean isAlive( Process p )
    {
        if ( p == null )
        {
            return false;
        }

        try
        {
            p.exitValue();
            return false;
        }
        catch ( IllegalThreadStateException e )
        {
            return true;
        }
    }

    public static String[] translateCommandline( String toProcess )
        throws Exception
    {
        if ( ( toProcess == null ) || ( toProcess.length() == 0 ) )
        {
            return new String[0];
        }

        // parse with a simple finite state machine

        final int normal = 0;
        final int inQuote = 1;
        final int inDoubleQuote = 2;
        int state = normal;
        StringTokenizer tok = new StringTokenizer( toProcess, "\"\' ", true );
        Vector<String> v = new Vector<String>();
        StringBuilder current = new StringBuilder();

        while ( tok.hasMoreTokens() )
        {
            String nextTok = tok.nextToken();
            switch ( state )
            {
                case inQuote:
                    if ( "\'".equals( nextTok ) )
                    {
                        state = normal;
                    }
                    else
                    {
                        current.append( nextTok );
                    }
                    break;
                case inDoubleQuote:
                    if ( "\"".equals( nextTok ) )
                    {
                        state = normal;
                    }
                    else
                    {
                        current.append( nextTok );
                    }
                    break;
                default:
                    if ( "\'".equals( nextTok ) )
                    {
                        state = inQuote;
                    }
                    else if ( "\"".equals( nextTok ) )
                    {
                        state = inDoubleQuote;
                    }
                    else if ( " ".equals( nextTok ) )
                    {
                        if ( current.length() != 0 )
                        {
                            v.addElement( current.toString() );
                            current.setLength( 0 );
                        }
                    }
                    else
                    {
                        current.append( nextTok );
                    }
                    break;
            }
        }

        if ( current.length() != 0 )
        {
            v.addElement( current.toString() );
        }

        if ( ( state == inQuote ) || ( state == inDoubleQuote ) )
        {
            throw new CommandLineException( "unbalanced quotes in " + toProcess );
        }

        String[] args = new String[v.size()];
        v.copyInto( args );
        return args;
    }

    /**
     * <p>Put quotes around the given String if necessary.</p>
     * <p>If the argument doesn't include spaces or quotes, return it
     * as is. If it contains double quotes, use single quotes - else
     * surround the argument by double quotes.</p>
     *
     * @throws CommandLineException if the argument contains both, single
     *                              and double quotes.
     * @deprecated Use {@link StringUtils#quoteAndEscape(String, char, char[], char[], char, boolean)},
     *             {@link StringUtils#quoteAndEscape(String, char, char[], char, boolean)}, or
     *             {@link StringUtils#quoteAndEscape(String, char)} instead.
     */
    @SuppressWarnings( { "JavaDoc", "deprecation" } )
    public static String quote( String argument )
        throws CommandLineException
    {
        return quote( argument, false, false, true );
    }

    /**
     * <p>Put quotes around the given String if necessary.</p>
     * <p>If the argument doesn't include spaces or quotes, return it
     * as is. If it contains double quotes, use single quotes - else
     * surround the argument by double quotes.</p>
     *
     * @throws CommandLineException if the argument contains both, single
     *                              and double quotes.
     * @deprecated Use {@link StringUtils#quoteAndEscape(String, char, char[], char[], char, boolean)},
     *             {@link StringUtils#quoteAndEscape(String, char, char[], char, boolean)}, or
     *             {@link StringUtils#quoteAndEscape(String, char)} instead.
     */
    @SuppressWarnings( { "JavaDoc", "UnusedDeclaration", "deprecation" } )
    public static String quote( String argument, boolean wrapExistingQuotes )
        throws CommandLineException
    {
        return quote( argument, false, false, wrapExistingQuotes );
    }

    /**
     * @deprecated Use {@link StringUtils#quoteAndEscape(String, char, char[], char[], char, boolean)},
     *             {@link StringUtils#quoteAndEscape(String, char, char[], char, boolean)}, or
     *             {@link StringUtils#quoteAndEscape(String, char)} instead.
     */
    @SuppressWarnings( { "JavaDoc" } )
    public static String quote( String argument, boolean escapeSingleQuotes, boolean escapeDoubleQuotes,
                                boolean wrapExistingQuotes )
        throws CommandLineException
    {
        if ( argument.contains( "\"" ) )
        {
            if ( argument.contains( "\'" ) )
            {
                throw new CommandLineException( "Can't handle single and double quotes in same argument" );
            }
            else
            {
                if ( escapeSingleQuotes )
                {
                    return "\\\'" + argument + "\\\'";
                }
                else if ( wrapExistingQuotes )
                {
                    return '\'' + argument + '\'';
                }
            }
        }
        else if ( argument.contains( "\'" ) )
        {
            if ( escapeDoubleQuotes )
            {
                return "\\\"" + argument + "\\\"";
            }
            else if ( wrapExistingQuotes )
            {
                return '\"' + argument + '\"';
            }
        }
        else if ( argument.contains( " " ) )
        {
            if ( escapeDoubleQuotes )
            {
                return "\\\"" + argument + "\\\"";
            }
            else
            {
                return '\"' + argument + '\"';
            }
        }

        return argument;
    }

    public static String toString( String[] line )
    {
        // empty path return empty string
        if ( ( line == null ) || ( line.length == 0 ) )
        {
            return "";
        }

        // path containing one or more elements
        final StringBuilder result = new StringBuilder();
        for ( int i = 0; i < line.length; i++ )
        {
            if ( i > 0 )
            {
                result.append( ' ' );
            }
            try
            {
                result.append( StringUtils.quoteAndEscape( line[i], '\"' ) );
            }
            catch ( Exception e )
            {
                System.err.println( "Error quoting argument: " + e.getMessage() );
            }
        }
        return result.toString();
    }

    private static Method getEnvMethod()
    {
        try
        {
            return System.class.getMethod( "getenv");
        }
        catch ( NoSuchMethodException e )
        {
            return null;
        }
        catch ( SecurityException e )
        {
            return null;
        }
    }

    private static Properties getEnvFromSystem( Method method, boolean caseSensitive )
        throws IllegalAccessException, IllegalArgumentException, InvocationTargetException
    {
        Properties envVars = new Properties();
        @SuppressWarnings( { "unchecked" } ) Map<String, String> envs = (Map<String, String>) method.invoke( null );
        for ( String key : envs.keySet() )
        {
            String value = envs.get( key );
            if ( !caseSensitive )
            {
                key = key.toUpperCase( Locale.ENGLISH );
            }
            envVars.put( key, value );
        }
        return envVars;
    }
}
