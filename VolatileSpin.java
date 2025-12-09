public class VolatileSpin {
    static volatile boolean running = true;

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: jbang VolatileSpin.java <numThreads>");
            System.exit(1);
        }

        int numThreads = Integer.parseInt(args[0]);
        Thread[] threads = new Thread[numThreads];

        for (int i = 0; i < numThreads; i++) {
            threads[i] = new Thread(() -> {
                while (running) {
                    // Tight loop reading volatile field
                    if (!running) break;
                }
            }, "spinner-" + i);
            threads[i].start();
        }

        System.out.println("Started " + numThreads + " spinning threads.");
        System.out.println("Press Enter to stop...");
        System.in.read();
        running = false;

        for (Thread t : threads) t.join();
        System.out.println("All threads stopped.");
    }
}
