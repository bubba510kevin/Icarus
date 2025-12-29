public class pipes {
    
    static {
        System.loadLibrary("PipeServerDLL"); // Loads PipeServerDLL.dll
    }

    public native boolean startServer(String pipeName);
    public native boolean send(byte[] data);
    public native byte[] receive(int maxBytes);
    public native void closeServer();

    public static void main(String[] args) {
        pipes ps = new pipes();

        if (ps.startServer("\\\\.\\pipe\\MyPipe")) {
            System.out.println("Pipe started.");

            ps.send("Hello from Java".getBytes());

            byte[] msg = ps.receive(1024);
            System.out.println("Received: " + new String(msg));

            ps.closeServer();
        }
    }

}
