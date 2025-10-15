import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class hold {
    public static void main(String[] args) throws IOException {
        int port = 8080;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server running on port " + port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                new Thread(() -> handleClient(clientSocket)).start();
            }
        }
    }

    private static void handleClient(Socket clientSocket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             OutputStream out = clientSocket.getOutputStream()) {

            String line = in.readLine();
            if (line == null || line.isEmpty()) return;

            System.out.println("Request: " + line);
            String path = line.split(" ")[1];

            // --- App endpoint ---
            if (path.startsWith("/app/run")) {
                String cmd = extractCmdFromQuery(path);
                String result = executePythonCommand(cmd);
                sendHttpJson(out, 200, Map.of("status", "ok", "output", result));
            } else {
                sendHttpJson(out, 404, Map.of("status", "error", "message", "Unknown endpoint"));
            }

        } catch (Exception e) {
            try {
                sendHttpJson(clientSocket.getOutputStream(), 500, Map.of("status", "error", "message", e.getMessage()));
            } catch (IOException ignored) {}
        } finally {
            try { clientSocket.close(); } catch (IOException ignored) {}
        }
    }

    // ---------------- Extract 'cmd' query parameter ----------------
    private static String extractCmdFromQuery(String path) throws UnsupportedEncodingException {
        if (!path.contains("cmd=")) return "";
        String query = path.split("\\?")[1];
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            String[] kv = pair.split("=");
            if (kv[0].equals("cmd")) return URLDecoder.decode(kv[1], StandardCharsets.UTF_8);
        }
        return "";
    }

    // ---------------- Call Python parser ----------------
    private static String executePythonCommand(String command) throws IOException, InterruptedException {
        String pythonScript = "/media/kevin/256GB/code/server/main.py";
        List<String> cmd = new ArrayList<>();
        cmd.add("python3");
        cmd.add(pythonScript);
        cmd.add(command);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) output.append(line).append("\n");
        }

        process.waitFor();
        return output.toString().trim();
    }

    // ---------------- Send JSON response ----------------
    private static void sendHttpJson(OutputStream out, int status, Map<String, String> data) throws IOException {
        String body = new com.google.gson.Gson().toJson(data); // wait for a resons from the target and send that
        PrintWriter pw = new PrintWriter(out, false);
        pw.printf("HTTP/1.1 %d OK\r\n", status);
        pw.printf("Content-Type: application/json\r\n");
        pw.printf("Content-Length: %d\r\n", body.getBytes().length);
        pw.print("\r\n");
        pw.print(body);
        pw.flush();
    }
}





