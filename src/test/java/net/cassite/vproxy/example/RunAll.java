package net.cassite.vproxy.example;

public class RunAll {
    public static void main(String[] args) throws Exception {
        System.out.println("==============================================");
        System.out.println("     selector event loop echo server");
        System.out.println("==============================================");
        SelectorEventLoopEchoServer.main(new String[0]);

        System.out.println("==============================================");
        System.out.println("         net event loop echo server");
        System.out.println("==============================================");
        NetEventLoopEchoServer.main(new String[0]);

        System.out.println("==============================================");
        System.out.println("   net event loop split buffers echo server");
        System.out.println("==============================================");
        NetEventLoopSplitBuffersEchoServer.main(new String[0]);
    }
}
