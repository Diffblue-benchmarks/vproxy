package net.cassite.vproxy.ci;

import io.vertx.core.Vertx;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.redis.client.*;
import org.junit.*;

import java.util.*;

import static org.junit.Assert.*;

public class CI {
    private static Command getCommand(String name) {
        return Command.create(name, 100, 0, 0, 0, false, false);
    }

    private static Command list = getCommand("list");
    private static Command list_detail = getCommand("list-detail");
    private static Command add = getCommand("add");
    private static Command update = getCommand("update");
    private static Command remove = getCommand("remove");

    private static Vertx vertx;
    private static Redis redis;
    private static WebClient webClient;

    @BeforeClass
    public static void setUpClass() throws Exception {
        String strPort = System.getProperty("vproxy_port");
        if (strPort == null)
            strPort = System.getenv("vproxy_port");
        if (strPort == null)
            strPort = "16379";
        int port = Integer.parseInt(strPort);

        String password = System.getProperty("vproxy_password");
        if (password == null)
            password = System.getenv("vproxy_password");
        if (password == null)
            password = "123456";

        if (System.getProperty("vproxy_exists") == null && System.getenv("vproxy_exists") == null) {
            net.cassite.vproxy.app.Main.main(new String[]{
                "resp-controller", "localhost:" + port, password,
                "allowSystemCallInNonStdIOController",
                "noStdIOController",
                "noLoadLast",
                "noSave"
            });
        }

        vertx = Vertx.vertx();
        redis = Redis.createClient(vertx, new RedisOptions()
            .setEndpoint(SocketAddress.inetSocketAddress(port, "127.0.0.1"))
        );
        Throwable[] err = {null};
        boolean[] done = {false};
        redis.connect(r -> {
            if (r.failed()) {
                err[0] = r.cause();
            } else {
                done[0] = true;
            }
        });
        while (true) {
            if (err[0] != null)
                throw new IllegalArgumentException(err[0]);
            if (done[0]) {
                break;
            }
            Thread.sleep(1);
        }
        execute(Request.cmd(Command.AUTH).arg(password));

        vertx.createHttpServer().requestHandler(req -> req.response().end("7771")).listen(7771);
        vertx.createHttpServer().requestHandler(req -> req.response().end("7772")).listen(7772);
        vertx.createHttpServer().requestHandler(req -> req.response().end("7773")).listen(7773);

        webClient = WebClient.create(vertx, new WebClientOptions()
            .setKeepAlive(false)
        );
    }

    @AfterClass
    public static void tearDownClass() {
        vertx.close();
    }

    private List<String> tlNames = new ArrayList<>();
    private List<String> socks5Names = new ArrayList<>();
    private List<String> elgNames = new ArrayList<>();
    private List<String> sgsNames = new ArrayList<>();
    private List<String> sgNames = new ArrayList<>();
    private List<String> securgNames = new ArrayList<>();
    private List<String> slgNames = new ArrayList<>();

    private String elg0;
    private String elg1;
    private String sgs0;

    private WebClient socks5WebClient = null;

    @Before
    public void setUp() {
        elg0 = randomName("elg0");
        execute(createReq(add, "event-loop-group", elg0));
        elgNames.add(elg0);
        checkCreate("event-loop-group", elg0);

        elg1 = randomName("elg1");
        execute(createReq(add, "event-loop-group", elg1));
        elgNames.add(elg1);
        checkCreate("event-loop-group", elg1);

        for (int i = 0; i < 2; ++i) {
            String name = randomName("el0" + i);
            execute(createReq(add, "event-loop", name, "to", "event-loop-group", elg0));
            checkCreate("event-loop", name, "event-loop-group", elg0);
        }
        for (int i = 0; i < 2; ++i) {
            String name = randomName("el1" + i);
            execute(createReq(add, "event-loop", name, "to", "event-loop-group", elg1));
            checkCreate("event-loop", name, "event-loop-group", elg1);
        }

        sgs0 = randomName("sgs0");
        execute(createReq(add, "server-groups", sgs0));
        sgsNames.add(sgs0);
        checkCreate("server-groups", sgs0);
    }

    @After
    public void tearDown() {
        // remove one another according to dependency
        // remove smart-lb-group
        for (String slg : slgNames) {
            execute(createReq(remove, "smart-lb-group", slg));
            checkRemove("smart-lb-group", slg);
        }
        // remove tl
        for (String tl : tlNames) {
            execute(createReq(remove, "tcp-lb", tl));
            checkRemove("tcp-lb", tl);
        }
        // remove socks5
        for (String socks5 : socks5Names) {
            execute(createReq(remove, "socks5-server", socks5));
            checkRemove("socks5-server", socks5);
        }
        // remove server groups
        for (String sgs : sgsNames) {
            execute(createReq(remove, "server-groups", sgs));
            checkRemove("server-groups", sgs);
        }
        // remove server group
        for (String sg : sgNames) {
            execute(createReq(remove, "server-group", sg));
            checkRemove("server-group", sg);
        }
        // remove event loop group
        for (String elg : elgNames) {
            execute(createReq(remove, "event-loop-group", elg));
            checkRemove("event-loop-group", elg);
        }
        // remove security group
        for (String securg : securgNames) {
            execute(createReq(remove, "security-group", securg));
            checkRemove("security-group", securg);
        }

        if (socks5WebClient != null) {
            socks5WebClient.close();
        }
    }

    private void initSocks5Client(int port) {
        socks5WebClient = WebClient.create(vertx, new WebClientOptions()
            .setKeepAlive(false)
            .setProxyOptions(new ProxyOptions()
                .setHost("127.0.0.1")
                .setPort(port)
                .setType(ProxyType.SOCKS5)
            )
        );
    }

    private static Response _execute(Request req) {
        Response[] resp = {null};
        Throwable[] t = {null};
        redis.send(req, r -> {
            if (r.failed()) {
                t[0] = r.cause();
            } else {
                resp[0] = r.result();
            }
        });
        while (true) {
            if (t[0] != null)
                throw new RuntimeException(t[0]);
            if (resp[0] != null) {
                Response r = resp[0];
                if (r.type() == ResponseType.ERROR) {
                    throw new RuntimeException(r.toString());
                }
                System.err.println(r);
                return r;
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static void execute(Request req) {
        Response r = _execute(req);
        assertEquals(ResponseType.BULK, r.type());
        assertEquals("OK", r.toString());
    }

    private static List<String> queryList(Request req) {
        Response r = _execute(req);
        assertEquals(ResponseType.MULTI, r.type());
        List<String> list = new LinkedList<>();
        for (int i = 0; i < r.size(); ++i) {
            Response rr = r.get(i);
            assertEquals(ResponseType.BULK, rr.type());
            list.add(rr.toString());
        }
        return list;
    }

    private static String randomName(String n) {
        int time = (int) (System.currentTimeMillis() % 3600_000);
        int rand = (int) (Math.random() * 1000);
        return n + "-" + time + "-" + rand;
    }

    private static Request createReq(Command cmd, String... args) {
        Request req = Request.cmd(cmd);
        for (String s : args) {
            req.arg(s);
        }
        return req;
    }

    private static void checkCreate(String resource, String name) {
        List<String> names = queryList(createReq(list, resource));
        assertTrue(names.contains(name));
        List<String> names2 = new ArrayList<>();
        List<String> details = queryList(createReq(list_detail, resource));
        for (String detail : details) {
            names2.add(detail.split(" ")[0]);
        }
        assertEquals(names2, names);
        assertTrue(names2.contains(name));
    }

    private static void checkCreate(String resource, String name, String parentResource, String parentName) {
        List<String> names = queryList(createReq(list, resource, "in", parentResource, parentName));
        assertTrue(names.contains(name));
        List<String> names2 = new ArrayList<>();
        List<String> details = queryList(createReq(list_detail, resource, "in", parentResource, parentName));
        for (String detail : details) {
            names2.add(detail.split(" ")[0]);
        }
        assertEquals(names2, names);
        assertTrue(names2.contains(name));
    }

    private static Map<String, String> getDetail(String resource, String name) {
        List<String> details = queryList(createReq(list_detail, resource));
        for (String detail : details) {
            String[] array = detail.split(" ");
            if (!array[0].equals(name)) {
                continue;
            }
            assertEquals("->", array[1]);
            Map<String, String> map = new HashMap<>();
            String last = null;
            for (int i = 2; i < array.length; ++i) {
                if (last == null) {
                    if (Arrays.asList("allow-non-backend", "deny-non-backend").contains(array[i])) {
                        map.put(array[i], "");
                    } else {
                        last = array[i];
                    }
                } else {
                    map.put(last, array[i]);
                    last = null;
                }
            }
            if (last != null)
                throw new IllegalArgumentException("the detail result is invalid: " + detail);
            return map;
        }
        throw new NoSuchElementException();
    }

    private static void checkRemove(String resource, String name) {
        List<String> names = queryList(createReq(list, resource));
        assertFalse(names.contains(name));
        names = new ArrayList<>();
        List<String> details = queryList(createReq(list_detail, resource));
        for (String detail : details) {
            names.add(detail.split(" ")[0]);
        }
        assertFalse(names.contains(name));
    }

    private static void checkRemove(String resource, String name, String parentResource, String parentName) {
        List<String> names = queryList(createReq(list, resource, "in", parentResource, parentName));
        assertFalse(names.contains(name));
        names = new ArrayList<>();
        List<String> details = queryList(createReq(list_detail, resource, "in", parentResource, parentName));
        for (String detail : details) {
            names.add(detail.split(" ")[0]);
        }
        assertFalse(names.contains(name));
    }

    private static String request(WebClient webClient, String host, int port) {
        Throwable[] t = {null};
        String[] str = {null};
        webClient.get(port, host, "/").send(r -> {
            if (r.failed()) {
                t[0] = r.cause();
            } else {
                str[0] = r.result().body().toString();
            }
        });
        while (true) {
            if (t[0] != null)
                throw new IllegalArgumentException(t[0]);
            if (str[0] != null)
                return str[0];
            try {
                Thread.sleep(1);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    private static String request(int port) {
        return request(webClient, "127.0.0.1", port);
    }

    private String requestViaProxy(String host, int port) {
        return request(socks5WebClient, host, port);
    }

    @Test
    public void simpleLB() throws Exception {
        int port = 7001;
        String lbName = randomName("lb0");
        execute(createReq(add, "tcp-lb", lbName,
            "acceptor-elg", elg0, "event-loop-group", elg1,
            "address", "127.0.0.1:" + port,
            "server-groups", sgs0));
        tlNames.add(lbName);
        checkCreate("tcp-lb", lbName);
        Map<String, String> detail = getDetail("tcp-lb", lbName);
        assertEquals(elg0, detail.get("acceptor"));
        assertEquals(elg1, detail.get("worker"));
        assertEquals("127.0.0.1:" + port, detail.get("bind"));
        assertEquals(sgs0, detail.get("backends"));
        assertEquals("16384", detail.get("in-buffer-size"));
        assertEquals("16384", detail.get("out-buffer-size"));
        assertEquals("(allow-all)", detail.get("security-group"));

        String sg0 = randomName("sg0");
        execute(createReq(add, "server-group", sg0,
            "timeout", "500", "period", "200", "up", "2", "down", "5",
            "event-loop-group", elg0));
        sgNames.add(sg0);
        checkCreate("server-group", sg0);

        execute(createReq(add, "server-group", sg0, "to", "server-groups", sgs0, "weight", "10"));
        checkCreate("server-group", sg0, "server-groups", sgs0);

        execute(createReq(add, "server", "sg7771", "to", "server-group", sg0, "address", "127.0.0.1:7771", "weight", "10"));
        execute(createReq(add, "server", "sg7772", "to", "server-group", sg0, "address", "127.0.0.1:7772", "weight", "10"));
        checkCreate("server", "sg7771", "server-group", sg0);
        checkCreate("server", "sg7772", "server-group", sg0);

        Thread.sleep(500);

        String resp1 = request(7001);
        String resp2 = request(7001);
        if (resp1.equals("7772")) {
            String foo = resp1;
            resp1 = resp2;
            resp2 = foo;
        }
        assertEquals("7771", resp1);
        assertEquals("7772", resp2);
    }

    @Test
    public void simpleSocks5() throws Exception {
        int port = 7002;
        String socks5Name = randomName("s0");
        execute(createReq(add, "socks5-server", socks5Name,
            "acceptor-elg", elg0, "event-loop-group", elg1,
            "address", "127.0.0.1:" + port,
            "server-groups", sgs0));
        socks5Names.add(socks5Name);
        checkCreate("socks5-server", socks5Name);
        Map<String, String> detail = getDetail("socks5-server", socks5Name);
        assertEquals(elg0, detail.get("acceptor"));
        assertEquals(elg1, detail.get("worker"));
        assertEquals("127.0.0.1:" + port, detail.get("bind"));
        assertEquals(sgs0, detail.get("backends"));
        assertEquals("16384", detail.get("in-buffer-size"));
        assertEquals("16384", detail.get("out-buffer-size"));
        assertEquals("(allow-all)", detail.get("security-group"));

        String sg0 = "myexample.com:8080";
        execute(createReq(add, "server-group", sg0,
            "timeout", "500", "period", "200", "up", "2", "down", "5",
            "event-loop-group", elg0));
        sgNames.add(sg0);
        checkCreate("server-group", sg0);

        String sg1 = "myexample2.com:8080";
        execute(createReq(add, "server-group", sg1,
            "timeout", "500", "period", "200", "up", "2", "down", "5",
            "event-loop-group", elg0));
        sgNames.add(sg1);
        checkCreate("server-group", sg1);

        execute(createReq(add, "server-group", sg0, "to", "server-groups", sgs0, "weight", "10"));
        checkCreate("server-group", sg0, "server-groups", sgs0);
        execute(createReq(add, "server-group", sg1, "to", "server-groups", sgs0, "weight", "10"));
        checkCreate("server-group", sg1, "server-groups", sgs0);

        execute(createReq(add, "server", "sg7771", "to", "server-group", sg0, "address", "127.0.0.1:7771", "weight", "10"));
        checkCreate("server", "sg7771", "server-group", sg0);
        execute(createReq(add, "server", "sg7772", "to", "server-group", sg0, "address", "127.0.0.1:7772", "weight", "10"));
        checkCreate("server", "sg7772", "server-group", sg0);
        execute(createReq(add, "server", "sg7773", "to", "server-group", sg1, "address", "127.0.0.1:7773", "weight", "10"));
        checkCreate("server", "sg7773", "server-group", sg1);

        Thread.sleep(500);

        initSocks5Client(port);
        {
            boolean got7771 = false;
            boolean got7772 = false;
            for (int i = 0; i < 10; ++i) {
                String resp = requestViaProxy("myexample.com", 8080);
                assertTrue("7771".equals(resp) || "7772".equals(resp));
                if (resp.equals("7771")) got7771 = true;
                if (resp.equals("7772")) got7772 = true;
            }
            assertTrue(got7771 && got7772);
        }
        {
            for (int i = 0; i < 10; ++i) {
                String resp = requestViaProxy("myexample2.com", 8080);
                assertEquals("7773", resp);
            }
        }
    }
}
