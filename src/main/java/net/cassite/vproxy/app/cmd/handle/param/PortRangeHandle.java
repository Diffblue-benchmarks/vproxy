package net.cassite.vproxy.app.cmd.handle.param;

import net.cassite.vproxy.app.cmd.Command;
import net.cassite.vproxy.app.cmd.Param;
import net.cassite.vproxy.util.Tuple;

public class PortRangeHandle {
    private PortRangeHandle() {
    }

    public static void check(Command cmd) throws Exception {
        Tuple<Integer, Integer> tuple;
        try {
            tuple = get(cmd);
        } catch (Exception e) {
            throw new Exception("invalid format for " + Param.portrange.fullname);
        }
        if (tuple.left < 0 || tuple.left > tuple.right || tuple.right > 65535) {
            throw new Exception("invalid format for " + Param.portrange.fullname);
        }
    }

    public static Tuple<Integer, Integer> get(Command cmd) {
        String range = cmd.args.get(Param.portrange);
        String[] arr = range.split(",");
        if (arr.length > 2)
            throw new IllegalArgumentException();
        int minPort = Integer.parseInt(arr[0]);
        int maxPort = Integer.parseInt(arr[1]);
        return new Tuple<>(minPort, maxPort);
    }
}
