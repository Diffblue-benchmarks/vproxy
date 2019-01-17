package net.cassite.vproxy.connection;

import net.cassite.vproxy.selector.Handler;
import net.cassite.vproxy.selector.HandlerContext;
import net.cassite.vproxy.selector.SelectorEventLoop;
import net.cassite.vproxy.util.Logger;

import java.io.IOException;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;

public class NetEventLoop {
    private static final HandlerForServer handlerForServer = new HandlerForServer();
    private static final HandlerForConnection handlerForConnection = new HandlerForClientConnection();
    private static final HandlerForClientConnection handlerForClientConnection = new HandlerForClientConnection();

    final SelectorEventLoop selectorEventLoop;

    public NetEventLoop(SelectorEventLoop selectorEventLoop) {
        this.selectorEventLoop = selectorEventLoop;
    }

    public void addServer(Server server, Object attachment, ServerHandler handler) throws IOException {
        server.eventLoop = this;
        selectorEventLoop.add(server.channel, SelectionKey.OP_ACCEPT,
            new ServerHandlerContext(this, server, attachment, handler),
            handlerForServer);
    }

    public void addConnection(Connection connection, Object attachment, ConnectionHandler handler) throws IOException {
        int opts = SelectionKey.OP_READ;
        if (connection.outBuffer.used() > 0) {
            opts |= SelectionKey.OP_WRITE;
        }
        connection.eventLoop = this;
        selectorEventLoop.add(connection.channel, opts,
            new ConnectionHandlerContext(this, connection, attachment, handler),
            handlerForConnection);
    }

    public void addClientConnection(ClientConnection connection, Object attachment, ClientConnectionHandler handler) throws IOException {
        int opts = SelectionKey.OP_CONNECT;
        connection.eventLoop = this;
        selectorEventLoop.add(connection.channel, opts,
            new ClientConnectionHandlerContext(this, connection, attachment, handler),
            handlerForClientConnection);
    }

    public void loop() {
        selectorEventLoop.loop();
    }
}

class HandlerForServer implements Handler<ServerSocketChannel> {
    @Override
    public void accept(HandlerContext<ServerSocketChannel> ctx) {
        ServerHandlerContext sctx = (ServerHandlerContext) ctx.getAttachment();

        ServerSocketChannel server = ctx.getChannel();
        SocketChannel sock;
        try {
            sock = server.accept();
        } catch (IOException e) {
            sctx.handler.acceptFail(sctx, e);
            return;
        }
        if (sock == null) {
            Logger.shouldNotHappen("no socket yet, ignore this event");
            return;
        }
        Connection conn = sctx.handler.getConnection(sock);
        if (conn != null) { // the user code may return null if got error
            sctx.handler.connection(sctx, conn);
        }
    }

    @Override
    public void connected(HandlerContext<ServerSocketChannel> ctx) {
        // will not fire
        Logger.shouldNotHappen("server should not fire `connected`");
    }

    @Override
    public void readable(HandlerContext<ServerSocketChannel> ctx) {
        // will not fire
        Logger.shouldNotHappen("server should not fire readable");
    }

    @Override
    public void writable(HandlerContext<ServerSocketChannel> ctx) {
        // will not fire
        Logger.shouldNotHappen("server should not fire writable");
    }
}

class HandlerForConnection implements Handler<SocketChannel> {
    @Override
    public void accept(HandlerContext<SocketChannel> ctx) {
        // will not fire
        Logger.shouldNotHappen("connection should not fire accept");
    }

    @Override
    public void connected(HandlerContext<SocketChannel> ctx) {
        // will not fire
        Logger.shouldNotHappen("connection should not fire connected");
    }

    @Override
    public void readable(HandlerContext<SocketChannel> ctx) {
        ConnectionHandlerContext cctx = (ConnectionHandlerContext) ctx.getAttachment();
        if (cctx.connection.inBuffer.free() == 0) {
            Logger.shouldNotHappen("the connection has no space to store data");
            return;
        }
        int read;
        try {
            read = cctx.connection.inBuffer.storeBytesFrom(ctx.getChannel());
        } catch (IOException e) {
            cctx.handler.exception(cctx, e);
            return;
        }
        if (read < 0) {
            // EOF, the remote write is closed
            cctx.connection.remoteClosed = true;
            // remove read event add write event (maybe more bytes to write)
            ctx.modify(SelectionKey.OP_WRITE);
            // the connection will be closed after write
            return;
        }
        if (read == 0) {
            Logger.shouldNotHappen("read nothing, the event should not be fired");
            return;
        }
        cctx.handler.readable(cctx); // the in buffer definitely have some bytes, let client code read
        if (cctx.connection.inBuffer.free() == 0) {
            // the in-buffer is full, and client code cannot read, remove read event
            Logger.lowLevelDebug("the inBuffer is full now, remove READ event");
            ctx.rmOps(SelectionKey.OP_READ);
        }
    }

    @Override
    public void writable(HandlerContext<SocketChannel> ctx) {
        ConnectionHandlerContext cctx = (ConnectionHandlerContext) ctx.getAttachment();
        if (cctx.connection.outBuffer.used() == 0) {
            if (cctx.connection.remoteClosed) {
                // no bytes to write, then the connection can be closed now
                cctx.connection.close();
                cctx.handler.closed(cctx);
            } else {
                Logger.shouldNotHappen("the connection has nothing to write");
            }
            return;
        }
        int write;
        try {
            write = cctx.connection.outBuffer.writeTo(ctx.getChannel());
        } catch (IOException e) {
            cctx.handler.exception(cctx, e);
            return;
        }
        if (write <= 0) {
            Logger.shouldNotHappen("wrote nothing, the event should not be fired");
            // we ignore it for now
            return;
        }
        cctx.handler.writable(cctx); // the out buffer definitely have some free space, let client code write
        if (cctx.connection.outBuffer.used() == 0) {
            // all bytes flushed, and no client bytes for now, remove write event
            Logger.lowLevelDebug("the outBuffer is empty now, remove WRITE event");
            ctx.rmOps(SelectionKey.OP_WRITE);
        }
    }
}

class HandlerForClientConnection extends HandlerForConnection {
    @Override
    public void connected(HandlerContext<SocketChannel> ctx) {
        ClientConnectionHandlerContext cctx = (ClientConnectionHandlerContext) ctx.getAttachment();

        int opts = SelectionKey.OP_READ;
        if (cctx.connection.outBuffer.used() > 0) {
            opts |= SelectionKey.OP_WRITE;
        }
        ctx.modify(opts);
        cctx.handler.connected(cctx);
    }
}
