let io; // undefined until init

module.exports.init = (httpServer) => {
    if (io) return io; // return same io if init'd

    io = require('socket.io')(httpServer, {
        cors: {
            origin: ['https://localhost:3443', 'https://localhost:8888', 'https://localhost:3443', 'https://localhost:8888'],
            methods: ['GET', 'POST'],
            credentials: true
        },
        allowEIO3: true
    });
    return io;
};

module.exports.get = () => {
    if (!io) throw new Error('socket.io not initialised yet');
    return io;
};
