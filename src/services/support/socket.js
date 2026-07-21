import { Server } from 'socket.io';
import { verifyToken } from '../auth/auth.js';
import { addSupportMessage, markSeen } from '../../db/support.repo.js';

const ADMINS = 'admins';
const room = (uid) => 'u:' + uid;

// Attach the support socket.io server to the HTTP server.
export function initSupportSocket(httpServer, corsOrigins) {
  const io = new Server(httpServer, {
    path: '/socket.io',
    cors: { origin: corsOrigins, credentials: true },
  });

  // Handshake auth: JWT in auth.token → user or admin.
  io.use((socket, next) => {
    const payload = verifyToken(socket.handshake.auth?.token || '');
    if (!payload?.sub) return next(new Error('unauthorized'));
    socket.data.isAdmin = payload.adm === true;
    socket.data.userId = payload.sub; // for a user, this is their user id
    next();
  });

  io.on('connection', (socket) => {
    if (socket.data.isAdmin) socket.join(ADMINS);
    else socket.join(room(socket.data.userId));

    // Send a message.
    socket.on('support:send', async ({ content, toUserId } = {}) => {
      const text = String(content || '').trim();
      if (!text) return;
      const isAdmin = socket.data.isAdmin;
      const userId = isAdmin ? toUserId : socket.data.userId;
      if (!userId) return;
      try {
        const msg = await addSupportMessage(userId, isAdmin ? 'admin' : 'user', text);
        io.to(room(userId)).emit('support:message', msg);
        io.to(ADMINS).emit('support:message', msg);
      } catch (e) {
        socket.emit('support:error', e.message);
      }
    });

    // Mark the other party's messages as seen.
    socket.on('support:seen', async ({ userId } = {}) => {
      const isAdmin = socket.data.isAdmin;
      const uid = isAdmin ? userId : socket.data.userId;
      if (!uid) return;
      await markSeen(uid, isAdmin ? 'user' : 'admin').catch(() => {});
      io.to(room(uid)).emit('support:seen', { userId: uid, by: isAdmin ? 'admin' : 'user' });
      io.to(ADMINS).emit('support:seen', { userId: uid, by: isAdmin ? 'admin' : 'user' });
    });
  });

  return io;
}
