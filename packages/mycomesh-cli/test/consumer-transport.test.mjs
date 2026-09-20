import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { NativeConsumerState } from '../src/consumer-runtime.mjs';

test('a stalled TLS handshake respects the shorter operation deadline', async t => {
  const directory=await mkdtemp(join(tmpdir(),'myco-transport-'));
  const sockets=new Set();
  const server=createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const state=new NativeConsumerState({env:{},dataDir:directory,historyDir:join(directory,'history'),healthTimeoutMs:80});
  t.after(async()=>{
    await state.dispatcher.destroy();
    for(const socket of sockets)socket.destroy();
    await new Promise(resolve=>server.close(resolve));
    await rm(directory,{recursive:true,force:true});
  });
  const started=performance.now();
  await assert.rejects(state.relayHealth(`https://127.0.0.1:${server.address().port}`,true));
  assert.ok(performance.now()-started<1000);
});
