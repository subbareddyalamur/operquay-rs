import { expect, it } from 'vitest';
import { IncomingWSMsg } from './ws-messages';

it('accepts an owner-scoped temporary-history warning', () => {
  expect(IncomingWSMsg.safeParse({ type:'suggest_history_status', payload:{ session_id:'terminal', status:'temporary' } }).success).toBe(true);
  expect(IncomingWSMsg.safeParse({ type:'suggest_history_status', payload:{ session_id:'terminal', status:'fixed' } }).success).toBe(true);
  expect(IncomingWSMsg.safeParse({ type:'suggest_history_status', payload:{ session_id:'terminal', status:'other' } }).success).toBe(false);
});

it('preserves the terminal message contract and rejects invalid messages', () => {
  expect(IncomingWSMsg.parse({ type:'terminal_output', payload:{ instance_id:'i-1', session_id:'s-1', output:'hello', extra:'ignored' } })).toEqual({ type:'terminal_output', payload:{ instance_id:'i-1', session_id:'s-1', output:'hello' } });
  expect(IncomingWSMsg.safeParse({ type:'session_started', payload:{ session_id:'s-1', recording:true } }).success).toBe(true);
  expect(IncomingWSMsg.safeParse({ type:'terminal_output', payload:{ instance_id:'i-1', session_id:'s-1', output:42 } }).success).toBe(false);
  expect(IncomingWSMsg.safeParse({ type:'unknown', payload:{} }).success).toBe(false);
});
